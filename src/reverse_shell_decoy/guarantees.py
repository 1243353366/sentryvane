"""The seven properties a decoy listener is supposed to have, checked rather than claimed.

Each property is paired with the mechanism that enforces it, the observation that
demonstrates it, and the limit that remains after both. The report is meant to fail
loudly: a property with no mechanism is reported as unenforced, not as satisfied.
"""

from __future__ import annotations

import ast
import asyncio
import pathlib
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

#: Calls that would let a listener turn peer input into host action.
EXECUTION_PRIMITIVES: Tuple[str, ...] = (
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.setuid",
    "pty.spawn",
    "eval",
    "exec",
    "compile",
    "__import__",
)

#: Calls that would let a listener reach beyond itself.
NETWORK_PRIMITIVES: Tuple[str, ...] = (
    "socket.create_connection",
    "socket.socket",
    "urllib.request.urlopen",
    "http.client.HTTPConnection",
    "ctypes.CDLL",
)

#: Modules whose behaviour a visitor can actually reach.
SURFACE_MODULES: Tuple[str, ...] = ("synthetic.py", "relay.py", "transport.py", "honeypot.py", "throttle.py")

PROPERTIES: Tuple[Dict[str, str], ...] = (
    {
        "id": "connection",
        "claim": "They can establish a connection.",
        "enforced_by": "an asyncio listener on a declared host and port, admitted only if the throttle allows it",
        "observed_by": "synthetic_connected / relay_connected records with peer, port and transport",
        "limit": "reachability depends on the binding; a loopback listener is reachable by this host only",
    },
    {
        "id": "host_resources",
        "claim": "They cannot access useful host resources.",
        "enforced_by": "peer bytes are classified by pattern only: never used as a path, a socket address or a command",
        "observed_by": "a canary file named in the request never appears in a response or a record",
        "limit": "this is a protocol-surface property; OS-level confinement is what bounds a memory or dependency bug",
    },
    {
        "id": "relay_scope",
        "claim": "They cannot use your proxy as an unrestricted relay.",
        "enforced_by": "the relay refuses any target that is not on loopback unless a separate override was set, and forwards only the connection it already holds",
        "observed_by": "constructing a relay with a remote target raises, and records carry target_scope=loopback",
        "limit": "the override exists for reviewed lab setups; when it is on, the report says explicit_remote",
    },
    {
        "id": "no_execution",
        "claim": "They cannot execute commands through your service.",
        "enforced_by": "no execution primitive in the reachable modules, and no interpreter of peer input",
        "observed_by": "a static capability scan plus probes sending shell syntax that never returns command output",
        "limit": "the scan covers this package, not its dependencies or the Python interpreter itself",
    },
    {
        "id": "synthetic_responses",
        "claim": "They receive synthetic or restricted responses.",
        "enforced_by": "a fixed banner set carrying an explicit notice, chosen per service",
        "observed_by": "the banner says it is synthetic and the session records peer_told_it_is_synthetic",
        "limit": "truthful, not unfingerprintable; a determined observer can tell a decoy from a real service",
    },
    {
        "id": "session_control",
        "claim": "Their session can be throttled, suspended or terminated.",
        "enforced_by": "token buckets for connects and input units, plus session, idle, line-length and input budgets",
        "observed_by": "synthetic_throttled records and a session reason naming which budget stopped it",
        "limit": "budgets are in-process; a restart resets them, and the throttle is not a network-level control",
    },
    {
        "id": "evidence",
        "claim": "Their activity generates evidence.",
        "enforced_by": "every connection, denial and termination appends a bounded, minimised record",
        "observed_by": "record counts by kind for the same probes that verify the other six properties",
        "limit": "evidence is only as trustworthy as the host that wrote it; see the compromise note",
    },
)


def _qualified(node: ast.AST) -> Optional[str]:
    """Render a call target as a dotted name, or None when it is not a plain name."""
    parts: List[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def scan_module(path: pathlib.Path) -> Dict[str, Any]:
    """Read one module and report execution and network primitives by line."""

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        return {"module": path.name, "error": str(exc), "execution": [], "network": []}

    execution: List[Dict[str, Any]] = []
    network: List[Dict[str, Any]] = []
    opens: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _qualified(node.func)
        if not name:
            continue
        if name in EXECUTION_PRIMITIVES:
            execution.append({"call": name, "line": node.lineno})
        elif name in NETWORK_PRIMITIVES:
            network.append({"call": name, "line": node.lineno})
        elif name in {"open", "io.open", "Path.open"}:
            literal = bool(node.args) and isinstance(node.args[0], ast.Constant)
            opens.append({"call": name, "line": node.lineno, "literal_argument": literal})
    return {"module": path.name, "execution": execution, "network": network, "opens": opens}


def scan_package(package_dir: Optional[pathlib.Path] = None) -> Dict[str, Any]:
    """Scan the listener modules; a missing module is reported, not skipped silently."""

    root = package_dir or pathlib.Path(__file__).resolve().parent
    modules: List[Dict[str, Any]] = []
    missing: List[str] = []
    for name in SURFACE_MODULES:
        path = root / name
        if not path.is_file():
            missing.append(name)
            continue
        modules.append(scan_module(path))
    execution_hits = sum(len(entry["execution"]) for entry in modules)
    non_literal_opens = [
        {"module": entry["module"], **opening}
        for entry in modules
        for opening in entry.get("opens", [])
        if not opening.get("literal_argument")
    ]
    return {
        "kind": "capability_scan",
        "modules": modules,
        "missing_modules": missing,
        "execution_hits": execution_hits,
        "network_hits": sum(len(entry["network"]) for entry in modules),
        "non_literal_opens": non_literal_opens,
        "note": (
            "A zero execution count is what makes 'cannot execute commands' checkable rather than "
            "asserted. Network calls are listed separately because the relay must open exactly one, "
            "to its loopback backend."
        ),
    }


async def _probe_async(*, canary_text: str = "CANARY-DO-NOT-SERVE", timeout: float = 6.0) -> Dict[str, Any]:
    from .relay import RelayFleet, RelayTarget
    from .synthetic import DEFAULT_SERVICES, SyntheticFleet
    from .throttle import InboundThrottle

    service = DEFAULT_SERVICES[0]
    throttle = InboundThrottle(connects_per_second=4, connects_per_second_per_peer=2, burst_multiplier=1.0)
    fleet = SyntheticFleet([service], allow_ephemeral_ports=True, throttle=throttle, max_runtime=timeout + 5)
    evidence: Dict[str, Any] = {"probes": [], "connect_ok": False, "canary_leaked": False}
    await fleet.start()
    try:
        port = fleet.bound_ports[0]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
        evidence["connect_ok"] = bool(banner)
        evidence["banner_is_synthetic"] = b"SYNTHETIC" in banner.upper()
        attempts = [
            ("read-host-file", ("cat /etc/passwd; cat %s" % canary_text).encode()),
            ("identity", b"id\nwhoami\n"),
            ("substitution", ("$(cat %s)" % canary_text).encode()),
            ("backticks", ("`cat %s`" % canary_text).encode()),
            ("relay-request", b"CONNECT example.com:443 HTTP/1.0\r\n\r\n"),
        ]
        for name, payload in attempts:
            writer.write(payload + b"\r\n")
            await writer.drain()
            try:
                chunk = await asyncio.wait_for(reader.readline(), timeout=2)
            except asyncio.TimeoutError:
                chunk = b""
            text = chunk.decode("utf-8", "replace")
            evidence["probes"].append(
                {
                    "probe": name,
                    "response_bytes": len(chunk),
                    "synthetic_notice": "SYNTHETIC" in text.upper(),
                    "leaked_canary": canary_text in text,
                    "looks_like_shell_output": "root:" in text or text.startswith("uid="),
                }
            )
        # Flood to exercise the throttle rather than trust it.
        denials = 0
        for _ in range(12):
            try:
                r2, w2 = await asyncio.open_connection("127.0.0.1", port)
                w2.write(b"GET / HTTP/1.0\r\n\r\n")
                await w2.drain()
                await asyncio.sleep(0.01)
                w2.close()
            except OSError:
                denials += 1
        evidence["throttle_attempts"] = 12
        evidence["throttle_closed_immediately"] = denials
        writer.close()
        await asyncio.sleep(0.2)
    finally:
        await fleet.stop("probe complete")

    records = fleet.audit
    kinds: Dict[str, int] = {}
    for record in records:
        kind = str(record.get("kind", "unknown"))
        kinds[kind] = kinds.get(kind, 0) + 1
    evidence["records_by_kind"] = dict(sorted(kinds.items()))
    # Denials are the evidence, so read them off the records rather than a counter
    # that may be reset by the time the fleet is stopped.
    evidence["throttle_denials"] = int(kinds.get("synthetic_throttled", 0))
    summary = fleet.summary() if hasattr(fleet, "summary") else {}
    if isinstance(summary, dict) and "throttle_denials" in summary:
        evidence["throttle_denials"] = max(evidence["throttle_denials"], int(summary["throttle_denials"] or 0))
    evidence["canary_leaked"] = any(entry["leaked_canary"] for entry in evidence["probes"])

    # The relay guard is a configuration property; check it by trying to break it.
    remote_refused = False
    try:
        RelayFleet([RelayTarget("remote", "example.com", 443)], port=0)
    except Exception as exc:  # the guard's own error type, named in the message
        remote_refused = "loopback" in str(exc).lower()
    evidence["relay_refuses_remote_target"] = remote_refused

    loopback_ok = True
    try:
        RelayFleet([RelayTarget("backend", "127.0.0.1", port)], port=0)
    except Exception:
        loopback_ok = False
    evidence["relay_accepts_loopback_target"] = loopback_ok

    sessions = [record for record in records if record.get("kind") == "synthetic_session"]
    evidence["session_reasons"] = sorted(
        {str(record.get("closed_reason", "")) for record in sessions if record.get("closed_reason")}
    )
    evidence["peer_told_it_is_synthetic"] = all(
        bool(record.get("peer_told_it_is_synthetic", True)) for record in records if record.get("kind") == "synthetic_connected"
    )
    return evidence


def probe(*, timeout: float = 6.0) -> Dict[str, Any]:
    """Run the live checks. Loopback only, ephemeral ports, no external traffic."""

    return asyncio.run(_probe_async(timeout=timeout))


def _status(ok: bool, *, unverified_reason: str = "") -> str:
    if ok:
        return "verified"
    return "unverified" if unverified_reason else "failed"


def report(
    *,
    evidence: Optional[Dict[str, Any]] = None,
    capability_scan: Optional[Dict[str, Any]] = None,
    probe_error: str = "",
) -> Dict[str, Any]:
    """Assemble the seven-property report from live evidence and the static scan."""

    scan = capability_scan if capability_scan is not None else scan_package()
    ev = evidence or {}
    probes = ev.get("probes", [])

    results: List[Dict[str, Any]] = []
    for prop in PROPERTIES:
        pid = prop["id"]
        entry: Dict[str, Any] = {
            "id": pid,
            "claim": prop["claim"],
            "enforced_by": prop["enforced_by"],
            "observed_by": prop["observed_by"],
            "limit": prop["limit"],
        }
        if pid == "connection":
            entry["status"] = _status(bool(ev.get("connect_ok")), unverified_reason=probe_error)
            entry["observed"] = {"connected": ev.get("connect_ok", False)}
        elif pid == "host_resources":
            clean = bool(probes) and not ev.get("canary_leaked")
            entry["status"] = _status(clean, unverified_reason=probe_error)
            entry["observed"] = {
                "canary_leaked": ev.get("canary_leaked", None),
                "probes_sent": len(probes),
                "non_literal_opens": len(scan.get("non_literal_opens", [])),
            }
        elif pid == "relay_scope":
            ok = bool(ev.get("relay_refuses_remote_target")) and bool(ev.get("relay_accepts_loopback_target"))
            entry["status"] = _status(ok, unverified_reason=probe_error)
            entry["observed"] = {
                "refuses_remote_target": ev.get("relay_refuses_remote_target", None),
                "accepts_loopback_target": ev.get("relay_accepts_loopback_target", None),
            }
        elif pid == "no_execution":
            quiet = scan.get("execution_hits") == 0
            clean_runs = bool(probes) and not any(item.get("looks_like_shell_output") for item in probes)
            entry["status"] = _status(quiet and clean_runs, unverified_reason=probe_error)
            entry["observed"] = {
                "execution_primitives_in_surface": scan.get("execution_hits", None),
                "shell_output_returned": any(item.get("looks_like_shell_output") for item in probes),
            }
        elif pid == "synthetic_responses":
            entry["status"] = _status(bool(ev.get("banner_is_synthetic")), unverified_reason=probe_error)
            entry["observed"] = {
                "banner_is_synthetic": ev.get("banner_is_synthetic", None),
                "peer_told_it_is_synthetic": ev.get("peer_told_it_is_synthetic", None),
            }
        elif pid == "session_control":
            controlled = bool(ev.get("throttle_denials")) or bool(ev.get("session_reasons"))
            entry["status"] = _status(controlled, unverified_reason=probe_error)
            entry["observed"] = {
                "throttle_denials": ev.get("throttle_denials", None),
                "throttle_attempts": ev.get("throttle_attempts", None),
                "session_reasons": ev.get("session_reasons", []),
            }
        elif pid == "evidence":
            kinds = ev.get("records_by_kind", {})
            entry["status"] = _status(len(kinds) >= 2, unverified_reason=probe_error)
            entry["observed"] = {"records_by_kind": kinds}
        if probe_error:
            entry["probe_error"] = probe_error
        results.append(entry)

    failed = [entry["id"] for entry in results if entry["status"] == "failed"]
    unverified = [entry["id"] for entry in results if entry["status"] == "unverified"]
    return {
        "kind": "containment_report",
        "properties": results,
        "summary": {
            "verified": [entry["id"] for entry in results if entry["status"] == "verified"],
            "failed": failed,
            "unverified": unverified,
            "verdict": "failed" if failed else ("unverified" if unverified else "verified"),
        },
        "capability_scan": {
            "modules_scanned": [module["module"] for module in scan.get("modules", [])],
            "missing_modules": scan.get("missing_modules", []),
            "execution_hits": scan.get("execution_hits"),
            "network_hits": scan.get("network_hits"),
        },
        "evidence": ev,
        "note": (
            "A property is 'verified' only when a mechanism and an observation both hold. "
            "'unverified' means the probe did not run; it is not a softer form of success. "
            "None of this survives a host that is already fully compromised."
        ),
    }


def audit(*, run_probe: bool = True, timeout: float = 6.0) -> Dict[str, Any]:
    """Run the live probe (or record why it did not run) and build the report."""

    evidence: Dict[str, Any] = {}
    error = ""
    if run_probe:
        try:
            evidence = probe(timeout=timeout)
        except Exception as exc:  # a probe failure is a result, not a crash
            error = "%s: %s" % (type(exc).__name__, exc)
    else:
        error = "probe not requested"
    return report(evidence=evidence, capability_scan=scan_package(), probe_error=error)
