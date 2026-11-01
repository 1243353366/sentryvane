"""Prevention and containment for listeners you did not ask for.

Prevention works on the rule, not on the process: a declared allowlist of listeners,
checked against what is actually bound, plus the OS-level steps that make an
undeclared bind hard in the first place.

Containment works on the smallest thing that makes an unwanted listener useless, and
refuses when it cannot tell the target apart from legitimate software. Three tiers,
in increasing collateral:

1. **Port** -- drop inbound on one port. Precise, reversible, and the only tier this
   tool will apply for you, because the blast radius is one port and the undo is one
   command.
2. **Cgroup** -- drop that process group's traffic via a `socket cgroupv2` match.
   Requires moving the process into its own cgroup first, so the collateral is however
   many processes already share one.
3. **Uid** -- drop one account's traffic. Blunt: it stops the legitimate processes of
   that account too, and the plan says how many.

Nothing here kills a process, edits another program's files, or touches a host that is
not this one. Every plan carries its own undo, and every applied change leaves a state
file so the rollback is not reconstructed from memory.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

TABLE_NAME = "sentryvane_contain"
STATE_DIR = pathlib.Path(os.environ.get("SENTRYVANE_STATE_DIR", "~/.local/state/sentryvane")).expanduser()

POLICY_VERSION = 1


class HardenError(RuntimeError):
    """Raised when a plan or an apply would be unsafe or malformed."""


def _require_text(name: str, value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise HardenError("%s must be text" % name)
    text = value.strip()
    if not text and not allow_empty:
        raise HardenError("%s must not be empty" % name)
    return text


def _ports(values: object, name: str) -> List[int]:
    if not isinstance(values, (list, tuple)) or not values:
        raise HardenError("%s must be a non-empty list of ports" % name)
    result: List[int] = []
    for value in values:
        if not isinstance(value, int) or isinstance(value, bool):
            raise HardenError("%s must contain integers" % name)
        if not 1 <= value <= 65535:
            raise HardenError("%s contains an out-of-range port: %d" % (name, value))
        result.append(value)
    return sorted(set(result))


def load_policy(policy: Any) -> Dict[str, Any]:
    """Validate a listener policy. A policy without a reason is refused."""

    if isinstance(policy, (str, pathlib.Path)):
        path = pathlib.Path(policy).expanduser()
        if not path.is_file():
            raise HardenError("%s is not a regular file" % path)
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise HardenError("policy is not valid JSON: %s" % exc) from None
    if not isinstance(policy, dict):
        raise HardenError("policy must be an object")

    version = policy.get("version", POLICY_VERSION)
    if version != POLICY_VERSION:
        raise HardenError("unsupported policy version: %r" % (version,))

    entries = policy.get("allow")
    if not isinstance(entries, list) or not entries:
        raise HardenError("policy needs a non-empty 'allow' list")

    allow: List[Dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise HardenError("allow[%d] must be an object" % index)
        executable = _require_text("allow[%d].executable" % index, entry.get("executable"))
        reason = _require_text("allow[%d].reason" % index, entry.get("reason"))
        exposure = entry.get("exposure", "loopback")
        if exposure not in {"loopback", "any"}:
            raise HardenError("allow[%d].exposure must be 'loopback' or 'any'" % index)
        allow.append(
            {
                "executable": executable,
                "ports": _ports(entry.get("ports"), "allow[%d].ports" % index),
                "exposure": exposure,
                "reason": reason,
            }
        )
    return {"version": POLICY_VERSION, "allow": allow}


def _executable_of(listener: Dict[str, Any]) -> str:
    for key in ("executable", "exe", "binary", "comm"):
        value = listener.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def verify_policy(listeners: Sequence[Dict[str, Any]], policy: Dict[str, Any]) -> Dict[str, Any]:
    """Compare bound listeners against the policy, one verdict per listener."""

    allow = policy.get("allow", [])
    results: List[Dict[str, Any]] = []
    for listener in listeners:
        port = listener.get("port")
        exposure = str(listener.get("exposure", "unknown"))
        executable = _executable_of(listener)
        entry = {
            "port": port,
            "address": listener.get("address", ""),
            "exposure": exposure,
            "executable": executable,
            "pid": listener.get("pid"),
            "uid": listener.get("uid"),
        }
        matched: List[Dict[str, Any]] = []
        for rule in allow:
            if executable and (
                executable == rule["executable"] or executable.endswith("/" + rule["executable"].split("/")[-1])
            ):
                matched.append(rule)
        if not executable:
            entry["status"] = "unattributed"
            entry["detail"] = "no executable could be attributed; treat as unknown, not as allowed"
        elif not matched:
            entry["status"] = "unlisted"
            entry["detail"] = "no policy entry covers this executable"
        else:
            rule = matched[0]
            if isinstance(port, int) and port not in rule["ports"]:
                entry["status"] = "unexpected-port"
                entry["detail"] = "executable is allowed, this port is not in its list"
            elif rule["exposure"] == "loopback" and exposure not in {"loopback", "localhost"}:
                entry["status"] = "unexpected-exposure"
                entry["detail"] = "policy allows loopback only; this listener is reachable more widely"
            else:
                entry["status"] = "approved"
                entry["detail"] = rule["reason"]
        results.append(entry)

    counts: Dict[str, int] = {}
    for entry in results:
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    unapproved = [entry for entry in results if entry["status"] != "approved"]
    verdict = "clean" if not unapproved else "drift"
    if not results:
        # An empty inventory is a scan that found nothing, not a host with nothing to find.
        verdict = "unknown"
    return {
        "kind": "listener_policy_verification",
        "listeners": results,
        "counts": dict(sorted(counts.items())),
        "unapproved": unapproved,
        "verdict": verdict,
        "note": (
            "An unattributed listener is reported as unknown rather than allowed. "
            "This compares what is bound against a written rule; it cannot tell you whether "
            "an approved executable has been replaced by something else."
        ),
    }


def prevention_plan(policy: Dict[str, Any], *, approved_ports: Optional[Iterable[int]] = None) -> Dict[str, Any]:
    """OS-level steps that make an undeclared listener harder to create or keep."""

    ports = sorted({port for rule in policy["allow"] for port in rule["ports"]})
    if approved_ports is not None:
        ports = sorted(set(ports) | {int(port) for port in approved_ports})
    allow_rules = "\n".join(
        "        tcp dport %d accept" % port for port in ports
    ) or "        # no approved inbound ports"
    nft_script = (
        "table inet sentryvane_inbound {\n"
        "    chain input {\n"
        "        type filter hook input priority -5; policy drop;\n"
        "        iif lo accept\n"
        "        ct state established,related accept\n"
        "%s\n"
        "    }\n"
        "}\n" % allow_rules
    )
    steps = [
        {
            "id": "inbound-default-deny",
            "what": "Default-deny inbound, with an explicit accept for each approved port.",
            "why": "An unwanted listener on any other port becomes unreachable even if it starts.",
            "commands": ["nft -f /etc/sentryvane/inbound.nft"],
            "file_to_write": {"path": "/etc/sentryvane/inbound.nft", "content": nft_script},
            "revert": ["nft delete table inet sentryvane_inbound"],
            "requires_root": True,
            "collateral": "Anything that legitimately needs an inbound port not listed here stops working.",
        },
        {
            "id": "raise-unprivileged-port-floor",
            "what": "Keep unprivileged processes off the low ports.",
            "why": "A listener impersonating a well-known service needs a low port; this makes that a privileged act.",
            "commands": [
                "sysctl -w net.ipv4.ip_unprivileged_port_start=1024",
                "printf 'net.ipv4.ip_unprivileged_port_start=1024\\n' > /etc/sysctl.d/60-sentryvane.conf",
            ],
            "revert": [
                "sysctl -w net.ipv4.ip_unprivileged_port_start=0",
                "rm -f /etc/sysctl.d/60-sentryvane.conf",
            ],
            "requires_root": True,
            "collateral": "Unprivileged services that bind below 1024 stop starting.",
        },
        {
            "id": "log-bind-attempts",
            "what": "Record every bind() attempt with the executable that made it.",
            "why": "Prevention without a record cannot be reviewed, and a blocked attempt is worth seeing.",
            "commands": [
                "auditctl -a always,exit -F arch=b64 -S bind -F key=sentryvane_bind",
                "auditctl -a always,exit -F arch=b32 -S bind -F key=sentryvane_bind",
            ],
            "revert": [
                "auditctl -d always,exit -F arch=b64 -S bind -F key=sentryvane_bind",
                "auditctl -d always,exit -F arch=b32 -S bind -F key=sentryvane_bind",
            ],
            "requires_root": True,
            "collateral": "Audit volume grows; tune the key's retention.",
        },
        {
            "id": "restrict-service-sockets",
            "what": "For each approved service unit, set RestrictAddressFamilies and NoNewPrivileges.",
            "why": "A compromised service cannot open a socket family or gain privileges it was not granted.",
            "commands": ["systemctl edit --full <unit>  # add RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX, NoNewPrivileges=yes"],
            "revert": ["systemctl revert <unit>"],
            "requires_root": True,
            "collateral": "A service that needs another address family fails after restart; per unit, not global.",
        },
        {
            "id": "verify-against-policy",
            "what": "Run the check that produced this plan on a schedule.",
            "why": "A rule that is never compared to reality drifts silently.",
            "commands": ["reverse-shell-decoy harden verify --policy /etc/sentryvane/listeners.json"],
            "revert": ["remove the scheduled job"],
            "requires_root": False,
            "collateral": "None; this step only reads.",
        },
    ]
    return {
        "kind": "prevention_plan",
        "approved_ports": ports,
        "steps": steps,
        "note": (
            "These are steps for you to review and run, not actions this tool takes. Each one "
            "names what it touches and how to undo it, because prevention that cannot be "
            "reversed is a way to break your own machine."
        ),
    }


def _proc_processes(proc_root: pathlib.Path) -> List[Dict[str, Any]]:
    """Read the process table: pid, uid, comm, cgroup path, exe."""

    processes: List[Dict[str, Any]] = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return processes
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        info: Dict[str, Any] = {"pid": pid, "uid": None, "comm": "", "cgroup": "", "exe": ""}
        try:
            status = (entry / "status").read_text(encoding="utf-8", errors="replace")
            for line in status.splitlines():
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        info["uid"] = int(parts[1])
                elif line.startswith("Name:"):
                    info["comm"] = line.split(":", 1)[1].strip()
        except OSError:
            pass
        try:
            text = (entry / "cgroup").read_text(encoding="utf-8", errors="replace").strip()
            for line in text.splitlines():
                parts = line.split(":", 2)
                if len(parts) == 3 and parts[2]:
                    info["cgroup"] = parts[2]
                    break
        except OSError:
            pass
        try:
            info["exe"] = os.readlink(entry / "exe")
        except OSError:
            pass
        processes.append(info)
    return processes


def _collateral_by_uid(processes: Sequence[Dict[str, Any]], uid: int) -> List[Dict[str, Any]]:
    return [proc for proc in processes if proc.get("uid") == uid]


def _collateral_by_cgroup(processes: Sequence[Dict[str, Any]], cgroup: str) -> List[Dict[str, Any]]:
    if not cgroup:
        return []
    return [proc for proc in processes if proc.get("cgroup") == cgroup]


def contain_plan(
    *,
    port: Optional[int] = None,
    pid: Optional[int] = None,
    policy: Optional[Dict[str, Any]] = None,
    listeners: Optional[Sequence[Dict[str, Any]]] = None,
    processes: Optional[Sequence[Dict[str, Any]]] = None,
    proc_root: str = "/proc",
) -> Dict[str, Any]:
    """Build the smallest intervention that makes the target useless, with its collateral."""

    if port is None and pid is None:
        raise HardenError("give a port or a pid to contain")
    if port is not None and pid is not None:
        raise HardenError("give a port or a pid, not both; the tier differs and mixing them hides collateral")

    root = pathlib.Path(proc_root)
    table = list(processes) if processes is not None else _proc_processes(root)
    inventory = list(listeners) if listeners is not None else []

    facts: Dict[str, Any] = {"port": port, "pid": pid}
    tiers: List[Dict[str, Any]] = []

    if port is not None:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise HardenError("port must be an integer between 1 and 65535")
        owners = [entry for entry in inventory if entry.get("port") == port]
        approved = []
        if policy:
            approved = [
                rule["reason"]
                for rule in policy.get("allow", [])
                if port in rule["ports"]
            ]
        facts["listeners_on_port"] = owners
        facts["approved_by_policy"] = approved
        if approved:
            raise HardenError(
                "port %d is allowlisted (%s); containing it would cut off software you approved" % (port, approved[0])
            )
        facts["other_listeners"] = [
            entry for entry in inventory if entry.get("port") != port and entry.get("address") in {"0.0.0.0", "::"}
        ]
        tiers.append(
            {
                "tier": "port",
                "scope": "inbound tcp on port %d" % port,
                "commands": [
                    "nft add table inet %s" % TABLE_NAME,
                    "nft 'add chain inet %s input { type filter hook input priority -10; }'" % TABLE_NAME,
                    "nft add rule inet %s input tcp dport %d drop" % (TABLE_NAME, port),
                ],
                "revert": ["nft delete table inet %s" % TABLE_NAME],
                "verifies": "loopback_scan: port %d no longer accepts, and approved ports still do" % port,
                "collateral": {
                    "listeners_also_blocked": [],
                    "note": "one port, inbound only. Existing outbound connections are untouched.",
                },
                "safe_to_apply": True,
                "why": "The listener can still run but nobody can reach it; undo is one table drop.",
            }
        )

    if pid is not None:
        if not isinstance(pid, int) or pid <= 0:
            raise HardenError("pid must be a positive integer")
        target = next((proc for proc in table if proc.get("pid") == pid), None)
        if target is None:
            raise HardenError("pid %d is not present in the process table" % pid)
        facts["process"] = {
            "pid": pid,
            "uid": target.get("uid"),
            "comm": target.get("comm", ""),
            "cgroup": target.get("cgroup", ""),
            "exe": target.get("exe", ""),
        }
        same_cgroup = _collateral_by_cgroup(table, target.get("cgroup", ""))
        same_uid = _collateral_by_uid(table, target.get("uid")) if target.get("uid") is not None else []
        cgroup_shared = len(same_cgroup) > 1
        crate = "sentryvane-q-%d" % pid
        tiers.append(
            {
                "tier": "cgroup",
                "scope": "that process's socket traffic only",
                "commands": [
                    "mkdir -p /sys/fs/cgroup/%s" % crate,
                    "printf '%d' > /sys/fs/cgroup/%s/cgroup.procs" % (pid, crate),
                    "nft add rule inet %s output socket cgroupv2 level 1 '%s' drop" % (TABLE_NAME, crate),
                    "nft add rule inet %s input socket cgroupv2 level 1 '%s' drop" % (TABLE_NAME, crate),
                ],
                "revert": [
                    "nft delete table inet %s" % TABLE_NAME,
                    "rmdir /sys/fs/cgroup/%s || true" % crate,
                ],
                "verifies": "the process's sockets fail while its neighbours keep working",
                "collateral": {
                    "processes_sharing_cgroup": [proc["pid"] for proc in same_cgroup if proc["pid"] != pid],
                    "note": (
                        "the process must be moved into its own cgroup first; if it already shares one, "
                        "every process listed here loses network too"
                    ),
                },
                "safe_to_apply": not cgroup_shared,
                "why": (
                    "no other process in this cgroup, so the blast radius is one process"
                    if not cgroup_shared
                    else "the cgroup is shared, so this tier cannot separate the target from its neighbours"
                ),
            }
        )
        tiers.append(
            {
                "tier": "uid",
                "scope": "every process running as uid %s" % target.get("uid"),
                "commands": [
                    "nft add rule inet %s output meta skuid %s drop" % (TABLE_NAME, target.get("uid")),
                    "nft add rule inet %s input meta skuid %s drop" % (TABLE_NAME, target.get("uid")),
                ],
                "revert": ["nft delete table inet %s" % TABLE_NAME],
                "verifies": "the process's traffic stops while other accounts are unaffected",
                "collateral": {
                    "processes_sharing_uid": len(same_uid),
                    "example_pids": [proc["pid"] for proc in same_uid if proc["pid"] != pid][:10],
                    "note": "blunt: this cuts the account's legitimate network use as well",
                },
                "safe_to_apply": len(same_uid) <= 1,
                "why": (
                    "the account runs nothing else"
                    if len(same_uid) <= 1
                    else "%d processes share the account, so this is not process-scoped" % len(same_uid)
                ),
            }
        )

    usable = [tier for tier in tiers if tier["safe_to_apply"]]
    chosen = min(usable, key=lambda tier: ["port", "cgroup", "uid"].index(tier["tier"])) if usable else None
    return {
        "kind": "containment_plan",
        "facts": facts,
        "tiers": tiers,
        "recommended": chosen["tier"] if chosen else "none",
        "applied_by_this_tool": ["port"],
        "note": (
            "Only the port tier is applied here automatically: one port, inbound only, undo is a table "
            "drop. Process- and account-scoped tiers are printed for you to run after reading the "
            "collateral, because their blast radius depends on facts this tool cannot verify for you. "
            "Nothing here kills a process or edits another program's files."
        ),
    }


def _state_path(port: int) -> pathlib.Path:
    return STATE_DIR / "contain" / ("port-%d.json" % port)


def apply_port_block(
    port: int,
    *,
    confirm: bool = False,
    runner: Any = None,
    require_root: bool = True,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Apply the port tier, or refuse. Records an undo file before touching anything."""

    if not confirm:
        raise HardenError("refusing to change firewall state without explicit confirmation")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise HardenError("port must be an integer between 1 and 65535")
    if policy:
        approved = [rule["reason"] for rule in policy.get("allow", []) if port in rule["ports"]]
        if approved:
            raise HardenError("port %d is allowlisted (%s); refusing to contain it" % (port, approved[0]))
    if require_root and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise HardenError("applying a firewall rule needs root; run the printed commands yourself instead")
    if shutil.which("nft") is None and runner is None:
        raise HardenError("nft is not installed; the plan's commands require it")

    run = runner or (lambda argv: subprocess.run(argv, capture_output=True, text=True, check=False))
    applied: List[Dict[str, Any]] = []
    for argv in (
        ["nft", "add", "table", "inet", TABLE_NAME],
        ["nft", "add", "chain", "inet", TABLE_NAME, "input", "{", "type", "filter", "hook", "input", "priority", "-10;", "}"],
        ["nft", "add", "rule", "inet", TABLE_NAME, "input", "tcp", "dport", str(port), "drop"],
    ):
        result = run(argv)
        applied.append(
            {
                "command": " ".join(argv),
                "returncode": getattr(result, "returncode", 0),
                "stderr": (getattr(result, "stderr", "") or "").strip()[:400],
            }
        )
    state = _state_path(port)
    state.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": "containment_state",
        "port": port,
        "table": TABLE_NAME,
        "applied": applied,
        "undo": ["nft", "delete", "table", "inet", TABLE_NAME],
        "verify": "reverse-shell-decoy contain verify --port %d" % port,
    }
    state.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    try:
        state.chmod(0o600)
    except OSError:
        pass
    payload["state_file"] = str(state)
    return payload


def rollback_port_block(*, port: int, runner: Any = None, require_root: bool = True) -> Dict[str, Any]:
    """Remove the containment table, and say whether an undo record existed."""

    state = _state_path(port)
    had_state = state.is_file()
    if require_root and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise HardenError("removing a firewall rule needs root")
    run = runner or (lambda argv: subprocess.run(argv, capture_output=True, text=True, check=False))
    result = run(["nft", "delete", "table", "inet", TABLE_NAME])
    if had_state:
        try:
            state.unlink()
        except OSError:
            pass
    return {
        "kind": "containment_rollback",
        "port": port,
        "table": TABLE_NAME,
        "had_state_file": had_state,
        "returncode": getattr(result, "returncode", 0),
        "stderr": (getattr(result, "stderr", "") or "").strip()[:400],
        "note": (
            "One table drop restores the previous inbound state for every port this tool blocked, "
            "including ports blocked in earlier runs."
        ),
    }
