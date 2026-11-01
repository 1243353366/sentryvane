"""Explicit, local-only operations; nothing runs on import."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import TextIO

from .input_files import read_regular
from .simulator import DecoySession, MAX_COMMANDS, MAX_INPUT

MAX_AUDIT_BYTES = 2 * 1024 * 1024


def new_private_file(path: str) -> TextIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8")


def read_audit(path: str | None) -> list[dict]:
    if path is None:
        return []
    content = read_regular(path, MAX_AUDIT_BYTES)
    if len(content) > MAX_AUDIT_BYTES:
        raise ValueError("audit input exceeds 2 MiB")
    lines = content.decode("utf-8").splitlines()
    if len(lines) > MAX_COMMANDS:
        raise ValueError("audit input exceeds 1000 records")
    events = [json.loads(line) for line in lines if line.strip()]
    if any(not isinstance(e, dict) or e.get("simulation") is not True for e in events):
        raise ValueError("audit records must be simulation:true objects")
    return events


def read_names(path: str) -> list[str]:
    content = read_regular(path, 256 * 1024)
    if len(content) > 256 * 1024:
        raise ValueError("name input exceeds 256 KiB")
    names = [line.strip() for line in content.decode("utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(names) > 1000:
        raise ValueError("name input exceeds 1000 names")
    return names


def simulate(persona: str, audit_path: str | None, presentation: str = "transparent") -> int:
    session = DecoySession(persona, presentation)
    audit = new_private_file(audit_path) if audit_path else None
    try:
        print("Operator notice: in-memory simulation only. No real privileges, execution, or network.\n"
              "Audit retains timestamps and command hashes, not raw commands or arguments.", file=sys.stderr)
        print(session.banner, end="")
        while not session.closed:
            if sys.stdin.isatty():
                print(session.prompt, end="", flush=True)
            raw = sys.stdin.readline(MAX_INPUT + 2)
            if not raw:
                break
            if len(raw.rstrip("\n")) > MAX_INPUT:
                print(session.execute(raw), end="")
                if audit and session.events:
                    audit.write(json.dumps(session.events[-1], ensure_ascii=True) + "\n")
                    audit.flush()
                print("[SIMULATED] oversized input; session stopped safely")
                break
            output = session.execute(raw.rstrip("\n"))
            print(output, end="", flush=True)
            if audit and session.events:
                audit.write(json.dumps(session.events[-1], ensure_ascii=True) + "\n")
                audit.flush()
    finally:
        if audit:
            audit.close()
    return 0


def add_log_input(p: argparse.ArgumentParser, required: bool = False) -> None:
    group = p.add_mutually_exclusive_group(required=required)
    group.add_argument("--logs", help="explicit local text/JSONL log file; no upload")
    group.add_argument("--paste", action="store_true", help="paste real logs into stdin, end with ENDLOG or EOF")
    p.add_argument("--format", choices=["text", "jsonl"], default="text")
    p.add_argument("--marker", default="ENDLOG", help="paste terminator on its own line")


def import_input(args: argparse.Namespace) -> dict | None:
    from .ingest import ingest_logs, ingest_pasted
    if args.paste:
        print(f"Paste logs; end with {args.marker} on its own line (or EOF). Paste stays local.\n"
              "Remove sensitive values first; automated redaction is not guaranteed.", file=sys.stderr)
        return ingest_pasted(sys.stdin, format=args.format, marker=args.marker)
    if args.logs:
        return ingest_logs(args.logs, format=args.format)
    return None


def optional_names(args: argparse.Namespace) -> dict | None:
    if bool(args.observed_names) != bool(args.trusted_names):
        raise ValueError("use --observed-names and --trusted-names together")
    if args.observed_names:
        from .typosquat import check_names
        return check_names(read_names(args.observed_names), read_names(args.trusted_names), kind=args.kind)
    return None


def add_optional_names(p: argparse.ArgumentParser) -> None:
    p.add_argument("--observed-names", help="one observed domain/package name per line")
    p.add_argument("--trusted-names", help="operator-provided trusted baseline, one per line")
    p.add_argument("--kind", choices=["domain", "package"], default="domain")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Local incident-response triage and a networkless decoy lab.")
    from . import __version__

    p.add_argument("--version", action="version", version=f"reverse-shell-decoy {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    cloud = sub.add_parser("cloud", help="analyze explicitly pasted/exported cloud logs; no credentials or account access")
    cloud.add_argument("--provider", required=True, choices=["cloudflare", "aws", "render", "railway"])
    cg = cloud.add_mutually_exclusive_group(required=True)
    cg.add_argument("--logs")
    cg.add_argument("--paste", action="store_true")
    cloud.add_argument("--format", choices=["auto", "json", "jsonl", "text"], default="auto")
    cloud.add_argument("--marker", default="ENDLOG")
    collect = sub.add_parser("collect-cloud", help="manual opt-in read-only API collection using your own scoped environment credentials")
    collect.add_argument("--provider", required=True, choices=["cloudflare", "aws", "render", "railway"])
    collect.add_argument("--scope-id", required=True)
    collect.add_argument("--since", required=True)
    collect.add_argument("--until", required=True)
    collect.add_argument("--region")
    summary = sub.add_parser("summary", help="summarize supplied files only; never launch or scan anything")
    from .summary import add_arguments
    add_arguments(summary)
    operations = sub.add_parser("operations", help="local decoy budget and activity-pattern summary from explicitly selected audit")
    from .operations import add_arguments as add_operations_arguments
    add_operations_arguments(operations)
    response = sub.add_parser("sinkhole-plan", help="review-only proposal; never changes DNS or redirects traffic")
    response.add_argument("--report", required=True)
    response.add_argument("--owned-domain", required=True)
    response.add_argument("--decoy-ip", required=True)
    response.add_argument("--confirm-owned", action="store_true")
    sub.add_parser("scan", help="read-only Linux shell/socket suspicion snapshot as JSON")
    sub.add_parser("os", help="read-only limited OS details of this computer")
    listeners = sub.add_parser(
        "listeners", help="read-only Linux TCP listeners and UDP bindings; no port probes"
    )
    listeners.add_argument(
        "--assure",
        action="store_true",
        help=(
            "add measured observation completeness: ownership recheck, executable "
            "identity, namespace coverage, permission accounting and an optional "
            "read-only netlink cross-check"
        ),
    )
    listeners.add_argument(
        "--no-recheck", action="store_true", help="take a single snapshot instead of two"
    )
    listeners.add_argument(
        "--cross-verify",
        action="store_true",
        help="request an independent NETLINK_SOCK_DIAG comparison (reports unavailable if unsupported)",
    )
    scan_loopback_parser = sub.add_parser(
        "scan-loopback",
        help="bounded connect scan of loopback ports only; no remote targets, no fingerprinting",
    )
    scan_loopback_parser.add_argument(
        "--ports", default="1-1024", help="port spec such as 22,80 or 1-1024 (default: 1-1024)"
    )
    scan_loopback_parser.add_argument(
        "--timeout", type=float, default=0.25, help="per-port connect timeout in seconds (default 0.25)"
    )
    scan_loopback_parser.add_argument(
        "--deadline", type=float, default=30.0, help="total scan budget in seconds (default 30)"
    )
    scan_loopback_parser.add_argument(
        "--pacing-ms", type=int, default=0, help="optional delay between attempts in milliseconds"
    )
    scan_loopback_parser.add_argument(
        "--cross-check",
        action="store_true",
        help="also read the listener inventory and report disagreements between the two views",
    )
    watchdog_parser = sub.add_parser(
        "watchdog",
        help="repeated bounded listener snapshots with recurrence links; never terminates anything",
    )
    watchdog_parser.add_argument("--observations", type=int, default=5, help="snapshot count (default 5)")
    watchdog_parser.add_argument(
        "--interval", type=float, default=2.0, help="seconds between snapshots (default 2)"
    )
    watchdog_parser.add_argument(
        "--deadline", type=float, default=120.0, help="total watching budget in seconds (default 120)"
    )
    synthetic_parser = sub.add_parser(
        "synthetic",
        help="serve obviously fake synthetic services on loopback and record interaction patterns only",
    )
    synthetic_parser.add_argument(
        "--runtime", type=float, default=60.0, help="how long to serve before stopping (default 60s)"
    )
    synthetic_parser.add_argument(
        "--services", default="all", help="comma-separated service names, or 'all' (default all)"
    )
    synthetic_parser.add_argument(
        "--full-payloads",
        action="store_true",
        help="also record the bytes a visitor sent to this synthetic service",
    )
    synthetic_parser.add_argument(
        "--tls-cert", default="", help="PEM certificate to serve these decoys over TLS (needs --tls-key)"
    )
    synthetic_parser.add_argument(
        "--tls-key", default="", help="PEM private key for --tls-cert; plaintext fallback is never used"
    )
    synthetic_parser.add_argument(
        "--allow-public",
        action="store_true",
        help="bind beyond loopback; requires independently reviewed infrastructure",
    )
    policy = sub.add_parser(
        "policy",
        help="compare effective nftables/iptables or Windows firewall state with CloudSentry's intent; changes nothing",
    )
    policy.add_argument(
        "--decoy-ports", default="22022,22080,26379", help="ports CloudSentry decoys may use (default decoy set)"
    )
    policy.add_argument(
        "--expected-ports", default="", help="inbound ports you deliberately opened, comma separated"
    )
    policy.add_argument(
        "--reviewed-public-ports", default="", help="decoy ports whose public exposure was reviewed"
    )
    relay = sub.add_parser(
        "relay",
        help="front loopback decoys through a rotating proxy, capture banners and fingerprint the opening bytes",
    )
    relay.add_argument(
        "--targets", required=True, help="loopback backends as host:port,host:port (remote targets are refused)"
    )
    relay.add_argument("--front-port", type=int, default=0, help="front listen port (default: ephemeral)")
    relay.add_argument("--runtime", type=float, default=60.0, help="seconds to serve (default 60)")
    relay.add_argument(
        "--rotate-every", type=int, default=3, help="rotate presentation every N connections (default 3)"
    )
    relay.add_argument(
        "--full-payloads", action="store_true", help="also record the bytes the visitor sent"
    )
    relay.add_argument(
        "--tls-cert", default="", help="PEM certificate for the front listener (needs --tls-key)"
    )
    relay.add_argument(
        "--tls-key", default="", help="PEM private key for --tls-cert; plaintext fallback is never used"
    )
    harden = sub.add_parser("harden", help="prevention: compare bound listeners to a declared allowlist, and plan hardening")
    harden.add_argument("action", choices=["verify", "plan"], help="verify listeners against the policy, or print the hardening steps")
    harden.add_argument("--policy", required=True, help="listener policy JSON: allow entries with executable, ports, exposure, reason")
    harden.add_argument("--proc-root", default="/proc", help="alternate procfs root, for tests and containers")

    contain = sub.add_parser("contain", help="containment: make one unwanted listener ineffective, with its collateral")
    contain.add_argument("action", choices=["plan", "apply", "rollback", "verify"])
    contain.add_argument("--port", type=int, help="port to contain")
    contain.add_argument("--pid", type=int, help="process id to contain (plan only)")
    contain.add_argument("--policy", help="listener policy JSON, so allowlisted ports are refused")
    contain.add_argument("--confirm", action="store_true", help="required for apply: this changes firewall state")
    contain.add_argument("--proc-root", default="/proc")

    guarantees = sub.add_parser(
        "guarantees",
        help="check the seven containment properties against the listeners, and say which are unverified",
    )
    guarantees.add_argument(
        "--no-probe", action="store_true", help="static capability scan only; every live property reports unverified"
    )
    guarantees.add_argument("--timeout", type=float, default=6.0, help="per-operation ceiling for the loopback probe")
    inspect_parser = sub.add_parser(
        "inspect",
        help="minimize a capture file: protocol metadata and allowlisted fields only, secrets redacted",
    )
    inspect_parser.add_argument("--file", required=True, help="captured JSONL or plain lines already on this host")
    inspect_parser.add_argument("--listener", default="file:provided", help="which listener produced it")
    inspect_parser.add_argument("--port", type=int, default=0, help="port the capture came from, for the scope record")
    inspect_parser.add_argument("--transport", choices=["tcp", "tls"], default="tcp")
    inspect_parser.add_argument(
        "--full", action="store_true", help="also emit the full-payload tier as separate, clearly labelled records"
    )
    inspect_parser.add_argument(
        "--limit", type=int, default=64 * 1024, help="per-record byte ceiling for the full-payload tier"
    )
    persist = sub.add_parser("persistence", help="read-only startup/backdoor indicators, not a malware verdict")
    persist.add_argument("--root", action="append", help="authorized config directory to inspect; default cron/systemd roots")
    ingest = sub.add_parser("ingest", help="normalize pasted or explicitly selected real logs locally")
    add_log_input(ingest, required=True)
    names = sub.add_parser("names", help="offline domain/package typosquatting indicators relative to your baseline")
    names.add_argument("--observed", required=True)
    names.add_argument("--trusted", required=True)
    names.add_argument("--kind", choices=["domain", "package"], default="domain")
    audit = sub.add_parser("audit", help="combined real OS, shell/socket, listener and startup audit")
    add_log_input(audit)
    add_optional_names(audit)
    sim = sub.add_parser("simulate", help="in-memory terminal; never executes commands or opens sockets")
    sim.add_argument("--persona", choices=["linux", "windows"], default="linux")
    sim.add_argument("--presentation", choices=["transparent", "realistic"], default="transparent",
                     help="realistic neutralizes terminal labels; operator notice and audit remain explicit")
    sim.add_argument("--audit", help="create a new private JSONL file; never overwrite")
    scenario = sub.add_parser("experiment", help="synthetic state effects only; no real OS/EDR events")
    scenario.add_argument("scenario", choices=["baseline", "process-limit", "network-loss", "telemetry-gap"])
    scenario.add_argument("--seed", type=int, default=0)
    evidence = sub.add_parser("evidence", help="export private ZIP with real observations, imports and separate decoy audit")
    evidence.add_argument("--output", required=True, help="new ZIP path; review before sharing")
    evidence.add_argument("--audit", help="optional simulation JSONL; never auto-collect logs")
    evidence.add_argument("--summary-report", help="optional previously generated cloud-summary JSON; no live account scan")
    add_log_input(evidence)
    add_optional_names(evidence)
    vault = sub.add_parser(
        "vault",
        help="seal your own collected evidence with authenticated encryption, and open it again with your key",
    )
    vault.add_argument(
        "action",
        choices=["keygen", "seal", "open", "verify", "status", "manifest", "verify-manifest"],
        help="keygen | seal | open | verify | status | manifest | verify-manifest",
    )
    vault.add_argument("paths", nargs="*", help="files or directories the action applies to")
    vault.add_argument("--out", help="destination for keygen, sealed output or a manifest")
    vault.add_argument("--key-file", default="", help="path to the 32-byte key (mode 600); else $SENTRYVANE_VAULT_KEY")
    vault.add_argument("--force", action="store_true", help="replace an existing destination or key")
    verify = sub.add_parser("verify", help="check bundle integrity, not truth or authenticity")
    verify.add_argument("path")
    return p


def emit(result: dict) -> None:
    print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))


def emit_scan(result: dict, command: str) -> None:
    """Keep scan JSON on stdout; offer a fresh, local consent-gated review."""
    emit(result)
    try:
        from .review import offer_review
        offer_review(result, command)
    except (OSError, ValueError, RuntimeError, ImportError):
        print("Optional review unavailable; the original scan result is unchanged.", file=sys.stderr)
    except KeyboardInterrupt:
        print("Optional review declined; the original scan result is unchanged.", file=sys.stderr)


def pasted_cloud_content(marker: str) -> str:
    if not marker or len(marker) > 64 or any(c.isspace() for c in marker):
        raise ValueError("paste marker must be 1..64 non-whitespace characters")
    print(f"Paste exported cloud logs; end with {marker} on its own line. Input stays local.\nRemove secrets first; this does not authenticate log origin.", file=sys.stderr)
    chunks, total = [], 0
    for _ in range(10001):
        line = sys.stdin.readline(256 * 1024 + 1)
        if not line or line.rstrip("\r\n") == marker:
            return "".join(chunks)
        if len(line.encode("utf-8")) > 256 * 1024 or len(chunks) >= 10000:
            raise ValueError("paste line/record limit exceeded")
        total += len(line.encode("utf-8"))
        if total > 8 * 1024 * 1024:
            raise ValueError("paste exceeds 8 MiB")
        chunks.append(line)
    raise ValueError("paste record limit exceeded")


async def _run_relay(fleet, runtime: float) -> int:
    """Serve the rotating front until the runtime elapses, then print the record."""

    await fleet.start()
    print(
        "relay front listening on 127.0.0.1:%d for %.0fs; targets must be loopback"
        % (fleet.bound_port, runtime),
        file=sys.stderr,
    )
    try:
        await asyncio.sleep(runtime)
    except asyncio.CancelledError:
        pass
    finally:
        await fleet.stop("runtime elapsed")
    print(json.dumps(fleet.as_dict(), indent=2, sort_keys=True))
    return 0


async def _run_synthetic(fleet, runtime: float) -> int:
    """Serve the synthetic fleet until the runtime elapses, then print the record."""

    await fleet.start()
    ports = ", ".join(str(port) for port in fleet.bound_ports)
    print(
        "serving synthetic decoy services on %s for %.0fs; every banner states it is synthetic"
        % (ports or "no ports", runtime),
        file=sys.stderr,
    )
    try:
        await asyncio.sleep(runtime)
    except asyncio.CancelledError:
        pass
    finally:
        await fleet.stop("runtime elapsed")
    print(json.dumps(fleet.as_dict(), indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "simulate":
            return simulate(args.persona, args.audit, args.presentation)
        if args.command == "cloud":
            from .cloud import analyze_cloud_logs
            content = pasted_cloud_content(args.marker) if args.paste else read_regular(args.logs, 8 * 1024 * 1024).decode("utf-8")
            emit_scan(analyze_cloud_logs(args.provider, content, format=args.format), args.command)
            return 0
        if args.command == "collect-cloud":
            from .collectors import collect_cloud
            emit_scan(collect_cloud(args.provider, args.scope_id, args.since, args.until, args.region), args.command)
            return 0
        if args.command == "summary":
            from .summary import run_args
            return run_args(args)
        if args.command == "operations":
            from .operations import run_args as run_operations_args
            return run_operations_args(args)
        if args.command == "sinkhole-plan":
            from .response import sinkhole_plan
            report = json.loads(read_regular(args.report, 8 * 1024 * 1024).decode("utf-8"))
            if not isinstance(report, dict):
                raise ValueError("report must be a JSON object")
            emit(sinkhole_plan(report, args.owned_domain, args.decoy_ip, args.confirm_owned))
            return 0
        if args.command == "scan":
            from .detector import scan
            emit_scan(scan(), args.command)
        elif args.command == "os":
            from .evidence import os_info
            emit_scan(os_info(), args.command)
        elif args.command == "listeners":
            if args.assure:
                from .observation import collect_snapshot
                emit_scan(
                    collect_snapshot(
                        recheck=not args.no_recheck,
                        cross_verify=args.cross_verify,
                    ),
                    args.command,
                )
            else:
                from .listeners import scan_listeners
                emit_scan(scan_listeners(), args.command)
        elif args.command == "scan-loopback":
            from .listeners import scan_listeners
            from .loopback_scan import cross_check_inventory, parse_port_spec, scan_loopback

            result = scan_loopback(
                parse_port_spec(args.ports),
                timeout=args.timeout,
                deadline_seconds=args.deadline,
                pacing_delay_ms=args.pacing_ms,
            )
            payload = result.as_dict()
            if args.cross_check:
                payload["cross_check"] = cross_check_inventory(result, scan_listeners())
            emit_scan(payload, args.command)
        elif args.command == "watchdog":
            from .watchdog import ListenerWatchdog

            emit_scan(
                ListenerWatchdog(
                    max_observations=args.observations,
                    min_interval_seconds=args.interval,
                    deadline_seconds=args.deadline,
                ).run(args.observations),
                args.command,
            )
        elif args.command == "synthetic":
            from .synthetic import DEFAULT_SERVICES, SyntheticFleet
            from .throttle import InboundThrottle

            if args.services.strip().lower() == "all":
                selected = DEFAULT_SERVICES
            else:
                wanted = {name.strip().lower() for name in args.services.split(",") if name.strip()}
                selected = tuple(
                    service for service in DEFAULT_SERVICES if service.name.lower() in wanted
                )
                if not selected:
                    print("no synthetic service matched the requested names", file=sys.stderr)
                    return 2
            from .transport import TransportError, optional_context

            try:
                tls_context = optional_context(args.tls_cert or None, args.tls_key or None)
            except TransportError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            fleet = SyntheticFleet(
                selected,
                throttle=InboundThrottle(),
                tls_context=tls_context,
                capture_payloads=args.full_payloads,
                allow_public=args.allow_public,
                max_runtime=args.runtime,
                host="0.0.0.0" if args.allow_public else "127.0.0.1",
            )
            return asyncio.run(_run_synthetic(fleet, args.runtime))
        elif args.command == "policy":
            from .loopback_scan import parse_port_spec
            from .policy import PolicyIntent, policy_report

            intent = PolicyIntent(
                decoy_ports=parse_port_spec(args.decoy_ports) if args.decoy_ports.strip() else (),
                expected_inbound_ports=parse_port_spec(args.expected_ports)
                if args.expected_ports.strip()
                else (),
                reviewed_public_ports=parse_port_spec(args.reviewed_public_ports)
                if args.reviewed_public_ports.strip()
                else (),
            )
            emit_scan(policy_report(intent), args.command)
        elif args.command == "relay":
            from .relay import RelayFleet, RelayTarget
            from .throttle import InboundThrottle

            targets = []
            for item in args.targets.split(","):
                if not item.strip():
                    continue
                host, _, port_text = item.strip().partition(":")
                if not port_text.isdigit():
                    print("targets must be written as host:port", file=sys.stderr)
                    return 2
                targets.append(RelayTarget(f"{host}:{port_text}", host, int(port_text)))
            if not targets:
                print("at least one loopback target is required", file=sys.stderr)
                return 2
            from .transport import TransportError, optional_context

            try:
                tls_context = optional_context(args.tls_cert or None, args.tls_key or None)
            except TransportError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            fleet = RelayFleet(
                targets,
                port=args.front_port,
                tls_context=tls_context,
                throttle=InboundThrottle(),
                rotate_every_connections=args.rotate_every,
                capture_payloads=args.full_payloads,
                max_runtime=args.runtime,
            )
            return asyncio.run(_run_relay(fleet, args.runtime))
        elif args.command == "harden":
            from .harden import load_policy, prevention_plan, verify_policy
            from .listeners import scan_listeners

            policy = load_policy(args.policy)
            if args.action == "plan":
                emit(prevention_plan(policy))
            else:
                inventory = scan_listeners(proc_root=args.proc_root)
                listeners = inventory.get("listeners", []) if isinstance(inventory, dict) else []
                result = verify_policy(listeners, policy)
                emit(result)
                return 0 if result["verdict"] == "clean" else 1
        elif args.command == "contain":
            from .harden import HardenError, apply_port_block, contain_plan, load_policy, rollback_port_block
            from .listeners import scan_listeners

            policy = load_policy(args.policy) if args.policy else None
            if args.action == "plan":
                inventory = scan_listeners(proc_root=args.proc_root)
                listeners = inventory.get("listeners", []) if isinstance(inventory, dict) else []
                emit(
                    contain_plan(
                        port=args.port, pid=args.pid, policy=policy, listeners=listeners, proc_root=args.proc_root
                    )
                )
            elif args.action == "apply":
                if args.port is None:
                    raise HardenError("apply needs --port; process-scoped tiers are printed, not applied")
                emit(apply_port_block(args.port, confirm=args.confirm, policy=policy))
            elif args.action == "rollback":
                if args.port is None:
                    raise HardenError("rollback needs --port")
                emit(rollback_port_block(port=args.port))
            else:
                if args.port is None:
                    raise HardenError("verify needs --port")
                emit({"kind": "containment_verify", "port": args.port, "note": "run the plan's own verify command; this reports state, not intent"})
        elif args.command == "guarantees":
            from .guarantees import audit

            result = audit(run_probe=not args.no_probe, timeout=args.timeout)
            emit(result)
            return 0 if result["summary"]["verdict"] == "verified" else 1
        elif args.command == "inspect":
            from .minimize import inspect_file, inspection_scope

            scope = inspection_scope(
                listener=args.listener, port=args.port, transport=args.transport, loopback_only=True
            )
            emit(inspect_file(args.file, scope=scope, include_full=args.full, limit=args.limit))
        elif args.command == "persistence":
            from .persistence import scan_persistence
            emit_scan(scan_persistence(args.root), args.command)
        elif args.command == "ingest":
            emit(import_input(args))
        elif args.command == "names":
            from .typosquat import check_names
            emit_scan(check_names(read_names(args.observed), read_names(args.trusted), kind=args.kind), args.command)
        elif args.command == "audit":
            from .correlation import audit_host
            emit_scan(audit_host(import_input(args), optional_names(args)), args.command)
        elif args.command == "experiment":
            from .experiments import run_scenario
            emit(run_scenario(args.scenario, args.seed))
        elif args.command == "evidence":
            from .correlation import audit_host
            from .evidence import export_bundle
            report = audit_host(import_input(args), optional_names(args))
            if args.summary_report:
                summary_input = json.loads(read_regular(args.summary_report, 8 * 1024 * 1024).decode("utf-8"))
                if not isinstance(summary_input, dict):
                    raise ValueError("supplied summary must be a JSON object")
                report["manual_summary_unverified"] = summary_input
            path = export_bundle(Path(args.output), report, read_audit(args.audit))
            print(f"Evidence ZIP created: {path}\nIncludes host OS, endpoint metadata and selected imports. Review before sharing. Nothing uploaded.")
        elif args.command == "vault":
            from . import __version__
            from . import vault as vault_module

            key = None
            if args.action not in {"keygen", "status"}:
                key = vault_module.load_key(args.key_file or None)
            if args.action == "keygen":
                if not args.out:
                    print("keygen needs --out PATH", file=sys.stderr)
                    return 2
                emit(vault_module.keygen(args.out, force=args.force))
            elif args.action == "seal":
                if not args.paths:
                    print("seal needs at least one file", file=sys.stderr)
                    return 2
                destination = args.out if args.out else None
                if destination and len(args.paths) > 1:
                    print("--out applies to a single file; seal them one at a time", file=sys.stderr)
                    return 2
                results = [
                    vault_module.seal_file(key, path, destination, force=args.force, tool_version=__version__)
                    for path in args.paths
                ]
                emit({"kind": "seal_results", "results": results})
            elif args.action == "open":
                if len(args.paths) != 1 or not args.out:
                    print("open needs one sealed file and --out PATH", file=sys.stderr)
                    return 2
                emit(vault_module.open_file(key, args.paths[0], args.out, force=args.force))
            elif args.action == "verify":
                if not args.paths:
                    print("verify needs at least one sealed file", file=sys.stderr)
                    return 2
                emit({"kind": "verify_results", "results": [vault_module.verify_file(key, p) for p in args.paths]})
            elif args.action == "status":
                emit(vault_module.status(args.paths or ["."]))
            elif args.action == "manifest":
                if not args.out or not args.paths:
                    print("manifest needs sealed files and --out PATH", file=sys.stderr)
                    return 2
                blob = vault_module.build_manifest(key, args.paths, tool_version=__version__)
                Path(args.out).write_bytes(blob)
                emit({
                    "kind": "manifest_written",
                    "manifest": args.out,
                    "entries": len(args.paths),
                    "note": "a manifest makes removal or substitution of a sealed file visible on verification",
                })
            elif args.action == "verify-manifest":
                if not args.paths:
                    print("verify-manifest needs a manifest path", file=sys.stderr)
                    return 2
                result = vault_module.verify_manifest(key, args.paths[0])
                emit(result)
                return 0 if result.get("intact") else 1
        elif args.command == "verify":
            from .evidence import verify_bundle
            result = verify_bundle(args.path)
            emit(result)
            return 0 if result.get("valid") else 1
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 130
    return 0
