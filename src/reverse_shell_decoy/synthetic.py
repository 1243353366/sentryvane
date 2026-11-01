"""A second, deliberately obvious synthetic decoy: pattern visibility, no deception.

The first decoy console presents a plausible-looking canned shell. This module is
its opposite by design: every service it presents says out loud that it is
synthetic, answers with canned text, and never executes, stores, or authenticates
anything. Its purpose is not to trick a knowledgeable visitor. It is to make
interaction patterns measurable on a listener you own, while making it impossible
to confuse the resulting records with real host activity.

Four properties, each covered by tests:

* **Obviously synthetic.** Every banner and every reply contains
  :data:`SYNTHETIC_MARKER` and names what it is not. A visitor cannot mistake it
  for a real service for long, and no record can be read as evidence that the
  host really runs SSH, HTTP or a database.
* **Nothing is executed.** Replies come from a fixed catalogue matched on
  lowercase text. There is no interpreter, no file access, no subprocess, no
  state that persists between sessions.
* **Interaction patterns instead of payloads.** For each session the recorder
  keeps bounded derived facts: bytes in and out, line count, arrival timing,
  whether the input looked like credentials, like a command, like a known exploit
  marker, or like an automated fingerprint, and a hash of the first line. Raw
  text is kept only when an explicit capture policy asks for it.
* **Separable evidence.** Every record carries ``synthetic: true``,
  ``source: "synthetic_decoy"`` and ``not_host_activity: true``, and
  :func:`exclude_synthetic` removes them, so a summary of real activity can never
  count the decoy's own invitations as findings against the host.

See ``docs/synthetic-decoy.md``.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .throttle import InboundThrottle

SYNTHETIC_MARKER = "SYNTHETIC DECOY"
SOURCE_SYNTHETIC = "synthetic_decoy"

PATTERN_EMPTY = "no_input"
PATTERN_PROBE = "service_probe"
PATTERN_CREDENTIAL = "credential_shaped_input"
PATTERN_COMMAND = "command_shaped_input"
PATTERN_EXPLOIT = "known_exploit_marker"
PATTERN_FINGERPRINT = "automated_fingerprint"

PATTERN_ORDER = (
    PATTERN_EMPTY,
    PATTERN_PROBE,
    PATTERN_CREDENTIAL,
    PATTERN_COMMAND,
    PATTERN_EXPLOIT,
    PATTERN_FINGERPRINT,
)

SYNTHETIC_ACTIVITY_NOTICE = (
    "These records describe connections that were invited by a listener on this host and "
    "answered by canned text. They are synthetic interactions, not host activity: nothing was "
    "executed, authenticated or stored, and the peer was told so in the banner. Do not add "
    "them to a count of suspicious or unauthorized activity without saying so explicitly."
)

MAX_SESSIONS = 32
MAX_SESSIONS_TOTAL = 500
MAX_LINE_BYTES = 4096
MAX_SESSION_INPUT_BYTES = 64 * 1024
MAX_TOTAL_INPUT_BYTES = 1024 * 1024
MAX_TOTAL_OUTPUT_BYTES = 1024 * 1024
MAX_RUNTIME_SECONDS = 3600.0
MAX_AUDIT_RECORDS = 2000

# Fixed, bounded token lists. Detection here describes shape, not intent and not skill.
_CREDENTIAL_TOKENS = ("password", "passwd", "login", "user ", "username", "auth", "token", "secret")
_COMMAND_TOKENS = (";", "|", "$(", "&&", "/bin/", "cat ", "ls ", "curl ", "wget ", "id", "whoami", "uname")
_EXPLOIT_TOKENS = (
    "../",
    "etc/passwd",
    "%2e%2e",
    "union select",
    "shellshock",
    "${jndi:",
    "() { :;",
    "cmd.exe",
    "/c ",
    "php://input",
)
_FINGERPRINT_TOKENS = ("nmap", "masscan", "zmap", "zgrab", "python-requests", "curl/", "wget/", "go-http-client")


class SyntheticDecoyError(ValueError):
    """Raised for an invalid synthetic service definition or usage."""


def _require_int(name: str, value: object, maximum: int, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an int")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _require_seconds(name: str, value: object, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    number = float(value)
    if not 0.0 < number <= maximum:
        raise ValueError(f"{name} must be greater than 0 and at most {maximum}")
    return number


def classify_line(line: str) -> str:
    """Return a bounded pattern label for one input line.

    The label describes the *shape* of the text. It never says that the peer is an
    attacker, skilled, or unauthorized.
    """

    text = line.strip().lower()
    if not text:
        return PATTERN_EMPTY
    if any(token in text for token in _EXPLOIT_TOKENS):
        return PATTERN_EXPLOIT
    if any(token in text for token in _FINGERPRINT_TOKENS):
        return PATTERN_FINGERPRINT
    if any(token in text for token in _CREDENTIAL_TOKENS):
        return PATTERN_CREDENTIAL
    if any(token in text for token in _COMMAND_TOKENS):
        return PATTERN_COMMAND
    return PATTERN_PROBE


def _obvious_banner(text: str) -> bytes:
    if SYNTHETIC_MARKER not in text:
        raise SyntheticDecoyError("every synthetic banner must contain the synthetic marker")
    return text.encode("utf-8", "replace")


@dataclass(frozen=True)
class SyntheticService:
    """One obviously fake service, defined as static text only."""

    name: str
    port: int
    banner: str
    default_reply: str
    catalogue: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise SyntheticDecoyError("name must be a non-empty string")
        # Port 0 is only meaningful for tests; SyntheticFleet decides whether it is allowed.
        _require_int("port", self.port, 65535, minimum=0)
        _obvious_banner(self.banner)
        _obvious_banner(self.default_reply)
        for needle, reply in self.catalogue:
            if not needle:
                raise SyntheticDecoyError("catalogue needles must be non-empty")
            _obvious_banner(reply)

    def reply_for(self, line: str) -> str:
        lowered = line.strip().lower()
        for needle, reply in self.catalogue:
            if needle in lowered:
                return reply
        return self.default_reply

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "port": self.port,
            "banner_length": len(self.banner),
            "catalogue_entries": len(self.catalogue),
            "obviously_synthetic": True,
        }


def _marker_line(name: str) -> str:
    return (
        f"{SYNTHETIC_MARKER}: this is not a real {name}. Nothing is executed, stored "
        "or authenticated here.\r\n"
    )


DEFAULT_SERVICES: Tuple[SyntheticService, ...] = (
    SyntheticService(
        name="shell-like endpoint",
        port=22022,
        banner=_marker_line("shell")
        + "SYNTHETIC-DECOY-0.0 (invented version, no shell attached)\r\n$ ",
        default_reply=(
            f"{SYNTHETIC_MARKER}: no shell, no filesystem, no command execution. "
            "This reply is fixed text.\r\n$ "
        ),
        catalogue=(("help", f"{SYNTHETIC_MARKER}: there is nothing to help with; this is canned text.\r\n$ "),),
    ),
    SyntheticService(
        name="web endpoint",
        port=22080,
        banner=(
            "HTTP/1.1 200 OK\r\n"
            "Server: SYNTHETIC-DECOY/0.0 (not a real web server)\r\n"
            "X-Synthetic-Decoy: true\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
            f"{SYNTHETIC_MARKER}: no real web service runs here. Nothing is executed or stored.\n"
        ),
        default_reply=f"{SYNTHETIC_MARKER}: fixed reply text, no application logic behind it.\n",
        catalogue=(
            ("get /", f"{SYNTHETIC_MARKER}: no content is served, this page does not exist.\n"),
            ("post /", f"{SYNTHETIC_MARKER}: nothing accepts a request body here.\n"),
        ),
    ),
    SyntheticService(
        name="database-like endpoint",
        port=26379,
        banner=(
            f"+{SYNTHETIC_MARKER}: no real database, invented version decoy-0.0.0, "
            "no data stored, no commands executed\r\n"
        ),
        default_reply=f"-{SYNTHETIC_MARKER}: unsupported, nothing is executed\r\n",
        catalogue=(
            ("ping", f"+{SYNTHETIC_MARKER} no service to ping\r\n"),
            ("info", f"+{SYNTHETIC_MARKER} no statistics exist\r\n"),
        ),
    ),
)


@dataclass
class _Session:
    session_id: str
    service: str
    port: int
    peer: str
    transport: str
    scope: Dict[str, Any]
    opening: bytes
    opened_at: float
    opened_utc: str
    bytes_in: int = 0
    bytes_out: int = 0
    lines: int = 0
    patterns: Dict[str, int] = field(default_factory=dict)
    first_line_sha256: str = ""
    last_arrival: Optional[float] = None
    total_gap_ms: int = 0
    max_gap_ms: int = 0
    gap_samples: int = 0

    def note(self, pattern: str) -> None:
        self.patterns[pattern] = self.patterns.get(pattern, 0) + 1

    def note_arrival(self, now: float) -> None:
        if self.last_arrival is not None:
            gap_ms = int((now - self.last_arrival) * 1000)
            self.total_gap_ms += gap_ms
            self.max_gap_ms = max(self.max_gap_ms, gap_ms)
            self.gap_samples += 1
        self.last_arrival = now

    def close_record(
        self, now: float, reason: str, capture: Optional[bytes] = None, started_at: float = 0.0
    ) -> Dict[str, Any]:
        duration_ms = int((now - self.opened_at) * 1000)
        mean_gap = int(self.total_gap_ms / self.gap_samples) if self.gap_samples else 0
        record: Dict[str, Any] = {
            "kind": "synthetic_session",
            "synthetic": True,
            "source": SOURCE_SYNTHETIC,
            "not_host_activity": True,
            "session_id": self.session_id,
            "service": self.service,
            "port": self.port,
            "peer": self.peer,
            "transport": self.transport,
            "opened_at_utc": self.opened_utc,
            "duration_ms": duration_ms,
            "closed_reason": reason,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "lines": self.lines,
            "patterns": dict(sorted(self.patterns.items())),
            "first_line_sha256": self.first_line_sha256,
            "arrival_gap_mean_ms": mean_gap,
            "arrival_gap_max_ms": self.max_gap_ms,
            "commands_per_second": round(self.lines / (duration_ms / 1000.0), 3) if duration_ms >= 100 else None,
            "executed_anything": False,
            "authenticated_anything": False,
            "stored_anything": False,
        }
        from .minimize import build_record

        record["inspection"] = build_record(
            scope=self.scope,
            opening=self.opening,
            bytes_in=self.bytes_in,
            frames=self.lines,
            duration_ms=duration_ms,
            peer=self.peer,
            payload=capture,
        )
        if capture is not None:
            record["payload_tier"] = "full"
            record["captured_bytes"] = len(capture)
            record["capture_sha256"] = hashlib.sha256(capture).hexdigest()
            record["payload_b64"] = _b64(capture)
        return record


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _utc_text() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SyntheticFleet:
    """Serve deliberately obvious synthetic services over loopback.

    The fleet is bounded: total sessions, distinct services, input and output
    bytes, session duration, idle time and total runtime all have limits, and the
    optional :class:`InboundThrottle` is consulted before a connection is served.
    """

    def __init__(
        self,
        services: Sequence[SyntheticService] = DEFAULT_SERVICES,
        *,
        host: str = "127.0.0.1",
        allow_public: bool = False,
        max_sessions: int = 4,
        max_sessions_total: int = 100,
        max_session_input_bytes: int = MAX_SESSION_INPUT_BYTES,
        max_input_bytes_total: int = MAX_TOTAL_INPUT_BYTES,
        max_output_bytes_total: int = MAX_TOTAL_OUTPUT_BYTES,
        idle_timeout: float = 20.0,
        session_timeout: float = 120.0,
        max_runtime: float = 600.0,
        audit_limit: int = MAX_AUDIT_RECORDS,
        throttle: Optional[InboundThrottle] = None,
        capture_payloads: bool = False,
        allow_ephemeral_ports: bool = False,
        tls_context: Optional[Any] = None,
    ) -> None:
        if not services:
            raise SyntheticDecoyError("at least one synthetic service is required")
        names = [service.name for service in services]
        ports = [service.port for service in services]
        if len(set(names)) != len(names):
            raise SyntheticDecoyError("synthetic service names must be unique")
        if len(set(ports)) != len(ports):
            raise SyntheticDecoyError("synthetic service ports must be unique")
        if any(service.port == 0 for service in services) and not allow_ephemeral_ports:
            raise SyntheticDecoyError(
                "port 0 (ephemeral bind) is only allowed when allow_ephemeral_ports is set, "
                "which exists for tests so a decoy never competes for a fixed production port"
            )
        if not isinstance(host, str) or not host:
            raise SyntheticDecoyError("host must be a non-empty string")
        if host not in {"127.0.0.1", "::1", "localhost"} and not allow_public:
            raise SyntheticDecoyError(
                "the synthetic fleet binds to loopback only unless allow_public is set explicitly"
            )
        if throttle is not None and not isinstance(throttle, InboundThrottle):
            raise SyntheticDecoyError("throttle must be an InboundThrottle or None")

        self.services = tuple(services)
        self.host = host
        self.allow_public = bool(allow_public)
        self.max_sessions = _require_int("max_sessions", max_sessions, MAX_SESSIONS)
        self.max_sessions_total = _require_int("max_sessions_total", max_sessions_total, 100000)
        self.max_session_input_bytes = _require_int(
            "max_session_input_bytes", max_session_input_bytes, MAX_SESSION_INPUT_BYTES
        )
        self.max_input_bytes_total = _require_int(
            "max_input_bytes_total", max_input_bytes_total, 64 * 1024 * 1024
        )
        self.max_output_bytes_total = _require_int(
            "max_output_bytes_total", max_output_bytes_total, 64 * 1024 * 1024
        )
        self.idle_timeout = _require_seconds("idle_timeout", idle_timeout, MAX_RUNTIME_SECONDS)
        self.session_timeout = _require_seconds("session_timeout", session_timeout, MAX_RUNTIME_SECONDS)
        self.max_runtime = _require_seconds("max_runtime", max_runtime, MAX_RUNTIME_SECONDS)
        self.audit_limit = _require_int("audit_limit", audit_limit, MAX_AUDIT_RECORDS)
        self.throttle = throttle
        self.capture_payloads = bool(capture_payloads)
        self.allow_ephemeral_ports = bool(allow_ephemeral_ports)

        self.audit: List[Dict[str, Any]] = []
        self._servers: List[asyncio.AbstractServer] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self._sessions: Dict[str, _Session] = {}
        self._session_counter = 0
        self._connection_count = 0
        self._input_total = 0
        self._output_total = 0
        self._throttle_denials = 0
        self._runtime_handle: Optional[asyncio.Task[None]] = None
        self._started_at: Optional[float] = None
        self._stopping = False
        self._stop_reason = ""
        self._actual_ports: Dict[str, int] = {}
        self._tls = tls_context
        self.transport = "tls" if tls_context is not None else "tcp"

    def _inspection_scope(self, service: SyntheticService, peer: str) -> Dict[str, Any]:
        from .minimize import inspection_scope

        return inspection_scope(
            listener="synthetic:%s" % service.name,
            port=self._actual_ports.get(service.name, service.port),
            transport=self.transport,
            loopback_only=self.host in {"127.0.0.1", "::1", "localhost"},
            reviewed_public=bool(getattr(self, "reviewed_public", False)),
        )

    # -- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        if self._servers:
            return
        self._started_at = time.monotonic()
        for service in self.services:
            server = await asyncio.start_server(
                lambda reader, writer, svc=service: self._handle(reader, writer, svc),
                host=self.host,
                port=service.port,
                limit=MAX_LINE_BYTES,
                ssl=self._tls,
            )
            self._servers.append(server)
            bound = server.sockets[0].getsockname()[1] if server.sockets else service.port
            self._actual_ports[service.name] = int(bound)
        self._runtime_handle = asyncio.create_task(self._watch_runtime())
        self._record(
            {
                "kind": "synthetic_fleet_started",
                "services": [service.as_dict() for service in self.services],
                "host": self.host,
                "loopback_only": self.host in {"127.0.0.1", "::1", "localhost"},
                "paced": self.throttle is not None,
                "capture_payloads": self.capture_payloads,
                "transport": self.transport,
            }
        )

    async def stop(self, reason: str = "requested") -> None:
        if self._stopping:
            return
        self._stopping = True
        self._stop_reason = reason
        if self._runtime_handle is not None:
            self._runtime_handle.cancel()
            self._runtime_handle = None
        for server in self._servers:
            server.close()
        for server in self._servers:
            try:
                await server.wait_closed()
            except Exception:
                pass
        self._servers.clear()
        for task in list(self._tasks):
            task.cancel()
        self._record({"kind": "synthetic_fleet_stopped", "reason": reason})

    async def _watch_runtime(self) -> None:
        try:
            await asyncio.sleep(self.max_runtime)
        except asyncio.CancelledError:
            return
        await self.stop("runtime limit reached")

    @property
    def bound_ports(self) -> Tuple[int, ...]:
        return tuple(
            self._actual_ports.get(service.name, service.port)
            for service in self.services
            if self._servers
        )

    def as_dict(self) -> Dict[str, Any]:
        patterns: Dict[str, int] = {name: 0 for name in PATTERN_ORDER}
        for record in self.audit:
            for name, count in (record.get("patterns") or {}).items():
                patterns[name] = patterns.get(name, 0) + int(count)
        peers = sorted({record.get("peer") for record in self.audit if record.get("peer")})
        return {
            "kind": "synthetic_fleet",
            "synthetic": True,
            "source": SOURCE_SYNTHETIC,
            "not_host_activity": True,
            "services": [
                dict(service.as_dict(), bound_port=self._actual_ports.get(service.name))
                for service in self.services
            ],
            "listen_host": self.host,
            "loopback_only": self.host in {"127.0.0.1", "::1", "localhost"},
            "active_sessions": len(self._sessions),
            "sessions_total": self._connection_count,
            "distinct_peers": len(peers),
            "bytes_in_total": self._input_total,
            "bytes_out_total": self._output_total,
            "throttle_denials": self._throttle_denials,
            "pattern_counts": patterns,
            "paced": self.throttle is not None,
            "records": [dict(record) for record in self.audit],
            "executed_anything": False,
            "notice": SYNTHETIC_ACTIVITY_NOTICE,
        }

    # -- session handling ------------------------------------------------
    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, service: SyntheticService
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        peer = "unknown"
        try:
            peer_ip = writer.get_extra_info("peername")
            if isinstance(peer_ip, tuple) and peer_ip:
                peer = str(peer_ip[0])
            if self.throttle is not None:
                denial = self.throttle.admit_connection(peer)
                if denial is not None:
                    self._throttle_denials += 1
                    self._record(
                        {
                            "kind": "synthetic_throttled",
                            "service": service.name,
                            "port": service.port,
                            "peer": peer,
                            "reason": denial,
                        }
                    )
                    writer.close()
                    return
            if self._connection_count >= self.max_sessions_total:
                self._record(
                    {
                        "kind": "synthetic_rejected",
                        "service": service.name,
                        "port": service.port,
                        "peer": peer,
                        "reason": "session allowance exhausted",
                    }
                )
                writer.close()
                return
            if len(self._sessions) >= self.max_sessions:
                self._record(
                    {
                        "kind": "synthetic_rejected",
                        "service": service.name,
                        "port": service.port,
                        "peer": peer,
                        "reason": "concurrent session limit reached",
                    }
                )
                writer.close()
                return

            self._connection_count += 1
            self._session_counter += 1
            session = _Session(
                transport=self.transport,
                scope=self._inspection_scope(service, peer),
                opening=b"",
                session_id=f"synthetic-{self._session_counter:05d}",
                service=service.name,
                port=self._actual_ports.get(service.name, service.port),
                peer=peer,
                opened_at=time.monotonic(),
                opened_utc=_utc_text(),
            )
            self._sessions[session.session_id] = session
            captured = bytearray() if self.capture_payloads else None
            self._record(
                {
                    "kind": "synthetic_connected",
                    "session_id": session.session_id,
                    "service": service.name,
                    "port": service.port,
                    "peer": peer,
                    "banner_bytes": len(service.banner),
                    "peer_told_it_is_synthetic": True,
                }
            )
            await self._send(writer, service.banner.encode("utf-8", "replace"), session)

            reason = "peer closed"
            deadline = session.opened_at + self.session_timeout
            while True:
                now = time.monotonic()
                if now >= deadline:
                    reason = "session timeout"
                    break
                remaining = min(self.idle_timeout, max(0.0, deadline - now))
                if self.max_input_bytes_total - self._input_total <= 0:
                    reason = "input budget exhausted"
                    break
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=remaining)
                except asyncio.TimeoutError:
                    reason = "idle timeout"
                    break
                if not line:
                    break
                if len(line) > MAX_LINE_BYTES:
                    reason = "line length limit"
                    break
                if not session.opening:
                    session.opening = bytes(line)
                session.note_arrival(time.monotonic())
                session.bytes_in += len(line)
                session.lines += 1
                if captured is not None:
                    captured.extend(line)
                if session.bytes_in > self.max_session_input_bytes:
                    reason = "session input budget exhausted"
                    break
                self._input_total += len(line)
                text = line.decode("utf-8", "replace")
                if not session.first_line_sha256:
                    session.first_line_sha256 = hashlib.sha256(line).hexdigest()
                session.note(classify_line(text))
                reply = service.reply_for(text)
                if not await self._send(writer, reply.encode("utf-8", "replace"), session):
                    reason = "output budget exhausted"
                    break
                if service.name == "web endpoint":
                    reason = "single-response service"
                    break

            self._finish(session, reason, bytes(captured) if captured is not None else None)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
            if task is not None:
                self._tasks.discard(task)

    async def _send(self, writer: asyncio.StreamWriter, payload: bytes, session: _Session) -> bool:
        if self._output_total + len(payload) > self.max_output_bytes_total:
            return False
        try:
            writer.write(payload)
            await writer.drain()
        except (ConnectionError, RuntimeError):
            return False
        self._output_total += len(payload)
        session.bytes_out += len(payload)
        return True

    def _finish(self, session: _Session, reason: str, capture: Optional[bytes]) -> None:
        self._sessions.pop(session.session_id, None)
        record = session.close_record(time.monotonic(), reason, capture)
        self._record(record)

    def _record(self, record: Dict[str, Any]) -> None:
        enriched = {
            "synthetic": True,
            "source": SOURCE_SYNTHETIC,
            "not_host_activity": True,
            "recorded_at_utc": _utc_text(),
        }
        enriched.update(record)
        self.audit.append(enriched)
        if len(self.audit) > self.audit_limit:
            del self.audit[: len(self.audit) - self.audit_limit]


def exclude_synthetic(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return only the records that are not synthetic-decoy interactions."""

    kept: List[Dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("synthetic") is True or record.get("source") == SOURCE_SYNTHETIC:
            continue
        kept.append(record)
    return kept


def summarize_patterns(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate interaction-pattern facts from synthetic session records."""

    sessions = [
        record
        for record in records
        if isinstance(record, dict) and record.get("kind") == "synthetic_session"
    ]
    counts: Dict[str, int] = {name: 0 for name in PATTERN_ORDER}
    for record in sessions:
        for name, value in (record.get("patterns") or {}).items():
            if name in counts:
                counts[name] += int(value)
    return {
        "kind": "synthetic_pattern_summary",
        "synthetic": True,
        "source": SOURCE_SYNTHETIC,
        "not_host_activity": True,
        "sessions": len(sessions),
        "distinct_peers": len({record.get("peer") for record in sessions}),
        "pattern_counts": counts,
        "shape_only": True,
        "notice": SYNTHETIC_ACTIVITY_NOTICE,
    }
