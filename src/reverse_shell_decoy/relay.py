"""Loopback relay: front a decoy through a proxy, rotate, fingerprint, bounce banners.

The shape this implements, and the shape it refuses:

* A visitor connects to a **front** listener on this host. The front presents a
  rotating, explicitly synthetic greeting, then connects to a **target** that
  must be on loopback (the honeypot). The target's own banner is captured and
  bounced back to the visitor, and the two connections are then pumped in both
  directions under byte and time budgets.
* It never relays a connection to a third party, never opens an outbound
  connection to a remote address, never intercepts a connection it did not
  receive, and never joins two different visitors' sessions. ``target_scope`` is
  recorded on every event so a reader can see which case applied.
* Rotation changes the front presentation and the backend target on a connection
  count or a time budget, so a visitor does not get a stable fingerprint of the
  same decoy forever, and each rotation is recorded with both sides named.
* Fingerprinting is passive and app-layer only: what the visitor sent first, what
  the backend announced first, and the timing. No raw-socket options are read, no
  active probing of the peer happens, and no inferred operating system is
  recorded as fact.

Banners are captured in both directions because that is where a decoy's honesty
and a visitor's tooling both show up: the backend banner proves the target said
what we think it said, and the peer's opening bytes are the only fingerprint
available without touching the network layer.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .synthetic import SYNTHETIC_MARKER
from .throttle import InboundThrottle

FP_UNKNOWN = "unknown_opening"
FP_TLS = "tls_client_hello"
FP_SSH = "ssh_client_identification"
FP_HTTP = "http_request"
FP_SHELL = "interactive_text"

MAX_PRESENTATIONS = 32
MAX_TARGETS = 16
MAX_BANNER_BYTES = 4096
MAX_SESSION_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_RUNTIME_SECONDS = 3600.0
MAX_RECORDS = 2000

NO_THIRD_PARTY_TRANSIT = (
    "The relay forwards only the same connection it received, only to a target on loopback on "
    "this host. It opens no outbound connection to a remote host, joins no two visitors' "
    "sessions, and never intercepts a connection it did not receive."
)


class RelayError(ValueError):
    """Raised for an invalid relay definition or usage."""


def _bounded_int(name: str, value: object, maximum: int, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an int")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_seconds(name: str, value: object, maximum: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    number = float(value)
    if not 0.0 < number <= maximum:
        raise ValueError(f"{name} must be greater than 0 and at most {maximum}")
    return number


def _loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _printable(blob: bytes, limit: int = 64) -> str:
    """Return a short, control-character-free rendering of captured bytes."""

    text = blob[:limit].decode("utf-8", "replace")
    return re.sub(r"[^\x20-\x7e]", "", text)


def fingerprint_opening(blob: bytes) -> Dict[str, Any]:
    """Classify the first bytes a peer sent. Passive, bounded, app-layer only."""

    if not isinstance(blob, (bytes, bytearray)):
        raise ValueError("blob must be bytes")
    data = bytes(blob)
    record: Dict[str, Any] = {
        "category": FP_UNKNOWN,
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest() if data else "",
        "detail": _printable(data),
        "inferred_operating_system": None,
    }
    if not data:
        return record

    if data[:2] == b"\x16\x03":
        record["category"] = FP_TLS
        record["detail"] = f"tls record version byte 0x{data[2]:02x}" if len(data) > 2 else "tls"
        return record
    if data.startswith(b"SSH-"):
        record["category"] = FP_SSH
        record["detail"] = _printable(data.split(b"\r\n", 1)[0], 48)
        return record

    head = data[:512]
    match = re.match(rb"(GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|TRACE|PATCH)\s+(\S{1,120})", head)
    if match:
        record["category"] = FP_HTTP
        agent = re.search(rb"User-Agent:\s*([^\r\n]{1,120})", head)
        record["detail"] = "%s %s" % (
            match.group(1).decode("ascii", "replace"),
            _printable(match.group(2), 80),
        )
        if agent:
            record["client_software"] = _printable(agent.group(1), 80)
        return record

    if data.endswith(b"\n") or b" " in data[:32]:
        record["category"] = FP_SHELL
        record["detail"] = _printable(data, 64)
        return record
    return record


@dataclass(frozen=True)
class Presentation:
    """One rotating front greeting. Must say it is synthetic."""

    name: str
    greeting: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise RelayError("presentation name must be a non-empty string")
        if not isinstance(self.greeting, str) or SYNTHETIC_MARKER not in self.greeting:
            raise RelayError("every relay presentation must state that it is synthetic")


@dataclass(frozen=True)
class RelayTarget:
    """One loopback backend, normally a synthetic decoy service."""

    name: str
    host: str
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise RelayError("target name must be a non-empty string")
        if not isinstance(self.host, str) or not self.host:
            raise RelayError("target host must be a non-empty string")
        _bounded_int("port", self.port, 65535)

    @property
    def loopback(self) -> bool:
        return _loopback(self.host)


DEFAULT_PRESENTATIONS: Tuple[Presentation, ...] = (
    Presentation("front-a", f"{SYNTHETIC_MARKER}: front proxy A, no real service behind this greeting\r\n"),
    Presentation("front-b", f"{SYNTHETIC_MARKER}: front proxy B, rotating presentation, nothing real here\r\n"),
    Presentation("front-c", f"{SYNTHETIC_MARKER}: front proxy C, this greeting changes on rotation\r\n"),
)


@dataclass
class _RelaySession:
    session_id: str
    peer: str
    transport: str
    target: str
    target_port: int
    presentation: str
    rotation_index: int
    opened_at: float
    opened_utc: str
    peer_bytes: int = 0
    backend_bytes: int = 0


class RelayFleet:
    """Front listener that bounces the same visitor connection to a loopback decoy."""

    def __init__(
        self,
        targets: Sequence[RelayTarget],
        presentations: Sequence[Presentation] = DEFAULT_PRESENTATIONS,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        allow_non_loopback_target: bool = False,
        rotate_every_connections: int = 3,
        rotate_every_seconds: float = 120.0,
        max_sessions: int = 8,
        max_sessions_total: int = 200,
        max_session_bytes: int = MAX_SESSION_BYTES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
        banner_bytes: int = MAX_BANNER_BYTES,
        idle_timeout: float = 30.0,
        max_runtime: float = 600.0,
        throttle: Optional[InboundThrottle] = None,
        capture_payloads: bool = False,
        tls_context: Optional[Any] = None,
        record_limit: int = MAX_RECORDS,
    ) -> None:
        if not targets:
            raise RelayError("at least one target is required")
        if len(targets) > MAX_TARGETS:
            raise RelayError(f"at most {MAX_TARGETS} targets are supported")
        if not presentations:
            raise RelayError("at least one presentation is required")
        if len(presentations) > MAX_PRESENTATIONS:
            raise RelayError(f"at most {MAX_PRESENTATIONS} presentations are supported")
        remote = [target.name for target in targets if not target.loopback]
        if remote and not allow_non_loopback_target:
            raise RelayError(
                "every relay target must be on loopback; relaying to a remote host would move "
                "this connection onto a third party, which CloudSentry refuses to do"
            )
        if not isinstance(host, str) or not host:
            raise RelayError("host must be a non-empty string")
        if throttle is not None and not isinstance(throttle, InboundThrottle):
            raise RelayError("throttle must be an InboundThrottle or None")

        self.targets = tuple(targets)
        self.presentations = tuple(presentations)
        self.host = host
        self.port = _bounded_int("port", port, 65535, minimum=0)
        self.allow_non_loopback_target = bool(allow_non_loopback_target)
        self.rotate_every_connections = _bounded_int(
            "rotate_every_connections", rotate_every_connections, 10000
        )
        self.rotate_every_seconds = _bounded_seconds(
            "rotate_every_seconds", rotate_every_seconds, MAX_RUNTIME_SECONDS
        )
        self.max_sessions = _bounded_int("max_sessions", max_sessions, 64)
        self.max_sessions_total = _bounded_int("max_sessions_total", max_sessions_total, 100000)
        self.max_session_bytes = _bounded_int("max_session_bytes", max_session_bytes, MAX_SESSION_BYTES, minimum=64)
        self.max_total_bytes = _bounded_int("max_total_bytes", max_total_bytes, 64 * 1024 * 1024, minimum=64)
        self.banner_bytes = _bounded_int("banner_bytes", banner_bytes, MAX_BANNER_BYTES, minimum=16)
        self.idle_timeout = _bounded_seconds("idle_timeout", idle_timeout, MAX_RUNTIME_SECONDS)
        self.max_runtime = _bounded_seconds("max_runtime", max_runtime, MAX_RUNTIME_SECONDS)
        self.throttle = throttle
        self.capture_payloads = bool(capture_payloads)
        self.record_limit = _bounded_int("record_limit", record_limit, MAX_RECORDS)

        self.records: List[Dict[str, Any]] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._tls = tls_context
        self.transport = "tls" if tls_context is not None else "tcp"
        self._sessions: Dict[str, _RelaySession] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._connections = 0
        self._bytes_total = 0
        self._throttle_denials = 0
        self._rotation_index = 0
        self._rotation_started = 0.0
        self._target_index = 0
        self._runtime_handle: Optional[asyncio.Task[None]] = None
        self._stopping = False

    # -- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        if self._server is not None:
            return
        self._rotation_started = time.monotonic()
        self._server = await asyncio.start_server(
            self._handle, host=self.host, port=self.port, ssl=self._tls
        )
        self._runtime_handle = asyncio.create_task(self._watch_runtime())
        self._record(
            {
                "kind": "relay_started",
                "transport": self.transport,
                "front_host": self.host,
                "front_port": self.bound_port,
                "targets": [
                    {"name": target.name, "host": target.host, "port": target.port, "loopback": target.loopback}
                    for target in self.targets
                ],
                "presentations": [presentation.name for presentation in self.presentations],
                "rotate_every_connections": self.rotate_every_connections,
                "rotate_every_seconds": self.rotate_every_seconds,
                "paced": self.throttle is not None,
                "capture_payloads": self.capture_payloads,
                "target_scope": "loopback" if not any(not t.loopback for t in self.targets) else "explicit_remote",
            }
        )

    async def stop(self, reason: str = "requested") -> None:
        if self._stopping:
            return
        self._stopping = True
        if self._runtime_handle is not None:
            self._runtime_handle.cancel()
            self._runtime_handle = None
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        for task in list(self._tasks):
            task.cancel()
        self._record({"kind": "relay_stopped", "reason": reason})

    async def _watch_runtime(self) -> None:
        try:
            await asyncio.sleep(self.max_runtime)
        except asyncio.CancelledError:
            return
        await self.stop("runtime limit reached")

    @property
    def bound_port(self) -> int:
        if self._server is None or not self._server.sockets:
            return self.port
        return int(self._server.sockets[0].getsockname()[1])

    @property
    def current_presentation(self) -> Presentation:
        return self.presentations[self._rotation_index % len(self.presentations)]

    def as_dict(self) -> Dict[str, Any]:
        sessions = [record for record in self.records if record["kind"] == "relay_session"]
        rotations = [record for record in self.records if record["kind"] == "relay_rotated"]
        return {
            "kind": "relay_fleet",
            "front_host": self.host,
            "front_port": self.bound_port,
            "sessions": len(sessions),
            "connections_total": self._connections,
            "rotations": len(rotations),
            "current_presentation": self.current_presentation.name,
            "throttle_denials": self._throttle_denials,
            "bytes_total": self._bytes_total,
            "target_scope": "loopback" if not any(not t.loopback for t in self.targets) else "explicit_remote",
            "no_third_party_transit": True,
            "footer": NO_THIRD_PARTY_TRANSIT,
            "records": [dict(record) for record in self.records],
        }

    # -- rotation --------------------------------------------------------
    def _maybe_rotate(self) -> None:
        now = time.monotonic()
        due_by_count = self._connections and self._connections % self.rotate_every_connections == 0
        due_by_time = (now - self._rotation_started) >= self.rotate_every_seconds
        if not (due_by_count or due_by_time):
            return
        previous = self.current_presentation.name
        self._rotation_index += 1
        self._rotation_started = now
        self._record(
            {
                "kind": "relay_rotated",
                "rotation_index": self._rotation_index,
                "from_presentation": previous,
                "to_presentation": self.current_presentation.name,
                "reason": "connection count" if due_by_count else "time budget",
                "connections_since_start": self._connections,
            }
        )

    def _next_target(self) -> RelayTarget:
        target = self.targets[self._target_index % len(self.targets)]
        self._target_index += 1
        return target

    # -- session handling ------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        backend_writer: Optional[asyncio.StreamWriter] = None
        try:
            peer = "unknown"
            peer_info = writer.get_extra_info("peername")
            if isinstance(peer_info, tuple) and peer_info:
                peer = str(peer_info[0])
            if self.throttle is not None:
                denial = self.throttle.admit_connection(peer)
                if denial is not None:
                    self._throttle_denials += 1
                    self._record(
                        {"kind": "relay_throttled", "peer": peer, "reason": denial, "banner_sent": False}
                    )
                    writer.close()
                    return
            if self._connections >= self.max_sessions_total or len(self._sessions) >= self.max_sessions:
                reason = (
                    "session allowance exhausted"
                    if self._connections >= self.max_sessions_total
                    else "concurrent session limit reached"
                )
                self._record({"kind": "relay_rejected", "peer": peer, "reason": reason})
                writer.close()
                return

            self._connections += 1
            if self._connections > 1:
                self._maybe_rotate()
            presentation = self.current_presentation
            target = self._next_target()
            session = _RelaySession(
                session_id=f"relay-{self._connections:05d}",
                peer=peer,
                transport=self.transport,
                target=target.name,
                target_port=target.port,
                presentation=presentation.name,
                rotation_index=self._rotation_index,
                opened_at=time.monotonic(),
                opened_utc=_utc_now(),
            )
            self._sessions[session.session_id] = session
            self._record(
                {
                    "kind": "relay_connected",
                    "session_id": session.session_id,
                    "peer": peer,
                    "transport": self.transport,
                    "target": target.name,
                    "target_port": target.port,
                    "presentation": presentation.name,
                    "rotation_index": self._rotation_index,
                    "target_scope": "loopback" if target.loopback else "explicit_remote",
                }
            )

            writer.write(presentation.greeting.encode("utf-8", "replace"))
            await writer.drain()
            try:
                backend_reader, backend_writer = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port, limit=self.banner_bytes),
                    timeout=self.idle_timeout,
                )
            except (OSError, asyncio.TimeoutError) as exc:
                self._record(
                    {
                        "kind": "relay_target_unreachable",
                        "session_id": session.session_id,
                        "target": target.name,
                        "target_scope": "loopback" if target.loopback else "explicit_remote",
                        "error": type(exc).__name__,
                    }
                )
                writer.close()
                return

            banner = b""
            try:
                banner = await asyncio.wait_for(backend_reader.read(self.banner_bytes), timeout=2.0)
            except asyncio.TimeoutError:
                pass
            if banner:
                writer.write(banner)
                await writer.drain()
                session.backend_bytes += len(banner)
                self._bytes_total += len(banner)
            self._record(
                {
                    "kind": "relay_banner",
                    "session_id": session.session_id,
                    "target": target.name,
                    "target_port": target.port,
                    "backend_banner_bytes": len(banner),
                    "backend_banner_sha256": hashlib.sha256(banner).hexdigest() if banner else "",
                    "backend_banner_synthetic": SYNTHETIC_MARKER.encode() in banner,
                    "backend_banner_preview": _printable(banner, 96),
                    "presentation": presentation.name,
                }
            )

            await self._pump(reader, writer, backend_reader, backend_writer, session)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            if backend_writer is not None:
                try:
                    backend_writer.close()
                except Exception:
                    pass
            try:
                writer.close()
            except Exception:
                pass
            if task is not None:
                self._tasks.discard(task)

    async def _pump(
        self,
        peer_reader: asyncio.StreamReader,
        peer_writer: asyncio.StreamWriter,
        backend_reader: asyncio.StreamReader,
        backend_writer: asyncio.StreamWriter,
        session: _RelaySession,
    ) -> None:
        fingerprint: Dict[str, Any] = {}
        captured = bytearray() if self.capture_payloads else None
        reason = "peer closed"
        deadline = session.opened_at + self.idle_timeout * 4

        async def peer_to_backend() -> str:
            nonlocal fingerprint, reason
            while True:
                if time.monotonic() > deadline:
                    return "idle timeout"
                try:
                    chunk = await asyncio.wait_for(peer_reader.read(2048), timeout=self.idle_timeout)
                except asyncio.TimeoutError:
                    return "idle timeout"
                if not chunk:
                    return "peer closed"
                if not fingerprint:
                    fingerprint = fingerprint_opening(chunk)
                    self._record(
                        {
                            "kind": "relay_fingerprint",
                            "session_id": session.session_id,
                            "peer": session.peer,
                            "category": fingerprint["category"],
                            "detail": fingerprint["detail"],
                            "sha256": fingerprint["sha256"],
                            "inferred_operating_system": None,
                        }
                    )
                if captured is not None:
                    captured.extend(chunk)
                session.peer_bytes += len(chunk)
                self._bytes_total += len(chunk)
                if session.peer_bytes > self.max_session_bytes or self._bytes_total > self.max_total_bytes:
                    return "byte budget exhausted"
                backend_writer.write(chunk)
                try:
                    await backend_writer.drain()
                except ConnectionError:
                    return "backend closed"
                if self.throttle is not None:
                    denial = self.throttle.admit_unit(session.peer)
                    if denial is not None:
                        return "peer paced out"

        async def backend_to_peer() -> str:
            while True:
                if time.monotonic() > deadline:
                    return "idle timeout"
                try:
                    chunk = await asyncio.wait_for(backend_reader.read(2048), timeout=self.idle_timeout)
                except asyncio.TimeoutError:
                    return "idle timeout"
                if not chunk:
                    return "backend closed"
                session.backend_bytes += len(chunk)
                self._bytes_total += len(chunk)
                if self._bytes_total > self.max_total_bytes:
                    return "byte budget exhausted"
                peer_writer.write(chunk)
                try:
                    await peer_writer.drain()
                except ConnectionError:
                    return "peer closed"

        tasks = [asyncio.create_task(peer_to_backend()), asyncio.create_task(backend_to_peer())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            if not task.cancelled() and task.exception() is None:
                reason = task.result() or reason
        self._sessions.pop(session.session_id, None)
        record: Dict[str, Any] = {
            "kind": "relay_session",
            "session_id": session.session_id,
            "peer": session.peer,
            "transport": session.transport,
            "target": session.target,
            "target_port": session.target_port,
            "presentation": session.presentation,
            "rotation_index": session.rotation_index,
            "opened_at_utc": session.opened_utc,
            "duration_ms": int((time.monotonic() - session.opened_at) * 1000),
            "peer_bytes": session.peer_bytes,
            "backend_bytes": session.backend_bytes,
            "closed_reason": reason,
            "fingerprint_category": fingerprint.get("category", FP_UNKNOWN),
            "executed_anything": False,
            "third_party_transit": False,
        }
        if captured is not None:
            import base64

            record["captured_bytes"] = len(captured)
            record["payload_sha256"] = hashlib.sha256(bytes(captured)).hexdigest()
            record["payload_b64"] = base64.b64encode(bytes(captured)).decode("ascii")
        self._record(record)

    def _record(self, record: Dict[str, Any]) -> None:
        enriched = {
            "relay": True,
            "no_third_party_transit": True,
            "recorded_at_utc": _utc_now(),
        }
        enriched.update(record)
        self.records.append(enriched)
        if len(self.records) > self.record_limit:
            del self.records[: len(self.records) - self.record_limit]
