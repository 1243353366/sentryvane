"""Metadata-first inspection: read the smallest thing that answers the question.

Order of operations, and the reason for it:

1. Decide what you are *permitted* to inspect before touching bytes. For this tool
   that is a connection to a listener it started, on this host, inside a declared
   window. Anything else is out of scope and is not parsed at all.
2. Parse protocol metadata: family, operation, target, header names, sizes. Not
   values, not bodies.
3. Keep an allowlisted set of application fields, each with the reason it is kept.
4. Redact anything secret-looking inside the fields that survive, and count the
   redactions rather than storing what was redacted.
5. Bound the record: field count, value length, total bytes.
6. State exactly what was inspected, what was deliberately not read, and why.

Full payload sits behind its own explicit tier, in a separate record, because the
two answer different questions. A minimized record answers "what was attempted,
from where, with what tooling". A full payload preserves the bytes, and with them
the credentials, tokens and third-party personal data that came along.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ALLOWLIST_VERSION = 1
MAX_FIELD_VALUE = 120
MAX_FIELDS = 24
MAX_REDACTION_ENTRIES = 12
MAX_WINDOW_BYTES = 4096
FULL_PAYLOAD_LIMIT = 64 * 1024

#: Every field this module is willing to keep, with the question it answers.
ALLOWLIST: Dict[str, str] = {
    "http.method": "which operation the visitor attempted, without any of its content",
    "http.path": "which decoy endpoint was targeted; query values are dropped, keys kept",
    "http.query_keys": "which parameters were supplied, never their values",
    "http.version": "protocol revision, for interop comparison only",
    "http.header_names": "client and tooling families without storing header values",
    "http.content_type": "what kind of body arrived, to size the risk without keeping it",
    "http.content_length": "body size only",
    "http.status": "response class the decoy returned",
    "ssh.banner": "client software and version string that scanners send first",
    "ssh.protocol": "SSH protocol revision",
    "redis.command": "top-level command token only, never its arguments",
    "smtp.greeting": "mail client greeting verb only",
    "tls.transport": "whether the session was encrypted, which changes what an observer saw",
    "frames.count": "how many lines arrived, to distinguish a scanner from a script",
    "bytes.in": "how much arrived, bounded by the session limit",
    "timing.duration_ms": "session length, used for pacing and rate context",
}

#: Things a minimised record deliberately does not contain, with the reason.
NOT_INSPECTED: Tuple[Dict[str, str], ...] = (
    {"item": "request or command bodies", "reason": "content is only needed for the explicit full-payload tier"},
    {"item": "header values", "reason": "cookies, authorization and session identifiers live there"},
    {"item": "query parameter values", "reason": "tokens and identifiers are routinely passed in the query string"},
    {"item": "credentials and key material", "reason": "never necessary to answer what was attempted"},
    {"item": "files past the inspection window", "reason": "beyond the declared window; inspect them deliberately"},
)

_SECRET_PATTERNS: Sequence[Tuple[str, "re.Pattern[str]"]] = (
    ("authorization bearer token", re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("api-style key", re.compile(r"\b(?:sk|pk|rk|ghp|gho|ghs|xox[abp])[-_][A-Za-z0-9._-]{10,}")),
    ("aws access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("password assignment", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S{4,}")),
    ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("long opaque blob", re.compile(r"\b[A-Za-z0-9+/=_-]{40,}\b")),
)
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_TOKENISH_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{16,}$")
_SAFE_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "trace", "connect"}


def _bounded(text: str, limit: int = MAX_FIELD_VALUE) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def redact_text(value: str, *, field: str = "") -> Tuple[str, List[str]]:
    """Replace secret-looking spans, returning the text and the rules that fired."""

    rules: List[str] = []
    result = str(value)
    for name, pattern in _SECRET_PATTERNS:
        result, count = pattern.subn("[redacted:%s]" % name.replace(" ", "-"), result)
        if count:
            rules.append(name)
    if _looks_secretish(field, result):
        result = "[redacted:opaque-value]"
        rules.append("field value is opaque and could be a credential")
    result, count = _IPV4.subn(lambda m: "%s.%s.%s.x" % (m.group(1), m.group(2), m.group(3)), result)
    if count:
        rules.append("host address truncated to its prefix")
    return _bounded(result), rules


def _looks_secretish(field: str, value: str) -> bool:
    marker = field.lower()
    if any(token in marker for token in ("authorization", "cookie", "token", "key", "secret", "password")):
        return bool(value)
    return False


def redact_peer(peer: str) -> Dict[str, str]:
    """Keep enough of an address to correlate sessions, not enough to be a dossier."""

    digest = hashlib.sha256(peer.encode("utf-8", "replace")).hexdigest()[:12]
    if ":" in peer:
        return {"address": "ipv6-prefix-hidden", "peer_id": digest}
    match = _IPV4.fullmatch(peer.strip())
    if match:
        return {"address": "%s.%s.%s.x" % (match.group(1), match.group(2), match.group(3)), "peer_id": digest}
    return {"address": redact_text(peer, field="peer")[0], "peer_id": digest}


def _text_of(raw: Any) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def parse_opening(opening: Any) -> Dict[str, Any]:
    """Parse the first line of a session. Returns fields and what was skipped."""

    line = _text_of(opening).strip("\r\n")
    if not line:
        return {
            "family": "empty",
            "confidence": "low",
            "basis": "no opening bytes",
            "fields": {},
            "redactions": [],
            "opening_sha256": hashlib.sha256(_text_of(opening).encode("utf-8", "replace")).hexdigest(),
            "opening_len": len(_text_of(opening)),
        }

    fields: Dict[str, Any] = {}
    redactions: List[str] = []
    family = "unknown"
    confidence = "low"
    basis = "opening line did not match a known parser"

    parts = line.split(" ")
    if len(parts) >= 2 and parts[0].lower() in _SAFE_VERBS and parts[1].startswith("/"):
        family, confidence, basis = "http", "high", "HTTP request line"
        fields["http.method"] = parts[0].upper()
        target, _, version = parts[1], " ", parts[2] if len(parts) > 2 else ""
        path, _, query = target.partition("?")
        segments = []
        for segment in path.split("/"):
            if not segment:
                continue
            if _TOKENISH_SEGMENT.match(segment):
                segments.append("[redacted:path-segment]")
                redactions.append("secret-looking path segment")
            else:
                segments.append(segment)
        fields["http.path"] = _bounded("/" + "/".join(segments))
        if query:
            keys = []
            for pair in query.split("&"):
                key = pair.split("=", 1)[0]
                keys.append(key[:40])
            fields["http.query_keys"] = sorted(set(keys))[:16]
            if any("=" in pair for pair in query.split("&")):
                redactions.append("query values dropped, keys kept")
        if version.upper().startswith("HTTP/"):
            fields["http.version"] = version.upper()
    elif line.upper().startswith("SSH-"):
        family, confidence, basis = "ssh", "high", "SSH identification string"
        tokens = line.split("-", 2)
        if len(tokens) >= 2:
            fields["ssh.protocol"] = tokens[1]
        if len(tokens) == 3:
            software, rules = redact_text(tokens[2], field="ssh.software")
            fields["ssh.banner"] = software
            redactions.extend(rules)
    elif line.upper().startswith(("EHLO ", "HELO ")):
        family, confidence, basis = "smtp", "medium", "SMTP greeting verb"
        fields["smtp.greeting"] = line.split(" ")[0].upper()
    elif re.match(r"^[A-Za-z]{2,20}(\s|$)", line) and line.split(" ")[0].isalpha():
        family, confidence, basis = "line-protocol", "low", "line-oriented command protocol"
        verb, rules = redact_text(line.split(" ")[0].upper(), field="redis.command")
        fields["redis.command"] = _bounded(verb, 40)
        if rules:
            redactions.append("command token contained secret-looking text")
        if len(line.split(" ")) > 1:
            redactions.append("command arguments dropped")
    else:
        redactions.append("unrecognised opening line stored as a digest only")

    return {
        "family": family,
        "confidence": confidence,
        "basis": basis,
        "fields": {k: fields[k] for k in list(fields)[:MAX_FIELDS]},
        "redactions": redactions[:MAX_REDACTION_ENTRIES],
        "opening_sha256": hashlib.sha256(_text_of(opening).encode("utf-8", "replace")).hexdigest(),
        "opening_len": len(_text_of(opening)),
    }


def inspection_scope(
    *,
    listener: str,
    port: int,
    transport: str = "tcp",
    loopback_only: bool = True,
    reviewed_public: bool = False,
    window_bytes: int = MAX_WINDOW_BYTES,
) -> Dict[str, Any]:
    """State the basis on which these bytes may be read at all."""

    window = max(1, min(int(window_bytes), MAX_WINDOW_BYTES))
    permitted = [
        {"item": "protocol metadata", "reason": "identifies family, operation and size without content"},
        {"item": "allowlisted application fields", "reason": "answers what was attempted; see the field list"},
        {"item": "session accounting", "reason": "bytes, frames and duration for pacing and rate context"},
    ]
    denied = [dict(entry) for entry in NOT_INSPECTED]
    if reviewed_public and not loopback_only:
        basis = "own listener on this host, public exposure independently reviewed"
    elif loopback_only:
        basis = "own listener on this host, loopback only"
    else:
        basis = "own listener on this host, non-loopback binding without a recorded review"
        denied.append(
            {
                "item": "traffic to this port",
                "reason": "binding beyond loopback was not reviewed, so exposure is unknown",
            }
        )
    return {
        "version": ALLOWLIST_VERSION,
        "basis": basis,
        "listener": listener,
        "port": int(port),
        "transport": transport,
        "inspection_window_bytes": window,
        "permitted": permitted,
        "not_permitted": [
            {"item": "any service this tool did not start", "reason": "not ours to read"},
            {"item": "any host other than this one", "reason": "out of authorised scope"},
            *denied,
        ],
    }


def build_record(
    *,
    scope: Dict[str, Any],
    opening: Any,
    bytes_in: int = 0,
    frames: int = 0,
    duration_ms: int = 0,
    peer: str = "",
    payload: Optional[bytes] = None,
) -> Dict[str, Any]:
    """The minimised evidence record: bounded, redacted, and explicit about itself."""

    parsed = parse_opening(opening)
    fields: Dict[str, Any] = dict(parsed["fields"])
    fields["bytes.in"] = int(bytes_in)
    fields["frames.count"] = int(frames)
    fields["timing.duration_ms"] = int(duration_ms)
    fields["tls.transport"] = scope.get("transport", "tcp")
    for name in list(fields):
        if name not in ALLOWLIST:
            fields.pop(name)
    kept = {name: fields[name] for name in list(fields)[:MAX_FIELDS]}

    redactions: List[Dict[str, str]] = []
    for rule in parsed["redactions"]:
        redactions.append({"where": "opening line", "rule": rule})
    if peer:
        redactions.append({"where": "peer", "rule": "address truncated; stable peer id kept for correlation"})

    record: Dict[str, Any] = {
        "kind": "inspection_record",
        "tier": "minimized",
        "scope": scope,
        "protocol": {
            "family": parsed["family"],
            "confidence": parsed["confidence"],
            "basis": parsed["basis"],
        },
        "fields": kept,
        "field_reasons": {name: ALLOWLIST[name] for name in kept},
        "redactions": redactions[:MAX_REDACTION_ENTRIES],
        "not_inspected": scope.get("not_permitted", []),
        "bounds": {
            "max_field_value": MAX_FIELD_VALUE,
            "max_fields": MAX_FIELDS,
            "fields_kept": len(kept),
            "stored_field_bytes": sum(len(str(value)) for value in kept.values()),
            "inspection_window_bytes": scope.get("inspection_window_bytes", MAX_WINDOW_BYTES),
        },
        "opening": {
            "sha256": parsed.get("opening_sha256", ""),
            "len": int(parsed.get("opening_len", 0)),
        },
        "peer": redact_peer(peer) if peer else {"address": "", "peer_id": ""},
        "why_this_is_enough": (
            "Family, operation, target and size answer what was attempted and from what tooling. "
            "Bodies, header values, query values and credentials do not change that answer, and they "
            "are what makes an evidence journal worth stealing."
        ),
    }
    if payload is not None:
        record["payload"] = {
            "stored": False,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "note": "the bytes are not in this record; the full-payload tier keeps them separately, on request",
        }
    return record


def full_payload_record(payload: bytes, *, limit: int = FULL_PAYLOAD_LIMIT, peer: str = "") -> Dict[str, Any]:
    """The explicit escalation tier. Separate record, bounded, and labelled."""

    import base64

    trimmed = payload[: max(1, min(int(limit), FULL_PAYLOAD_LIMIT))]
    return {
        "kind": "full_payload",
        "tier": "full",
        "bytes_in": len(payload),
        "stored_bytes": len(trimmed),
        "truncated": len(trimmed) != len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "payload_b64": base64.b64encode(trimmed).decode("ascii"),
        "peer_id": redact_peer(peer)["peer_id"] if peer else "",
        "warning": (
            "Full payload holds everything the visitor sent, including credentials, tokens and "
            "third-party personal data. Keep it only as long as the investigation needs it, seal it "
            "with 'vault seal', and prefer the minimized record when it already answers the question."
        ),
        "why": "requested explicitly; used when the minimized fields cannot answer whether a technique actually worked",
    }


def summarize(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate minimised records without widening what is stored."""

    families: Dict[str, int] = {}
    methods: Dict[str, int] = {}
    redactions: Dict[str, int] = {}
    full_tier = 0
    total = 0
    for record in records:
        total += 1
        if record.get("tier") == "full":
            full_tier += 1
        family = (record.get("protocol") or {}).get("family")
        if family:
            families[family] = families.get(family, 0) + 1
        method = (record.get("fields") or {}).get("http.method")
        if method:
            methods[method] = methods.get(method, 0) + 1
        for entry in record.get("redactions", []):
            rule = entry.get("rule", "unknown")
            redactions[rule] = redactions.get(rule, 0) + 1
    return {
        "kind": "inspection_summary",
        "records": total,
        "full_payload_records": full_tier,
        "protocol_families": dict(sorted(families.items())),
        "http_methods": dict(sorted(methods.items())),
        "redaction_rules_applied": dict(sorted(redactions.items())),
        "note": "counts only; widening a summary into payloads is a separate, deliberate step",
    }


def inspect_file(
    path: str,
    *,
    scope: Dict[str, Any],
    include_full: bool = False,
    limit: int = FULL_PAYLOAD_LIMIT,
) -> Dict[str, Any]:
    """Minimise an existing capture file, optionally adding the full-payload tier.

    Accepts JSONL records that carry ``payload_b64`` or ``payload``, and falls back
    to treating each non-empty line as a raw opening line. The output never widens
    beyond the requested tier.
    """

    import base64
    import json
    from pathlib import Path

    source = Path(path)
    if not source.is_file():
        raise ValueError("%s is not a regular file" % source)
    raw = source.read_bytes()
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("%s is larger than the 8 MiB inspection input limit" % source)

    records: List[Dict[str, Any]] = []
    full_records: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        text = line.decode("utf-8", "replace").strip()
        if not text:
            continue
        payload: Optional[bytes] = None
        opening: Any = text
        peer = ""
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            peer = str(parsed.get("peer", ""))[:64]
            encoded = parsed.get("payload_b64")
            if isinstance(encoded, str):
                try:
                    payload = base64.b64decode(encoded, validate=True)
                except (ValueError, TypeError):
                    payload = None
            if payload is not None:
                opening = payload.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
            elif isinstance(parsed.get("opening"), str):
                opening = parsed["opening"]
            elif isinstance(parsed.get("first_line"), str):
                opening = parsed["first_line"]
        records.append(
            build_record(scope=scope, opening=opening, peer=peer, payload=payload)
        )
        if include_full and payload:
            full_records.append(full_payload_record(payload, limit=limit, peer=peer))

    result: Dict[str, Any] = {
        "kind": "inspection_file_result",
        "source": str(source),
        "scope": scope,
        "records": records,
        "summary": summarize(records),
        "tier": "full" if include_full else "minimized",
    }
    if include_full:
        result["full_payload_records"] = full_records
        result["full_payload_count"] = len(full_records)
    return result
