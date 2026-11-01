"""TLS on the listeners this tool runs on your own machine.

The point is narrow and honest: when a decoy or relay front terminates TLS with a
key you hold, an observer on the path sees ciphertext instead of your fake banner
and the visitor's keystrokes, and a scanner that only reads plaintext gets
nothing useful. The plaintext still exists in this process, because something has
to interpret it to record evidence.

This module refuses to start a listener in a half-configured state. If TLS is
requested and the certificate or key is missing, unreadable, or mismatched, the
call raises instead of quietly falling back to plaintext: "encrypted" must not be
a label the operator believes without evidence.
"""

from __future__ import annotations

import hashlib
import ssl
from pathlib import Path
from typing import Any, Dict, Optional


class TransportError(ValueError):
    """TLS was requested but cannot be configured safely."""


def _require_file(path: str, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_file():
        raise TransportError("%s file %s does not exist" % (label, candidate))
    try:
        candidate.read_bytes()[:1]
    except OSError as exc:
        raise TransportError("%s file %s is not readable: %s" % (label, candidate, exc)) from exc
    return candidate


def server_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """Build a server context from the operator's own certificate and key."""

    cert = _require_file(cert_path, "certificate")
    key = _require_file(key_path, "private key")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    try:
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    except ssl.SSLError as exc:
        raise TransportError(
            "certificate and key could not be loaded together (%s). A mismatched pair is "
            "refused rather than served as if it were working." % exc
        ) from exc
    except OSError as exc:
        raise TransportError("certificate or key could not be read: %s" % exc) from exc
    return context


def describe(cert_path: str) -> Dict[str, Any]:
    """Metadata to record alongside a session so its transport is provable."""

    cert = _require_file(cert_path, "certificate")
    der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="utf-8", errors="replace"))
    return {
        "transport": "tls",
        "tls_min_version": "TLSv1.2",
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "certificate_path": str(cert),
        "plaintext_visible_to": [
            "this process, in memory, for as long as the session is open (it has to be decrypted to be recorded)",
            "anyone who already runs code on this host and can read that memory",
        ],
        "note": (
            "A TLS client that does not accept this certificate will fail the handshake. "
            "That is the intended behaviour: the decoy does not pretend to be a service you "
            "do not own a certificate for."
        ),
    }


def optional_context(cert_path: Optional[str], key_path: Optional[str]) -> Optional[ssl.SSLContext]:
    """Return a context when TLS is configured, and nothing when it is not asked for.

    Passing only one half of the pair is an error, not a silent downgrade.
    """

    if not cert_path and not key_path:
        return None
    if not cert_path or not key_path:
        raise TransportError(
            "TLS needs both --tls-cert and --tls-key. Serving plaintext because only one "
            "was supplied would contradict the operator's intent."
        )
    return server_context(cert_path, key_path)
