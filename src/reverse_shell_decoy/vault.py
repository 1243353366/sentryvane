"""Authenticated encryption for the evidence this tool collects on your own host.

Scope, stated plainly, because encryption is easy to over-claim:

* This protects evidence **at rest**: a copied archive, a synced folder, a stolen
  backup, a support bundle, or a disk image taken later. Without the key those
  are ciphertext.
* It does **not** protect evidence from an attacker who is already running code
  as you while the tool runs. The key is in process memory, and the plaintext of
  a captured session exists in memory before it is written. Sealing does not
  undo that; see ``docs/encrypted-evidence.md``.
* Sealing a file does **not** erase the plaintext original. ``status`` reports
  every plaintext sibling it can see, because a sealed copy next to an open one
  protects nothing.
* Nothing here decrypts traffic that is not addressed to your own services. A
  listener owned by somebody else is not yours to read.

ChaCha20-Poly1305 comes from ``cryptography``. When that package is missing this
module refuses to operate rather than falling back to something weaker, so an
operator never gets "encrypted" evidence that is not.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

MAGIC = b"SVVAULT1"
AAD_PREFIX = b"sentryvane.evidence.vault.v1"
KEY_BYTES = 32
NONCE_BYTES = 12
HEADER_VERSION = 1
MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024
DEFAULT_KEY_ENV = "SENTRYVANE_VAULT_KEY"
SEALED_SUFFIX = ".svv"
MANIFEST_SUFFIX = ".svm"
_KEY_HEX = KEY_BYTES * 2


class VaultUnavailable(RuntimeError):
    """The authenticated-encryption backend is not installed."""


class VaultError(ValueError):
    """An operator-fixable problem: bad key, bad file, unsafe permissions."""


def _aead_class():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError as exc:  # pragma: no cover - exercised via _force_unavailable
        raise VaultUnavailable(
            "evidence encryption needs the optional 'cryptography' package: "
            "python -m pip install 'sentryvane[vault]'. Nothing was written, and "
            "this tool will not use a weaker fallback cipher."
        ) from exc
    return ChaCha20Poly1305


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fingerprint(key: bytes) -> str:
    """A short, non-secret identifier for a key, safe to log and to store."""

    return hashlib.sha256(b"sentryvane.key.id|" + key).hexdigest()[:16]


def _coerce_key(raw: bytes, origin: str) -> bytes:
    if len(raw) == KEY_BYTES:
        return raw
    text = raw.strip()
    if len(text) == _KEY_HEX:
        try:
            return binascii.unhexlify(text)
        except binascii.Error:
            pass
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        decoded = b""
    if len(decoded) == KEY_BYTES:
        return decoded
    raise VaultError(
        "%s does not contain a %d-byte key (raw, %d hex characters, or base64). "
        "Generate one with: reverse-shell-decoy vault keygen --out <path>" % (origin, KEY_BYTES, _KEY_HEX)
    )


def _check_key_permissions(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise VaultError(
            "%s is a symbolic link. Point the vault at the key file itself so the "
            "permissions that are checked are the permissions that are used." % path
        )
    if not stat.S_ISREG(info.st_mode):
        raise VaultError("%s is not a regular file, so it cannot hold a vault key." % path)
    if info.st_mode & 0o077:
        raise VaultError(
            "%s is readable by group or others (mode %o). A key that other accounts can "
            "read is not protecting the evidence: chmod 600 %s"
            % (path, stat.S_IMODE(info.st_mode), path)
        )


def load_key(path: Optional[str] = None, *, env: str = DEFAULT_KEY_ENV) -> bytes:
    """Load the operator's key from a file, or from an environment variable."""

    if path:
        key_path = Path(path)
        if not key_path.exists():
            raise VaultError("no key file at %s" % key_path)
        _check_key_permissions(key_path)
        return _coerce_key(key_path.read_bytes(), str(key_path))
    value = os.environ.get(env, "")
    if not value:
        raise VaultError(
            "no key available. Pass --key-file, or set %s. The key is never written by "
            "this tool: if you lose it, the sealed evidence is gone." % env
        )
    return _coerce_key(value.encode("utf-8"), "environment variable %s" % env)


def keygen(path: str, *, force: bool = False) -> Dict[str, Any]:
    """Create a new random key with owner-only permissions."""

    key_path = Path(path)
    if key_path.exists() and not force:
        raise VaultError("%s already exists; refusing to overwrite a key that may be in use" % key_path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, base64.b64encode(secrets.token_bytes(KEY_BYTES)) + b"\n")
    finally:
        os.close(descriptor)
    os.chmod(key_path, 0o600)
    return {
        "kind": "vault_key",
        "path": str(key_path),
        "bytes": KEY_BYTES,
        "fingerprint": fingerprint(load_key(str(key_path))),
        "created_utc": _utc_now(),
        "warning": (
            "This is the only copy. It is not recoverable, it is not stored anywhere else, "
            "and nothing in the sealed evidence can be read without it. Back it up somewhere "
            "you control, separately from the evidence."
        ),
    }


def _header_bytes(header: Dict[str, Any]) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _aad(header_bytes: bytes) -> bytes:
    return AAD_PREFIX + b"|" + header_bytes


def seal_bytes(
    key: bytes,
    plaintext: bytes,
    *,
    stream: str = "evidence",
    index: int = 0,
    source_label: str = "",
    tool_version: str = "",
) -> bytes:
    """Encrypt and authenticate one blob of evidence."""

    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise VaultError(
            "refusing to seal %d bytes in one record (limit %d). Seal files individually "
            "instead of concatenating them." % (len(plaintext), MAX_PLAINTEXT_BYTES)
        )
    aead = _aead_class()(key)
    nonce = secrets.token_bytes(NONCE_BYTES)
    header = {
        "v": HEADER_VERSION,
        "tool_version": tool_version,
        "created_utc": _utc_now(),
        "stream": stream,
        "index": int(index),
        "plaintext_len": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "source_label": source_label,
        "key_fp": fingerprint(key),
    }
    header_bytes = _header_bytes(header)
    if len(header_bytes) > 0xFFFF:
        raise VaultError("vault header is unexpectedly large")
    ciphertext = aead.encrypt(nonce, plaintext, _aad(header_bytes))
    return MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes + nonce + ciphertext


def _parse(blob: bytes) -> tuple[Dict[str, Any], bytes, bytes, bytes]:
    if not blob.startswith(MAGIC):
        raise VaultError("not a sealed evidence file (missing the %s magic)" % MAGIC.decode("ascii"))
    offset = len(MAGIC)
    if len(blob) < offset + 4:
        raise VaultError("sealed file is truncated before its header length")
    header_len = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    header_bytes = blob[offset : offset + header_len]
    if len(header_bytes) != header_len:
        raise VaultError("sealed file is truncated inside its header")
    offset += header_len
    if len(blob) < offset + NONCE_BYTES + 16:
        raise VaultError("sealed file is truncated before its ciphertext")
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultError("sealed file header is not valid JSON") from exc
    if not isinstance(header, dict) or header.get("v") != HEADER_VERSION:
        raise VaultError("unsupported sealed-file version")
    nonce = blob[offset : offset + NONCE_BYTES]
    ciphertext = blob[offset + NONCE_BYTES :]
    return header, header_bytes, nonce, ciphertext


def open_bytes(key: bytes, blob: bytes) -> tuple[bytes, Dict[str, Any]]:
    """Authenticate and decrypt one sealed blob."""

    header, header_bytes, nonce, ciphertext = _parse(blob)
    if header.get("key_fp") and header["key_fp"] != fingerprint(key):
        raise VaultError(
            "this evidence was sealed with a different key (record %s, supplied key %s)"
            % (header["key_fp"], fingerprint(key))
        )
    aead = _aead_class()(key)
    try:
        plaintext = aead.decrypt(nonce, ciphertext, _aad(header_bytes))
    except Exception as exc:  # cryptography raises InvalidTag
        raise VaultError(
            "authentication failed: the file was altered, truncated, or sealed with another key. "
            "Treat this evidence as unreliable rather than as merely unreadable."
        ) from exc
    if len(plaintext) != header.get("plaintext_len"):
        raise VaultError("decrypted length does not match the authenticated header")
    if hashlib.sha256(plaintext).hexdigest() != header.get("plaintext_sha256"):
        raise VaultError("decrypted content does not match the authenticated digest")
    return plaintext, header


def inspect_bytes(blob: bytes) -> Dict[str, Any]:
    """Report what a sealed file claims about itself, without the key.

    The header is authenticated, so these fields cannot be altered without the
    verification failing later; but this call verifies nothing on its own.
    """

    header, _, _, ciphertext = _parse(blob)
    return {
        "kind": "sealed_evidence",
        "sealed_bytes": len(blob),
        "ciphertext_bytes": len(ciphertext),
        **{key: header.get(key) for key in (
            "v", "tool_version", "created_utc", "stream", "index",
            "plaintext_len", "plaintext_sha256", "source_label", "key_fp",
        )},
        "authenticated": False,
        "note": "metadata only; run 'vault verify' with the key to authenticate the content",
    }


def _write_private(path: Path, data: bytes, *, force: bool) -> None:
    if path.exists() and not force:
        raise VaultError("%s already exists; pass --force to replace it" % path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def seal_file(
    key: bytes,
    source: str,
    destination: Optional[str] = None,
    *,
    force: bool = False,
    tool_version: str = "",
) -> Dict[str, Any]:
    src = Path(source)
    if not src.is_file():
        raise VaultError("%s is not a regular file" % src)
    size = src.stat().st_size
    if size > MAX_PLAINTEXT_BYTES:
        raise VaultError("%s is %d bytes, over the %d byte record limit" % (src, size, MAX_PLAINTEXT_BYTES))
    plaintext = src.read_bytes()
    blob = seal_bytes(key, plaintext, stream="file", source_label=str(src.name), tool_version=tool_version)
    dst = Path(destination) if destination else Path(str(src) + SEALED_SUFFIX)
    _write_private(dst, blob, force=force)
    return {
        "kind": "seal_result",
        "source": str(src),
        "sealed": str(dst),
        "plaintext_bytes": len(plaintext),
        "sealed_bytes": len(blob),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "key_fp": fingerprint(key),
        "plaintext_original_still_present": src.exists(),
        "note": (
            "Sealing wrote a new file. The plaintext original is still on disk: delete it "
            "yourself once the sealed copy is backed up, and remember that deletion on most "
            "modern media is not guaranteed. Full-disk encryption is what covers that gap."
        ),
    }


def open_file(key: bytes, source: str, destination: str, *, force: bool = False) -> Dict[str, Any]:
    src = Path(source)
    if not src.is_file():
        raise VaultError("%s is not a regular file" % src)
    plaintext, header = open_bytes(key, src.read_bytes())
    _write_private(Path(destination), plaintext, force=force)
    return {
        "kind": "open_result",
        "sealed": str(src),
        "written": str(destination),
        "plaintext_bytes": len(plaintext),
        "sealed_at_utc": header.get("created_utc"),
        "sealed_with_key_fp": header.get("key_fp"),
        "current_key_fp": fingerprint(key),
        "note": "the decrypted copy is plaintext on disk; handle it as the sensitive evidence it is",
    }


def verify_file(key: bytes, source: str) -> Dict[str, Any]:
    src = Path(source)
    if not src.is_file():
        raise VaultError("%s is not a regular file" % src)
    plaintext, header = open_bytes(key, src.read_bytes())
    return {
        "kind": "verify_result",
        "file": str(src),
        "authenticated": True,
        "plaintext_bytes": len(plaintext),
        "sealed_at_utc": header.get("created_utc"),
        "source_label": header.get("source_label"),
        "key_fp": header.get("key_fp"),
    }


def status(paths: Sequence[str]) -> Dict[str, Any]:
    """Describe what is sealed and, more usefully, what is still plaintext."""

    entries: List[Dict[str, Any]] = []
    plaintext_seen: List[str] = []
    gaps: List[str] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            entries.append({"path": str(path), "state": "missing"})
            continue
        if path.is_dir():
            files = sorted(p for p in path.rglob("*") if p.is_file())
        else:
            files = [path]
        for item in files:
            try:
                blob = item.read_bytes()
            except OSError as exc:
                entries.append({"path": str(item), "state": "unreadable", "reason": str(exc)})
                continue
            if blob.startswith(MAGIC):
                info = inspect_bytes(blob)
                entries.append({"path": str(item), "state": "sealed", **{
                    "sealed_bytes": info["sealed_bytes"],
                    "plaintext_bytes": info["plaintext_len"],
                    "sealed_at_utc": info["created_utc"],
                    "key_fp": info["key_fp"],
                }})
                plain_name = item.name[: -len(SEALED_SUFFIX)] if item.name.endswith(SEALED_SUFFIX) else ""
                if plain_name and (item.parent / plain_name).exists():
                    gaps.append("%s is sealed but %s is still there in the clear" % (item, item.parent / plain_name))
            else:
                plaintext_seen.append(str(item))
                entries.append({"path": str(item), "state": "plaintext", "bytes": len(blob)})
    if plaintext_seen:
        gaps.append("%d file(s) are plaintext; sealing them is what makes a stolen copy useless" % len(plaintext_seen))
    return {
        "kind": "vault_status",
        "paths": [str(p) for p in paths],
        "entries": entries,
        "sealed": sum(1 for e in entries if e["state"] == "sealed"),
        "plaintext": sum(1 for e in entries if e["state"] == "plaintext"),
        "gaps": gaps,
        "limits": [
            "Encryption at rest does not stop a compromised host from reading evidence while it is collected.",
            "Sealing does not erase the plaintext original.",
            "This covers your own evidence on your own machine; it decrypts nobody else's traffic.",
        ],
    }


def build_manifest(key: bytes, sealed_paths: Sequence[str], *, tool_version: str = "") -> bytes:
    """Seal an inventory so that removal or substitution of a sealed file is visible."""

    records: List[Dict[str, Any]] = []
    for raw in sealed_paths:
        path = Path(raw)
        if not path.is_file():
            raise VaultError("%s is not a regular file" % path)
        blob = path.read_bytes()
        if not blob.startswith(MAGIC):
            raise VaultError("%s is not sealed; only sealed files belong in a manifest" % path)
        header = inspect_bytes(blob)
        records.append({
            "path": str(path),
            "sealed_bytes": len(blob),
            "sealed_sha256": hashlib.sha256(blob).hexdigest(),
            "plaintext_sha256": header.get("plaintext_sha256"),
            "sealed_at_utc": header.get("created_utc"),
            "key_fp": header.get("key_fp"),
        })
    payload = json.dumps(
        {"kind": "vault_manifest", "created_utc": _utc_now(), "entries": records},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return seal_bytes(key, payload, stream="manifest", source_label="manifest", tool_version=tool_version)


def verify_manifest(key: bytes, manifest_path: str) -> Dict[str, Any]:
    path = Path(manifest_path)
    if not path.is_file():
        raise VaultError("%s is not a regular file" % manifest_path)
    plaintext, _ = open_bytes(key, path.read_bytes())
    try:
        manifest = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultError("manifest payload is not valid JSON") from exc
    if manifest.get("kind") != "vault_manifest":
        raise VaultError("sealed file is not a vault manifest")
    missing: List[str] = []
    altered: List[str] = []
    ok = 0
    for entry in manifest.get("entries", []):
        target = Path(entry["path"])
        if not target.is_file():
            missing.append(str(target))
            continue
        blob = target.read_bytes()
        if len(blob) != entry["sealed_bytes"] or hashlib.sha256(blob).hexdigest() != entry["sealed_sha256"]:
            altered.append(str(target))
            continue
        ok += 1
    return {
        "kind": "manifest_verification",
        "manifest": str(path),
        "expected": len(manifest.get("entries", [])),
        "matched": ok,
        "missing": missing,
        "altered": altered,
        "intact": not missing and not altered,
        "manifest_created_utc": manifest.get("created_utc"),
        "note": "a manifest detects removal and substitution of sealed files; it does not restore them",
    }
