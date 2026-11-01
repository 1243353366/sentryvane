"""Tests for sealed evidence: authenticated encryption, key handling, and the honest gaps.

These tests need the optional encryption backend. When it is missing the suite
skips rather than pretending the feature works; the module under test fails
closed in exactly the same situation, which one test asserts explicitly.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from reverse_shell_decoy import vault

try:  # pragma: no cover - the skip path is environment dependent
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

PAYLOAD = b"GET /admin HTTP/1.1\r\nHost: decoy\r\nX-Probe: credential-stuffing\r\n\r\n"


class VaultTestCase(unittest.TestCase):
    def setUp(self) -> None:
        if not HAVE_CRYPTO:
            self.skipTest("optional 'cryptography' package not installed")
        self._dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._dir.name)
        self.key_path = self.root / "vault.key"
        vault.keygen(str(self.key_path))
        self.key = vault.load_key(str(self.key_path))

    def tearDown(self) -> None:
        self._dir.cleanup()

    def _sealed(self, payload: bytes = PAYLOAD, name: str = "session.log") -> pathlib.Path:
        blob = vault.seal_bytes(self.key, payload, stream="file", source_label=name)
        path = self.root / (name + vault.SEALED_SUFFIX)
        path.write_bytes(blob)
        return path


class KeyHandlingTests(VaultTestCase):
    def test_generated_key_is_owner_only_and_reloading_matches(self) -> None:
        mode = self.key_path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)
        self.assertEqual(len(self.key), vault.KEY_BYTES)
        self.assertEqual(vault.fingerprint(self.key), vault.fingerprint(vault.load_key(str(self.key_path))))

    def test_world_readable_key_is_refused(self) -> None:
        os.chmod(self.key_path, 0o644)
        with self.assertRaises(vault.VaultError) as caught:
            vault.load_key(str(self.key_path))
        self.assertIn("chmod 600", str(caught.exception))

    def test_symlinked_key_is_refused(self) -> None:
        link = self.root / "link.key"
        os.symlink(self.key_path, link)
        with self.assertRaises(vault.VaultError) as caught:
            vault.load_key(str(link))
        self.assertIn("symbolic link", str(caught.exception))

    def test_short_key_is_rejected_with_guidance(self) -> None:
        bad = self.root / "short.key"
        bad.write_bytes(b"too-short")
        os.chmod(bad, 0o600)
        with self.assertRaises(vault.VaultError) as caught:
            vault.load_key(str(bad))
        self.assertIn("32-byte key", str(caught.exception))

    def test_missing_key_is_an_error_not_a_default(self) -> None:
        with self.assertRaises(vault.VaultError):
            vault.load_key(None, env="SENTRYVANE_VAULT_KEY_NOT_SET_FOR_TEST")

    def test_keygen_refuses_to_overwrite(self) -> None:
        with self.assertRaises(vault.VaultError):
            vault.keygen(str(self.key_path))


class SealOpenTests(VaultTestCase):
    def test_round_trip_restores_the_exact_bytes(self) -> None:
        path = self._sealed()
        restored, header = vault.open_bytes(self.key, path.read_bytes())
        self.assertEqual(restored, PAYLOAD)
        self.assertEqual(header["plaintext_len"], len(PAYLOAD))

    def test_sealed_file_contains_no_plaintext(self) -> None:
        blob = self._sealed().read_bytes()
        self.assertNotIn(b"credential-stuffing", blob)
        self.assertNotIn(b"GET /admin", blob)
        self.assertTrue(blob.startswith(vault.MAGIC))

    def test_wrong_key_reports_a_key_mismatch_not_corruption(self) -> None:
        path = self._sealed()
        other = vault._coerce_key(b"\x01" * vault.KEY_BYTES, "test")
        with self.assertRaises(vault.VaultError) as caught:
            vault.open_bytes(other, path.read_bytes())
        self.assertIn("different key", str(caught.exception))

    def test_tampered_ciphertext_fails_authentication(self) -> None:
        path = self._sealed()
        blob = bytearray(path.read_bytes())
        blob[-5] ^= 0x01
        with self.assertRaises(vault.VaultError) as caught:
            vault.open_bytes(self.key, bytes(blob))
        self.assertIn("altered", str(caught.exception))

    def test_tampered_header_fails_authentication(self) -> None:
        path = self._sealed()
        blob = bytearray(path.read_bytes())
        marker = blob.find(b'"plaintext_len"')
        self.assertGreater(marker, 0)
        blob[marker + len(b'"plaintext_len":')] = ord("9")
        with self.assertRaises(vault.VaultError):
            vault.open_bytes(self.key, bytes(blob))

    def test_truncated_file_is_refused_before_decryption(self) -> None:
        path = self._sealed()
        blob = path.read_bytes()
        with self.assertRaises(vault.VaultError):
            vault.open_bytes(self.key, blob[: len(vault.MAGIC) + 2])

    def test_unsealed_input_is_named_as_such(self) -> None:
        with self.assertRaises(vault.VaultError) as caught:
            vault.open_bytes(self.key, b"plain evidence, no magic here" * 3)
        self.assertIn("not a sealed evidence file", str(caught.exception))

    def test_inspection_needs_no_key_and_says_it_verified_nothing(self) -> None:
        info = vault.inspect_bytes(self._sealed().read_bytes())
        self.assertEqual(info["plaintext_len"], len(PAYLOAD))
        self.assertFalse(info["authenticated"])
        self.assertIn("verify", info["note"])

    def test_oversized_record_is_refused(self) -> None:
        with self.assertRaises(vault.VaultError) as caught:
            vault.seal_bytes(self.key, b"x" * (vault.MAX_PLAINTEXT_BYTES + 1))
        self.assertIn("limit", str(caught.exception))


class FileAndStatusTests(VaultTestCase):
    def test_sealing_reports_that_the_plaintext_original_survives(self) -> None:
        src = self.root / "capture.log"
        src.write_bytes(PAYLOAD)
        result = vault.seal_file(self.key, str(src), tool_version="0.1.5")
        self.assertTrue(result["plaintext_original_still_present"])
        self.assertTrue((self.root / "capture.log.svv").exists())
        self.assertIn("Full-disk encryption", result["note"])

    def test_open_writes_private_file_and_refuses_to_clobber(self) -> None:
        path = self._sealed()
        target = self.root / "restored.log"
        vault.open_file(self.key, str(path), str(target))
        self.assertEqual(target.read_bytes(), PAYLOAD)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(vault.VaultError):
            vault.open_file(self.key, str(path), str(target))

    def test_status_names_plantext_siblings_as_a_gap(self) -> None:
        src = self.root / "capture.log"
        src.write_bytes(PAYLOAD)
        vault.seal_file(self.key, str(src))
        report = vault.status([str(self.root)])
        self.assertEqual(report["sealed"], 1)
        self.assertGreaterEqual(report["plaintext"], 1)
        self.assertTrue(any("still there in the clear" in gap for gap in report["gaps"]))
        self.assertTrue(report["limits"])

    def test_verify_authenticates_without_writing_anything(self) -> None:
        path = self._sealed()
        before = sorted(p.name for p in self.root.iterdir())
        result = vault.verify_file(self.key, str(path))
        self.assertTrue(result["authenticated"])
        self.assertEqual(before, sorted(p.name for p in self.root.iterdir()))


class ManifestTests(VaultTestCase):
    def test_manifest_detects_removal(self) -> None:
        first = self._sealed(name="one.log")
        second = self._sealed(name="two.log")
        manifest = vault.build_manifest(self.key, [str(first), str(second)])
        manifest_path = self.root / "evidence.svm"
        manifest_path.write_bytes(manifest)
        self.assertTrue(vault.verify_manifest(self.key, str(manifest_path))["intact"])

        second.unlink()
        result = vault.verify_manifest(self.key, str(manifest_path))
        self.assertFalse(result["intact"])
        self.assertEqual(result["missing"], [str(second)])

    def test_manifest_detects_substitution(self) -> None:
        path = self._sealed()
        manifest_path = self.root / "evidence.svm"
        manifest_path.write_bytes(vault.build_manifest(self.key, [str(path)]))
        path.write_bytes(vault.seal_bytes(self.key, b"replacement evidence", stream="file"))
        result = vault.verify_manifest(self.key, str(manifest_path))
        self.assertFalse(result["intact"])
        self.assertEqual(result["altered"], [str(path)])

    def test_manifest_refuses_unsealed_input(self) -> None:
        plain = self.root / "plain.log"
        plain.write_bytes(PAYLOAD)
        with self.assertRaises(vault.VaultError):
            vault.build_manifest(self.key, [str(plain)])


class FailClosedTests(unittest.TestCase):
    def test_missing_backend_is_reported_not_worked_around(self) -> None:
        original = vault._aead_class
        vault._aead_class = lambda: (_ for _ in ()).throw(vault.VaultUnavailable("backend missing"))
        try:
            with self.assertRaises(vault.VaultUnavailable):
                vault.seal_bytes(b"\x00" * vault.KEY_BYTES, PAYLOAD)
        finally:
            vault._aead_class = original


class VaultCliTests(VaultTestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1] / "src")
        return subprocess.run(
            [sys.executable, "-m", "reverse_shell_decoy", "vault", *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_cli_seals_and_opens_the_same_bytes(self) -> None:
        src = self.root / "capture.log"
        src.write_bytes(PAYLOAD)
        sealed = self._run("seal", str(src), "--key-file", str(self.key_path))
        self.assertEqual(sealed.returncode, 0, sealed.stderr)
        self.assertIn("seal_result", sealed.stdout)

        out = self.root / "restored.log"
        opened = self._run("open", str(src) + vault.SEALED_SUFFIX, "--out", str(out), "--key-file", str(self.key_path))
        self.assertEqual(opened.returncode, 0, opened.stderr)
        self.assertEqual(out.read_bytes(), PAYLOAD)

    def test_cli_status_needs_no_key(self) -> None:
        src = self.root / "capture.log"
        src.write_bytes(PAYLOAD)
        self._run("seal", str(src), "--key-file", str(self.key_path))
        status = self._run("status", str(self.root))
        self.assertEqual(status.returncode, 0, status.stderr)
        report = json.loads(status.stdout)
        self.assertEqual(report["kind"], "vault_status")
        self.assertEqual(report["sealed"], 1)

    def test_cli_fails_cleanly_when_no_key_is_available(self) -> None:
        src = self.root / "capture.log"
        src.write_bytes(PAYLOAD)
        env_result = self._run("seal", str(src), "--key-file", str(self.root / "absent.key"))
        self.assertEqual(env_result.returncode, 2)
        self.assertIn("no key file", env_result.stderr)
        self.assertFalse((self.root / "capture.log.svv").exists())


if __name__ == "__main__":
    unittest.main()
