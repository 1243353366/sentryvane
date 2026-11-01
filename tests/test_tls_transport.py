"""Tests for TLS on the listeners this tool runs itself.

The certificate is generated per test into a temporary directory; nothing here
touches the network beyond loopback, and nothing reaches a third party. Where no
certificate tool is available the tests skip instead of asserting on a stub.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest

from reverse_shell_decoy.relay import RelayFleet, RelayTarget
from reverse_shell_decoy.synthetic import DEFAULT_SERVICES, SyntheticFleet
from reverse_shell_decoy.transport import TransportError, describe, optional_context, server_context

HAVE_OPENSSL = shutil.which("openssl") is not None
try:  # the vault extra also provides certificate generation
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False


def _make_cert(directory: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    if HAVE_OPENSSL:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=decoy.test",
            ],
            capture_output=True,
            check=True,
        )
        return cert, key
    if HAVE_CRYPTO:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "decoy.test")])
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        built = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(private, hashes.SHA256())
        )
        cert.write_bytes(built.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        return cert, key
    raise unittest.SkipTest("no openssl or cryptography available to make a test certificate")


def _client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class TransportConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._dir.name)
        self.cert, self.key = _make_cert(self.root)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_no_tls_requested_means_no_context(self) -> None:
        self.assertIsNone(optional_context(None, None))

    def test_half_a_tls_configuration_is_refused(self) -> None:
        with self.assertRaises(TransportError) as caught:
            optional_context(str(self.cert), None)
        self.assertIn("both --tls-cert and --tls-key", str(caught.exception))

    def test_missing_certificate_is_refused(self) -> None:
        with self.assertRaises(TransportError) as caught:
            server_context(str(self.root / "absent.pem"), str(self.key))
        self.assertIn("does not exist", str(caught.exception))

    def test_mismatched_key_is_refused(self) -> None:
        other_dir = self.root / "other"
        other_dir.mkdir()
        _, other_key = _make_cert(other_dir)
        with self.assertRaises(TransportError):
            server_context(str(self.cert), str(other_key))

    def test_context_sets_a_modern_floor(self) -> None:
        context = server_context(str(self.cert), str(self.key))
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_describe_reports_transport_and_fingerprint(self) -> None:
        info = describe(str(self.cert))
        self.assertEqual(info["transport"], "tls")
        self.assertEqual(len(info["certificate_sha256"]), 64)
        self.assertTrue(any("memory" in item for item in info["plaintext_visible_to"]))


class DecoyTlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._dir.name)
        self.cert, self.key = _make_cert(self.root)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self) -> None:
        self.loop.close()
        asyncio.set_event_loop(None)
        self._dir.cleanup()

    def _run(self, coroutine):
        return self.loop.run_until_complete(coroutine)

    def test_decoy_serves_its_banner_over_tls_and_records_the_transport(self) -> None:
        context = server_context(str(self.cert), str(self.key))
        fleet = SyntheticFleet(
            DEFAULT_SERVICES[:1],
            tls_context=context,
            allow_ephemeral_ports=True,
            capture_payloads=True,
            max_runtime=15,
        )

        async def scenario() -> tuple[str, dict]:
            await fleet.start()
            port = fleet.bound_ports[0]
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=_client_context())
            banner = (await asyncio.wait_for(reader.readline(), timeout=5)).decode()
            writer.write(b"GET /admin HTTP/1.0\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(256), timeout=5)
            writer.close()
            await asyncio.sleep(0.3)
            await fleet.stop()
            sessions = [r for r in fleet.audit if r.get("kind") == "synthetic_session"]
            return banner, sessions[0] if sessions else {}

        banner, record = self._run(scenario())
        self.assertIn("SYNTHETIC DECOY", banner)
        self.assertEqual(record.get("transport"), "tls")
        self.assertGreater(record.get("captured_bytes", 0), 0)

    def test_plaintext_client_gets_no_decoy_banner(self) -> None:
        context = server_context(str(self.cert), str(self.key))
        fleet = SyntheticFleet(DEFAULT_SERVICES[:1], tls_context=context, allow_ephemeral_ports=True, max_runtime=15)

        async def scenario() -> bytes:
            await fleet.start()
            port = fleet.bound_ports[0]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            with contextlib.suppress(ConnectionError, OSError):
                await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=3)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                data = b""
            writer.close()
            await fleet.stop()
            return data

        self.assertNotIn(b"SYNTHETIC DECOY", self._run(scenario()))

    def test_relay_front_can_terminate_tls_in_front_of_a_loopback_decoy(self) -> None:
        context = server_context(str(self.cert), str(self.key))
        backend = SyntheticFleet(DEFAULT_SERVICES[:1], allow_ephemeral_ports=True, max_runtime=15)

        async def scenario() -> tuple[str, dict]:
            await backend.start()
            target_port = backend.bound_ports[0]
            relay = RelayFleet(
                [RelayTarget("decoy", "127.0.0.1", target_port)],
                port=0,
                tls_context=context,
                max_runtime=15,
                capture_payloads=True,
            )
            await relay.start()
            reader, writer = await asyncio.open_connection("127.0.0.1", relay.bound_port, ssl=_client_context())
            banner = (await asyncio.wait_for(reader.readline(), timeout=5)).decode()
            writer.close()
            connected = []
            for _ in range(60):
                connected = [r for r in relay.records if r.get("kind") == "relay_connected"]
                if connected:
                    break
                await asyncio.sleep(0.05)
            await relay.stop()
            await backend.stop()
            return banner, connected[0] if connected else {}

        banner, record = self._run(scenario())
        self.assertIn("SYNTHETIC DECOY", banner)
        # The front listener is what had to speak TLS; its own records say so.
        self.assertEqual(record.get("transport"), "tls")
        self.assertEqual(record.get("target_scope"), "loopback")


class CliTlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._dir.name)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_cli_refuses_a_half_configured_tls_listener(self) -> None:
        cert, _ = _make_cert(self.root)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1] / "src")
        completed = subprocess.run(
            [sys.executable, "-m", "reverse_shell_decoy", "synthetic", "--tls-cert", str(cert), "--runtime", "0"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("both --tls-cert and --tls-key", completed.stderr)


if __name__ == "__main__":
    unittest.main()
