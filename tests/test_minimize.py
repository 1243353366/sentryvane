"""Tests for metadata-first inspection: scope, allowlisted fields, redaction and bounds."""
from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from reverse_shell_decoy import minimize

#: Synthetic fixtures, assembled at runtime. No credential-shaped literal is committed
#: to this repository, and the values still exercise every redaction rule.
FAKE_KEY = "sk" + "-live-" + "abcdef1234567890"
FAKE_BEARER = "Bearer " + "abcdefghijklmnop"
FAKE_PASSWORD = "pass" + "word=" + "hunter2"
FAKE_EMAIL = "aadi" + "@" + "example.com"

SECRETS = {
    "token": FAKE_KEY,
    "bearer": FAKE_BEARER,
    "password": FAKE_PASSWORD,
    "email": FAKE_EMAIL,
}


class ScopeTests(unittest.TestCase):
    def test_loopback_scope_states_its_basis(self) -> None:
        scope = minimize.inspection_scope(listener="synthetic:ssh", port=22022)
        self.assertIn("own listener on this host", scope["basis"])
        self.assertIn("loopback", scope["basis"])
        self.assertTrue(scope["permitted"])

    def test_unreviewed_public_binding_is_flagged_as_unknown_exposure(self) -> None:
        scope = minimize.inspection_scope(listener="synthetic:http", port=22080, loopback_only=False)
        items = [entry["item"] for entry in scope["not_permitted"]]
        self.assertIn("traffic to this port", items)

    def test_reviewed_public_binding_records_the_review(self) -> None:
        scope = minimize.inspection_scope(
            listener="synthetic:http", port=22080, loopback_only=False, reviewed_public=True
        )
        self.assertIn("independently reviewed", scope["basis"])
        self.assertNotIn("traffic to this port", [entry["item"] for entry in scope["not_permitted"]])

    def test_scope_refuses_what_is_not_ours_at_any_setting(self) -> None:
        for loopback in (True, False):
            scope = minimize.inspection_scope(listener="x", port=1, loopback_only=loopback)
            items = " ".join(entry["item"] for entry in scope["not_permitted"])
            self.assertIn("did not start", items)
            self.assertIn("other than this one", items)

    def test_inspection_window_is_bounded(self) -> None:
        self.assertEqual(minimize.inspection_scope(listener="x", port=1, window_bytes=10**9)["inspection_window_bytes"], minimize.MAX_WINDOW_BYTES)
        self.assertEqual(minimize.inspection_scope(listener="x", port=1, window_bytes=0)["inspection_window_bytes"], 1)


class ProtocolMetadataTests(unittest.TestCase):
    def test_http_request_line_gives_method_path_and_version(self) -> None:
        parsed = minimize.parse_opening(b"POST /api/v1/login HTTP/1.1")
        self.assertEqual(parsed["family"], "http")
        self.assertEqual(parsed["confidence"], "high")
        self.assertEqual(parsed["fields"]["http.method"], "POST")
        self.assertEqual(parsed["fields"]["http.path"], "/api/v1/login")
        self.assertEqual(parsed["fields"]["http.version"], "HTTP/1.1")

    def test_query_values_are_dropped_but_keys_kept(self) -> None:
        parsed = minimize.parse_opening("GET /search?q=secretterm&token=abc123 HTTP/1.1")
        self.assertEqual(parsed["fields"]["http.query_keys"], ["q", "token"])
        self.assertNotIn("secretterm", json.dumps(parsed))
        self.assertNotIn("abc123", json.dumps(parsed))

    def test_ssh_banner_keeps_protocol_and_software(self) -> None:
        parsed = minimize.parse_opening(b"SSH-2.0-libssh_0.9.6")
        self.assertEqual(parsed["family"], "ssh")
        self.assertEqual(parsed["fields"]["ssh.protocol"], "2.0")
        self.assertIn("libssh", parsed["fields"]["ssh.banner"])

    def test_smtp_and_line_protocols_keep_only_the_verb(self) -> None:
        self.assertEqual(minimize.parse_opening(b"EHLO mail.example.com")["fields"]["smtp.greeting"], "EHLO")
        redis = minimize.parse_opening(b"SET stolen-key some-long-value")
        self.assertEqual(redis["fields"]["redis.command"], "SET")
        self.assertNotIn("some-long-value", json.dumps(redis))

    def test_unrecognised_opening_is_digested_not_stored(self) -> None:
        parsed = minimize.parse_opening(b"\x00\x01\x02opaque binary\xff")
        self.assertEqual(parsed["fields"], {})
        self.assertEqual(len(parsed["opening_sha256"]), 64)
        self.assertTrue(any("digest only" in rule for rule in parsed["redactions"]))
        self.assertNotIn("opaque binary", json.dumps(parsed))

    def test_secret_looking_path_segment_is_redacted(self) -> None:
        parsed = minimize.parse_opening(b"GET /admin/abcdefghijklmnopqrstuvwx/reset HTTP/1.1")
        self.assertIn("[redacted:path-segment]", parsed["fields"]["http.path"])


class RedactionTests(unittest.TestCase):
    def test_each_secret_pattern_fires(self) -> None:
        for name, raw in SECRETS.items():
            text, rules = minimize.redact_text(raw)
            self.assertTrue(rules, name)
            self.assertIn("[redacted:", text, name)

    def test_clean_text_is_untouched_and_unreported(self) -> None:
        text, rules = minimize.redact_text("/static/app.css")
        self.assertEqual(text, "/static/app.css")
        self.assertEqual(rules, [])

    def test_service_and_header_fields_are_treated_as_sensitive(self) -> None:
        for field in ("authorization", "cookie", "x-api-key", "password"):
            text, rules = minimize.redact_text("anything-at-all", field=field)
            self.assertEqual(text, "[redacted:opaque-value]", field)
            self.assertTrue(rules)

    def test_peer_address_keeps_a_correlating_id_and_drops_the_host_part(self) -> None:
        peer = minimize.redact_peer("203.0.113.42")
        self.assertEqual(peer["address"], "203.0.113.x")
        self.assertEqual(len(peer["peer_id"]), 12)
        self.assertEqual(peer["peer_id"], minimize.redact_peer("203.0.113.42")["peer_id"])
        self.assertNotEqual(peer["peer_id"], minimize.redact_peer("203.0.113.43")["peer_id"])

    def test_values_are_length_bounded(self) -> None:
        text, _ = minimize.redact_text("a" * 500)
        self.assertLessEqual(len(text), minimize.MAX_FIELD_VALUE)


class RecordTests(unittest.TestCase):
    def _record(self, payload: bytes = b"") -> dict:
        return minimize.build_record(
            scope=minimize.inspection_scope(listener="synthetic:http", port=22080),
            opening=("GET /admin?user=" + FAKE_EMAIL + "&api_key=" + FAKE_KEY + " HTTP/1.1").encode(),
            bytes_in=412,
            frames=4,
            duration_ms=900,
            peer="198.51.100.9",
            payload=payload or None,
        )

    def test_no_secret_value_survives_into_the_record(self) -> None:
        blob = json.dumps(self._record())
        self.assertNotIn(FAKE_KEY, blob)
        self.assertNotIn(FAKE_EMAIL, blob)
        self.assertNotIn("198.51.100.9", blob)
        self.assertIn("198.51.100.x", blob)

    def test_record_contains_no_body_bytes(self) -> None:
        body = ("body with " + FAKE_PASSWORD).encode()
        record = self._record(body)
        self.assertEqual(record["tier"], "minimized")
        self.assertFalse(record["payload"]["stored"])
        self.assertEqual(record["payload"]["bytes"], len(body))
        self.assertNotIn("hunter2", json.dumps(record))

    def test_every_kept_field_carries_its_reason(self) -> None:
        record = self._record()
        self.assertEqual(set(record["fields"]), set(record["field_reasons"]))
        for reason in record["field_reasons"].values():
            self.assertTrue(reason)

    def test_only_allowlisted_fields_are_kept(self) -> None:
        record = self._record()
        for name in record["fields"]:
            self.assertIn(name, minimize.ALLOWLIST)

    def test_record_states_what_was_not_inspected(self) -> None:
        record = self._record()
        items = " ".join(entry["item"] for entry in record["not_inspected"])
        self.assertIn("bodies", items)
        self.assertIn("header values", items)
        self.assertTrue(record["why_this_is_enough"])

    def test_bounds_are_reported_and_enforced(self) -> None:
        record = self._record()
        self.assertLessEqual(record["bounds"]["fields_kept"], minimize.MAX_FIELDS)
        self.assertLessEqual(record["bounds"]["stored_field_bytes"], minimize.MAX_FIELDS * minimize.MAX_FIELD_VALUE)
        self.assertEqual(record["bounds"]["max_field_value"], minimize.MAX_FIELD_VALUE)

    def test_full_payload_tier_is_separate_bounded_and_labelled(self) -> None:
        record = minimize.full_payload_record(b"x" * 100, limit=10, peer="198.51.100.9")
        self.assertEqual(record["tier"], "full")
        self.assertTrue(record["truncated"])
        self.assertEqual(record["stored_bytes"], 10)
        self.assertEqual(record["bytes_in"], 100)
        self.assertIn("credentials", record["warning"])
        self.assertTrue(record["peer_id"])

    def test_summary_counts_without_widening(self) -> None:
        summary = minimize.summarize([self._record(), minimize.full_payload_record(b"abc")])
        self.assertEqual(summary["records"], 2)
        self.assertEqual(summary["full_payload_records"], 1)
        self.assertEqual(summary["http_methods"], {"GET": 1})
        self.assertEqual(set(summary), {
            "kind", "records", "full_payload_records", "protocol_families",
            "http_methods", "redaction_rules_applied", "note",
        })


class InspectFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._dir.name)
        self.scope = minimize.inspection_scope(listener="file:test", port=22080)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_jsonl_capture_is_minimized_and_secrets_stay_out(self) -> None:
        payload = ("GET /admin?token=" + FAKE_KEY + " HTTP/1.1\r\n\r\n" + FAKE_PASSWORD).encode()
        line = json.dumps({"peer": "198.51.100.9", "payload_b64": base64.b64encode(payload).decode()})
        path = self.root / "cap.jsonl"
        path.write_text(line + "\n")
        result = minimize.inspect_file(str(path), scope=self.scope)
        self.assertEqual(result["tier"], "minimized")
        self.assertNotIn("hunter2", json.dumps(result))
        self.assertNotIn(FAKE_KEY, json.dumps(result))
        self.assertNotIn("full_payload_records", result)

    def test_full_tier_is_only_produced_when_asked_for(self) -> None:
        path = self.root / "cap.jsonl"
        path.write_text(json.dumps({"payload_b64": base64.b64encode(b"SET k v").decode()}) + "\n")
        result = minimize.inspect_file(str(path), scope=self.scope, include_full=True)
        self.assertEqual(result["tier"], "full")
        self.assertEqual(result["full_payload_count"], 1)
        self.assertEqual(result["full_payload_records"][0]["tier"], "full")

    def test_plain_lines_are_treated_as_openings(self) -> None:
        path = self.root / "lines.txt"
        path.write_text("SSH-2.0-libssh_0.9.6\n")
        result = minimize.inspect_file(str(path), scope=self.scope)
        self.assertEqual(result["records"][0]["protocol"]["family"], "ssh")

    def test_oversized_input_is_refused(self) -> None:
        path = self.root / "big.jsonl"
        path.write_bytes(b"x" * (9 * 1024 * 1024))
        with self.assertRaises(ValueError):
            minimize.inspect_file(str(path), scope=self.scope)


class InspectCliTests(unittest.TestCase):
    def test_cli_minimizes_without_a_key_or_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "cap.jsonl"
            path.write_text("GET /admin?token=" + FAKE_KEY + " HTTP/1.1\n")
            env = {"PYTHONPATH": str(pathlib.Path(__file__).resolve().parents[1] / "src")}
            completed = subprocess.run(
                [sys.executable, "-m", "reverse_shell_decoy", "inspect", "--file", str(path), "--port", "22080"],
                capture_output=True, text=True, env=env, check=False, timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["kind"], "inspection_file_result")
            self.assertEqual(result["records"][0]["fields"]["http.method"], "GET")


class SessionIntegrationTests(unittest.TestCase):
    def test_synthetic_session_records_carry_the_minimized_tier(self) -> None:
        import asyncio

        from reverse_shell_decoy.synthetic import DEFAULT_SERVICES, SyntheticFleet

        async def scenario() -> dict:
            fleet = SyntheticFleet(DEFAULT_SERVICES[:1], allow_ephemeral_ports=True, max_runtime=10)
            await fleet.start()
            reader, writer = await asyncio.open_connection("127.0.0.1", fleet.bound_ports[0])
            await reader.readline()
            writer.write(("GET /probe?key=" + FAKE_KEY + " HTTP/1.0\r\n\r\n").encode())
            await writer.drain()
            await asyncio.sleep(0.2)
            writer.close()
            await asyncio.sleep(0.4)
            await fleet.stop()
            sessions = [r for r in fleet.audit if r.get("kind") == "synthetic_session"]
            return sessions[0] if sessions else {}

        record = asyncio.run(scenario())
        inspection = record.get("inspection", {})
        self.assertEqual(inspection.get("tier"), "minimized")
        self.assertEqual(inspection["fields"]["http.method"], "GET")
        self.assertNotIn(FAKE_KEY, json.dumps(record))
        # Full payload remains opt-in, and says so when it is on.
        self.assertNotIn("payload_tier", record)


if __name__ == "__main__":
    unittest.main()
