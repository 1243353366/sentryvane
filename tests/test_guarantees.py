"""Tests for the seven containment properties.

Each property is checked twice: once against the mechanism (static scan or a guard
that must raise) and once against an observation from a live loopback run. A property
without both is expected to report as unverified, and that is tested too.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from reverse_shell_decoy import guarantees


class PropertyCatalogueTests(unittest.TestCase):
    def test_all_seven_properties_are_declared_in_the_users_order(self) -> None:
        ids = [prop["id"] for prop in guarantees.PROPERTIES]
        self.assertEqual(
            ids,
            [
                "connection",
                "host_resources",
                "relay_scope",
                "no_execution",
                "synthetic_responses",
                "session_control",
                "evidence",
            ],
        )

    def test_every_property_states_mechanism_observation_and_limit(self) -> None:
        for prop in guarantees.PROPERTIES:
            for key in ("claim", "enforced_by", "observed_by", "limit"):
                self.assertTrue(prop.get(key), "%s missing %s" % (prop["id"], key))

    def test_every_property_has_a_limit_because_none_is_absolute(self) -> None:
        self.assertEqual(len({prop["limit"] for prop in guarantees.PROPERTIES}), len(guarantees.PROPERTIES))


class CapabilityScanTests(unittest.TestCase):
    def test_shipped_listener_modules_contain_no_execution_primitive(self) -> None:
        scan = guarantees.scan_package()
        self.assertEqual(scan["missing_modules"], [])
        self.assertEqual(scan["execution_hits"], 0)
        self.assertTrue(scan["modules"])

    def test_scan_detects_a_planted_execution_primitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            module = pathlib.Path(directory) / "sneaky.py"
            module.write_text(
                "import os\n"
                "def handler(peer_input):\n"
                "    os.system(peer_input)\n"
                "    return eval(peer_input)\n"
            )
            result = guarantees.scan_module(module)
        calls = [entry["call"] for entry in result["execution"]]
        self.assertEqual(calls, ["os.system", "eval"])
        self.assertEqual([entry["line"] for entry in result["execution"]], [3, 4])

    def test_scan_separates_network_calls_from_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            module = pathlib.Path(directory) / "connector.py"
            module.write_text("import socket\nsocket.create_connection(('127.0.0.1', 22))\n")
            result = guarantees.scan_module(module)
        self.assertEqual(result["execution"], [])
        self.assertEqual(result["network"][0]["call"], "socket.create_connection")

    def test_non_literal_open_is_reported_because_peer_input_must_not_become_a_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            module = pathlib.Path(directory) / "reader.py"
            module.write_text("def serve(name):\n    return open(name).read()\n")
            result = guarantees.scan_module(module)
        self.assertEqual(len(result["opens"]), 1)
        self.assertFalse(result["opens"][0]["literal_argument"])

    def test_unreadable_module_is_reported_not_ignored(self) -> None:
        result = guarantees.scan_module(pathlib.Path("/nonexistent/module.py"))
        self.assertIn("error", result)


class LiveProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = guarantees.probe(timeout=8.0)

    def test_a_visitor_can_connect_and_is_told_it_is_synthetic(self) -> None:
        self.assertTrue(self.evidence["connect_ok"])
        self.assertTrue(self.evidence["banner_is_synthetic"])
        self.assertTrue(self.evidence["peer_told_it_is_synthetic"])

    def test_host_file_requests_and_shell_syntax_never_return_content(self) -> None:
        self.assertFalse(self.evidence["canary_leaked"])
        leaks = [entry["probe"] for entry in self.evidence["probes"] if entry["leaked_canary"]]
        self.assertEqual(leaks, [])
        output = [entry["probe"] for entry in self.evidence["probes"] if entry["looks_like_shell_output"]]
        self.assertEqual(output, [])

    def test_connect_attempt_is_refused_by_the_relay_guard(self) -> None:
        self.assertTrue(self.evidence["relay_refuses_remote_target"])
        self.assertTrue(self.evidence["relay_accepts_loopback_target"])

    def test_a_flood_is_throttled_and_the_denials_are_recorded(self) -> None:
        self.assertGreaterEqual(self.evidence["throttle_attempts"], 10)
        self.assertGreater(self.evidence["throttle_denials"], 0)
        self.assertIn("synthetic_throttled", self.evidence["records_by_kind"])

    def test_termination_names_a_budget(self) -> None:
        self.assertTrue(self.evidence["session_reasons"])
        for reason in self.evidence["session_reasons"]:
            self.assertTrue(reason)

    def test_every_probe_produced_evidence_of_several_kinds(self) -> None:
        kinds = self.evidence["records_by_kind"]
        self.assertGreaterEqual(len(kinds), 3)
        self.assertIn("synthetic_connected", kinds)
        self.assertIn("synthetic_session", kinds)


class ReportTests(unittest.TestCase):
    def test_live_report_verifies_all_seven(self) -> None:
        result = guarantees.audit(timeout=8.0)
        self.assertEqual(result["kind"], "containment_report")
        self.assertEqual(result["summary"]["verdict"], "verified", result["summary"])
        self.assertEqual(len(result["summary"]["verified"]), 7)

    def test_a_property_without_an_observation_is_unverified_not_passed(self) -> None:
        result = guarantees.audit(run_probe=False)
        self.assertEqual(result["summary"]["verdict"], "unverified")
        self.assertEqual(result["summary"]["verified"], [])
        self.assertEqual(len(result["summary"]["unverified"]), 7)
        for prop in result["properties"]:
            self.assertEqual(prop["status"], "unverified")
            self.assertIn("not requested", prop["probe_error"])

    def test_a_leaked_canary_fails_the_host_resource_property(self) -> None:
        evidence = {
            "connect_ok": True,
            "banner_is_synthetic": True,
            "peer_told_it_is_synthetic": True,
            "probes": [{"probe": "read-host-file", "leaked_canary": True, "looks_like_shell_output": False}],
            "canary_leaked": True,
            "relay_refuses_remote_target": True,
            "relay_accepts_loopback_target": True,
            "throttle_denials": 3,
            "records_by_kind": {"synthetic_connected": 1, "synthetic_session": 1},
        }
        result = guarantees.report(evidence=evidence)
        by_id = {prop["id"]: prop for prop in result["properties"]}
        self.assertEqual(by_id["host_resources"]["status"], "failed")
        self.assertEqual(result["summary"]["verdict"], "failed")

    def test_command_output_in_a_response_fails_the_execution_property(self) -> None:
        evidence = {
            "connect_ok": True,
            "banner_is_synthetic": True,
            "probes": [{"probe": "identity", "leaked_canary": False, "looks_like_shell_output": True}],
            "canary_leaked": False,
            "relay_refuses_remote_target": True,
            "relay_accepts_loopback_target": True,
            "throttle_denials": 2,
            "records_by_kind": {"synthetic_connected": 1, "synthetic_session": 1},
        }
        by_id = {prop["id"]: prop for prop in guarantees.report(evidence=evidence)["properties"]}
        self.assertEqual(by_id["no_execution"]["status"], "failed")

    def test_an_open_relay_fails_the_relay_property(self) -> None:
        evidence = {
            "connect_ok": True,
            "banner_is_synthetic": True,
            "probes": [{"probe": "x", "leaked_canary": False, "looks_like_shell_output": False}],
            "relay_refuses_remote_target": False,
            "relay_accepts_loopback_target": True,
            "throttle_denials": 1,
            "records_by_kind": {"synthetic_connected": 1, "synthetic_session": 1},
        }
        by_id = {prop["id"]: prop for prop in guarantees.report(evidence=evidence)["properties"]}
        self.assertEqual(by_id["relay_scope"]["status"], "failed")

    def test_report_carries_the_capability_scan_and_the_compromise_note(self) -> None:
        result = guarantees.report(evidence={}, probe_error="boom")
        self.assertEqual(result["capability_scan"]["execution_hits"], 0)
        self.assertIn("compromised", result["note"])


class GuaranteesCliTests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1] / "src")
        return subprocess.run(
            [sys.executable, "-m", "reverse_shell_decoy", "guarantees", *args],
            capture_output=True, text=True, env=env, check=False, timeout=90,
        )

    def test_static_only_run_exits_nonzero_because_nothing_is_verified(self) -> None:
        completed = self._run("--no-probe")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["summary"]["verdict"], "unverified")

    def test_live_run_exits_zero_and_lists_the_properties(self) -> None:
        completed = self._run("--timeout", "8")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["summary"]["verdict"], "verified")
        self.assertEqual(len(result["properties"]), 7)


if __name__ == "__main__":
    unittest.main()
