"""Tests for prevention policy and containment planning.

The point of these tests is the refusals: an approved port is not contained, a shared
cgroup is not called process-scoped, an unconfirmed apply changes nothing, and an empty
inventory is not scored as a clean host.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from reverse_shell_decoy import harden

POLICY = {
    "version": 1,
    "allow": [
        {"executable": "/usr/sbin/sshd", "ports": [22], "exposure": "any", "reason": "operator SSH"},
        {"executable": "/usr/bin/python3", "ports": [22022, 22080], "exposure": "loopback", "reason": "synthetic decoys"},
    ],
}

LIVE = [
    {"port": 22, "address": "0.0.0.0", "exposure": "public", "executable": "/usr/sbin/sshd", "pid": 900, "uid": 0},
    {"port": 22022, "address": "127.0.0.1", "exposure": "loopback", "executable": "/usr/bin/python3", "pid": 1200, "uid": 1000},
    {"port": 4444, "address": "0.0.0.0", "exposure": "public", "executable": "/tmp/.x/nc", "pid": 4242, "uid": 1000},
    {"port": 8080, "address": "0.0.0.0", "exposure": "public", "executable": "", "pid": 5150, "uid": 1000},
    {"port": 9999, "address": "0.0.0.0", "exposure": "public", "executable": "/usr/bin/python3", "pid": 1300, "uid": 1000},
]

PROCS = [
    {"pid": 1, "uid": 0, "comm": "systemd", "cgroup": "/system.slice", "exe": "/usr/lib/systemd/systemd"},
    {"pid": 4242, "uid": 1000, "comm": "nc", "cgroup": "/user.slice/session-3.scope", "exe": "/tmp/.x/nc"},
    {"pid": 1200, "uid": 1000, "comm": "python3", "cgroup": "/user.slice/session-3.scope", "exe": "/usr/bin/python3"},
    {"pid": 5150, "uid": 4242, "comm": "curl", "cgroup": "/user.slice/session-9.scope", "exe": "/usr/bin/curl"},
]


class FakeResult:
    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr


class RecordingRunner:
    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, argv):
        self.calls.append(list(argv))
        return FakeResult(self.returncode, self.stderr)


class PolicyTests(unittest.TestCase):
    def test_policy_requires_a_reason_for_every_entry(self) -> None:
        with self.assertRaises(harden.HardenError):
            harden.load_policy({"allow": [{"executable": "/bin/x", "ports": [1]}]})

    def test_policy_rejects_bad_ports_and_exposure(self) -> None:
        with self.assertRaises(harden.HardenError):
            harden.load_policy({"allow": [{"executable": "/bin/x", "ports": [0], "reason": "r"}]})
        with self.assertRaises(harden.HardenError):
            harden.load_policy({"allow": [{"executable": "/bin/x", "ports": [9], "exposure": "everywhere", "reason": "r"}]})

    def test_policy_from_file_and_version_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "p.json"
            path.write_text(json.dumps(POLICY))
            self.assertEqual(len(harden.load_policy(path)["allow"]), 2)
            path.write_text(json.dumps({**POLICY, "version": 99}))
            with self.assertRaises(harden.HardenError):
                harden.load_policy(path)

    def test_empty_policy_is_refused(self) -> None:
        with self.assertRaises(harden.HardenError):
            harden.load_policy({"allow": []})


class VerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = harden.verify_policy(LIVE, harden.load_policy(POLICY))
        self.by_port = {entry["port"]: entry for entry in self.result["listeners"]}

    def test_each_listener_gets_the_right_verdict(self) -> None:
        self.assertEqual(self.by_port[22]["status"], "approved")
        self.assertEqual(self.by_port[22022]["status"], "approved")
        self.assertEqual(self.by_port[4444]["status"], "unlisted")
        self.assertEqual(self.by_port[8080]["status"], "unattributed")
        self.assertEqual(self.by_port[9999]["status"], "unexpected-port")

    def test_unattributed_is_never_treated_as_allowed(self) -> None:
        entry = self.by_port[8080]
        self.assertNotEqual(entry["status"], "approved")
        self.assertIn("unknown", entry["detail"])

    def test_loopback_only_rule_catches_a_wider_binding(self) -> None:
        listeners = [{"port": 22080, "address": "0.0.0.0", "exposure": "public", "executable": "/usr/bin/python3"}]
        result = harden.verify_policy(listeners, harden.load_policy(POLICY))
        self.assertEqual(result["listeners"][0]["status"], "unexpected-exposure")

    def test_drift_summary_counts_and_lists_the_unapproved(self) -> None:
        self.assertEqual(self.result["verdict"], "drift")
        self.assertEqual(self.result["counts"], {"approved": 2, "unattributed": 1, "unexpected-port": 1, "unlisted": 1})
        self.assertEqual(len(self.result["unapproved"]), 3)

    def test_clean_host_and_empty_inventory_are_different_answers(self) -> None:
        clean = harden.verify_policy(LIVE[:2], harden.load_policy(POLICY))
        self.assertEqual(clean["verdict"], "clean")
        self.assertEqual(harden.verify_policy([], harden.load_policy(POLICY))["verdict"], "unknown")


class PreventionPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = harden.prevention_plan(harden.load_policy(POLICY))

    def test_every_step_names_what_it_touches_and_how_to_undo_it(self) -> None:
        for step in self.plan["steps"]:
            self.assertTrue(step["revert"], step["id"])
            self.assertTrue(step["why"], step["id"])
            self.assertIn("collateral", step)

    def test_default_deny_accepts_exactly_the_policy_ports(self) -> None:
        step = next(step for step in self.plan["steps"] if step["id"] == "inbound-default-deny")
        content = step["file_to_write"]["content"]
        for port in (22, 22022, 22080):
            self.assertIn("tcp dport %d accept" % port, content)
        self.assertNotIn("dport 4444", content)
        self.assertIn("policy drop", content)

    def test_plan_is_advisory_not_executed(self) -> None:
        self.assertIn("not actions this tool takes", self.plan["note"])
        self.assertEqual(self.plan["kind"], "prevention_plan")


class ContainmentPlanTests(unittest.TestCase):
    def test_allowlisted_port_is_refused_before_any_plan_is_built(self) -> None:
        with self.assertRaises(harden.HardenError):
            harden.contain_plan(port=22, policy=harden.load_policy(POLICY), listeners=LIVE)

    def test_port_tier_is_precise_and_reversible(self) -> None:
        plan = harden.contain_plan(port=4444, policy=harden.load_policy(POLICY), listeners=LIVE)
        self.assertEqual(plan["recommended"], "port")
        tier = plan["tiers"][0]
        self.assertTrue(tier["safe_to_apply"])
        self.assertIn("tcp dport 4444 drop", " ".join(tier["commands"]))
        self.assertEqual(tier["revert"], ["nft delete table inet %s" % harden.TABLE_NAME])
        self.assertEqual(tier["collateral"]["listeners_also_blocked"], [])

    def test_port_and_pid_together_are_refused_as_confusing(self) -> None:
        with self.assertRaises(harden.HardenError):
            harden.contain_plan(port=4444, pid=4242, processes=PROCS)

    def test_shared_cgroup_is_not_called_process_scoped(self) -> None:
        plan = harden.contain_plan(pid=4242, processes=PROCS)
        cgroup_tier = next(tier for tier in plan["tiers"] if tier["tier"] == "cgroup")
        self.assertFalse(cgroup_tier["safe_to_apply"])
        self.assertEqual(cgroup_tier["collateral"]["processes_sharing_cgroup"], [1200])
        self.assertIn("shared", cgroup_tier["why"])

    def test_lone_process_gets_a_safe_cgroup_tier(self) -> None:
        procs = [
            {"pid": 4242, "uid": 1000, "comm": "nc", "cgroup": "/user.slice/alone.scope", "exe": "/tmp/.x/nc"},
            {"pid": 1, "uid": 0, "comm": "systemd", "cgroup": "/system.slice", "exe": "/usr/lib/systemd/systemd"},
        ]
        plan = harden.contain_plan(pid=4242, processes=procs)
        cgroup_tier = next(tier for tier in plan["tiers"] if tier["tier"] == "cgroup")
        self.assertTrue(cgroup_tier["safe_to_apply"])
        self.assertIn("socket cgroupv2", " ".join(cgroup_tier["commands"]))

    def test_uid_tier_reports_how_many_processes_it_would_cut(self) -> None:
        plan = harden.contain_plan(pid=4242, processes=PROCS)
        uid_tier = next(tier for tier in plan["tiers"] if tier["tier"] == "uid")
        self.assertEqual(uid_tier["collateral"]["processes_sharing_uid"], 2)
        self.assertFalse(uid_tier["safe_to_apply"])

    def test_pid_not_in_the_table_is_an_error(self) -> None:
        with self.assertRaises(harden.HardenError):
            harden.contain_plan(pid=999999, processes=PROCS)

    def test_plan_states_which_tier_the_tool_would_apply(self) -> None:
        plan = harden.contain_plan(port=4444, listeners=LIVE)
        self.assertEqual(plan["applied_by_this_tool"], ["port"])
        self.assertIn("nothing here kills a process", plan["note"].lower())


class ApplyTests(unittest.TestCase):
    def test_apply_without_confirmation_changes_nothing(self) -> None:
        runner = RecordingRunner()
        with self.assertRaises(harden.HardenError):
            harden.apply_port_block(4444, confirm=False, runner=runner, require_root=False)
        self.assertEqual(runner.calls, [])

    def test_apply_refuses_an_allowlisted_port(self) -> None:
        runner = RecordingRunner()
        with self.assertRaises(harden.HardenError):
            harden.apply_port_block(22, confirm=True, runner=runner, require_root=False, policy=harden.load_policy(POLICY))
        self.assertEqual(runner.calls, [])

    def test_apply_records_an_undo_file_and_the_exact_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.environ["SENTRYVANE_STATE_DIR"] = directory
            harden.STATE_DIR = pathlib.Path(directory)
            runner = RecordingRunner()
            result = harden.apply_port_block(4444, confirm=True, runner=runner, require_root=False)
            self.assertEqual(len(runner.calls), 3)
            self.assertIn("tcp", runner.calls[2])
            self.assertIn("4444", runner.calls[2])
            state = pathlib.Path(result["state_file"])
            self.assertTrue(state.is_file())
            payload = json.loads(state.read_text())
            self.assertEqual(payload["undo"], ["nft", "delete", "table", "inet", harden.TABLE_NAME])
            self.assertEqual(oct(state.stat().st_mode)[-3:], "600")

    def test_a_failed_command_is_reported_rather_than_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harden.STATE_DIR = pathlib.Path(directory)
            result = harden.apply_port_block(
                4444, confirm=True, runner=RecordingRunner(1, "nft: permission denied"), require_root=False
            )
            self.assertEqual(result["applied"][0]["returncode"], 1)
            self.assertIn("permission denied", result["applied"][0]["stderr"])

    def test_rollback_drops_the_table_and_clears_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            harden.STATE_DIR = pathlib.Path(directory)
            harden.apply_port_block(4444, confirm=True, runner=RecordingRunner(), require_root=False)
            runner = RecordingRunner()
            result = harden.rollback_port_block(port=4444, runner=runner, require_root=False)
            self.assertEqual(runner.calls, [["nft", "delete", "table", "inet", harden.TABLE_NAME]])
            self.assertTrue(result["had_state_file"])
            self.assertFalse(harden._state_path(4444).is_file())

    def test_root_is_required_by_default(self) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            self.skipTest("running as root")
        with self.assertRaises(harden.HardenError):
            harden.apply_port_block(4444, confirm=True, runner=RecordingRunner())


class ProcessTableTests(unittest.TestCase):
    def test_procfs_read_survives_missing_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            entry = root / "1234"
            entry.mkdir()
            (entry / "status").write_text("Name:\tweird\nUid:\t1000\t1000\t1000\t1000\n")
            procs = harden._proc_processes(root)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0]["pid"], 1234)
        self.assertEqual(procs[0]["uid"], 1000)
        self.assertEqual(procs[0]["comm"], "weird")

    def test_absent_proc_root_yields_no_processes_instead_of_raising(self) -> None:
        self.assertEqual(harden._proc_processes(pathlib.Path("/nonexistent-proc")), [])


class CliTests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1] / "src")
        env.pop("SENTRYVANE_STATE_DIR", None)
        return subprocess.run(
            [sys.executable, "-m", "reverse_shell_decoy", *args],
            capture_output=True, text=True, env=env, check=False, timeout=60,
        )

    def test_plan_needs_no_root_and_prints_every_step(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = pathlib.Path(directory) / "p.json"
            policy.write_text(json.dumps(POLICY))
            completed = self._run("harden", "plan", "--policy", str(policy))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(json.loads(completed.stdout)["steps"]), 5)

    def test_apply_without_confirm_is_refused(self) -> None:
        completed = self._run("contain", "apply", "--port", "4444")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("confirmation", completed.stderr + completed.stdout)


if __name__ == "__main__":
    unittest.main()
