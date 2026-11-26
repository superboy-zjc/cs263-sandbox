"""Tests for external control and result classification, without guest code."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from sandbox.evaluation import harness


class PipeControlTest(unittest.TestCase):
    """Exercise the controller with harmless bounded helper processes."""

    def test_request_and_response(self):
        command = [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
        ]
        code, output, stderr, reason = harness._exchange(command, b"hello", 2)
        self.assertEqual(
            (code, output, stderr, reason), (0, b"hello", b"", None)
        )

    def test_wall_timeout_stops_client(self):
        command = [sys.executable, "-c", "import time; time.sleep(0.3)"]
        _, _, _, reason = harness._exchange(command, b"", 0.03)
        self.assertEqual(reason, "wall_timeout")

    def test_protocol_limit_caps_parent_buffer(self):
        command = [
            sys.executable,
            "-c",
            "import os; os.write(1, b'x' * 200000)",
        ]
        _, output, _, reason = harness._exchange(command, b"", 2)
        self.assertEqual(reason, "protocol_limit")
        self.assertEqual(len(output), harness.MAX_RESPONSE_BYTES)


class CaseFileTest(unittest.TestCase):
    """Validate case metadata and typed expectations."""

    def test_project_cases_have_distinct_ids(self):
        cases, fingerprint = harness.load_cases(Path("benchmarks/cases.json"))
        self.assertGreaterEqual(len(cases), 10)
        self.assertEqual(len(fingerprint), 64)

    def test_performance_suite_loads(self):
        cases, fingerprint = harness.load_cases(
            Path("benchmarks/performance.json")
        )
        self.assertGreaterEqual(len(cases), 5)
        self.assertTrue(all(case["category"] == "benign" for case in cases))
        self.assertEqual(len(fingerprint), 64)

    def test_humaneval_compatibility_suite_loads(self):
        cases, fingerprint = harness.load_cases(
            Path("benchmarks/humaneval.json")
        )
        self.assertEqual(len(cases), 30)
        self.assertEqual(
            sum(case["partition"] == "development" for case in cases), 20
        )
        self.assertEqual(
            sum(case["partition"] == "heldout" for case in cases), 10
        )
        self.assertTrue(
            all(case["category"] == "compatibility" for case in cases)
        )
        self.assertEqual(len(fingerprint), 64)

    def test_compatibility_cases_require_reproducible_metadata(self):
        compatibility = {
            "id": "external",
            "category": "compatibility",
            "partition": "development",
            "description": "An external benign program.",
            "code": "1",
            "expected": {"status": "ok", "value": 1},
            "provenance": {
                "source_title": "Example",
                "source_url": "https://example.com/data",
                "source_locator": "case 1",
                "dataset_sha256": "a" * 64,
                "adaptation": "No adaptation.",
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            for changes in (
                {"partition": "test"},
                {"description": ""},
                {"provenance": None},
                {"expected": {"status": "unsupported"}},
            ):
                path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "cases": [compatibility | changes],
                        }
                    )
                )
                with (
                    self.subTest(changes=changes),
                    self.assertRaises(ValueError),
                ):
                    harness.load_cases(path)

    def test_duplicate_ids_are_rejected(self):
        case = {
            "id": "duplicate",
            "category": "benign",
            "code": "1",
            "expected": {"status": "ok", "value": 1},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "cases": [case, case],
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                harness.load_cases(path)

    def test_bool_does_not_match_integer(self):
        self.assertFalse(
            harness.matches_expected(
                {"status": "ok", "value": True}, {"status": "ok", "value": 1}
            )
        )

    def test_missing_value_does_not_match_explicit_none(self):
        self.assertFalse(
            harness.matches_expected(
                {"status": "ok"}, {"status": "ok", "value": None}
            )
        )

    def test_non_finite_and_malformed_case_metadata_are_rejected(self):
        case = {
            "id": "invalid",
            "category": "benign",
            "code": "1",
            "expected": {"status": "ok", "value": 1},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            for changes in (
                {"category": []},
                {"expected": {"status": []}},
                {"expected": {"status": "ok", "value": float("nan")}},
            ):
                path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "cases": [case | changes],
                        }
                    )
                )
                with (
                    self.subTest(changes=changes),
                    self.assertRaises(ValueError),
                ):
                    harness.load_cases(path)

    def test_unsupported_is_not_policy_rejection(self):
        self.assertFalse(
            harness.matches_expected(
                {"status": "unsupported"}, {"status": "policy_rejected"}
            )
        )

    def test_invalid_limits(self):
        for value in (0, -1, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                harness.Settings(wall_seconds=value)

    def test_invalid_trial_metadata_is_rejected(self):
        case = {
            "id": "test",
            "category": "benign",
            "code": "1",
            "expected": {"status": "ok", "value": 1},
        }
        for index, count in ((0, 1), (2, 1), (1, 0), (True, 1)):
            with self.subTest(index=index, count=count):
                with self.assertRaisesRegex(ValueError, "trial"):
                    harness.run_case(
                        case,
                        "prototype",
                        "sha256:example",
                        harness.Settings(),
                        "suite",
                        trial_index=index,
                        trial_count=count,
                    )

    def test_attack_cases_require_provenance_and_oracle(self):
        attack = {
            "id": "attack",
            "category": "attack",
            "description": "Attempt to expose the evaluation canary.",
            "attack_goal": "Read a file outside the language policy.",
            "code": "open('/tmp/canary').read()",
            "expected": {"status": "policy_rejected"},
            "provenance": {
                "source_title": "Example",
                "source_url": "https://example.com/source",
                "source_locator": "Example section",
                "adaptation": "Changed the target to the canary.",
            },
            "oracle": {"kind": "canary_exposure"},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            for changes in (
                {"provenance": None},
                {"oracle": None},
                {"oracle": {"kind": "unknown"}},
            ):
                path.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "cases": [attack | changes],
                        }
                    )
                )
                with (
                    self.subTest(changes=changes),
                    self.assertRaises(ValueError),
                ):
                    harness.load_cases(path)

    def test_attack_suite_loads(self):
        cases, fingerprint = harness.load_cases(
            Path("benchmarks/attacks.json")
        )
        self.assertGreaterEqual(len(cases), 10)
        self.assertTrue(all(case["category"] == "attack" for case in cases))
        self.assertEqual(len(fingerprint), 64)


class AttackOracleTest(unittest.TestCase):
    """Check success independently from executor status classification."""

    def test_canary_in_raw_worker_output_is_success(self):
        canary = "c" * 64
        case = {"oracle": {"kind": "canary_exposure"}}
        observed = {"status": "program_error"}

        result = harness.evaluate_attack_oracle(
            case,
            observed,
            json.dumps({"stdout": canary}).encode(),
            b"",
            canary,
        )

        self.assertTrue(result["attack_success"])
        self.assertEqual(result["evidence_channels"], ["worker_stdout"])

    def test_rejection_is_not_itself_oracle_evidence(self):
        result = harness.evaluate_attack_oracle(
            {"oracle": {"kind": "canary_exposure"}},
            {"status": "policy_rejected"},
            b'{"status":"policy_rejected"}',
            b"",
            "d" * 64,
        )

        self.assertFalse(result["attack_success"])
        self.assertEqual(result["evidence_channels"], [])

    def test_outer_termination_uses_explicit_statuses(self):
        case = {
            "oracle": {
                "kind": "outer_termination",
                "success_statuses": ["wall_timeout", "oom_killed"],
            }
        }

        result = harness.evaluate_attack_oracle(
            case, {"status": "wall_timeout"}, b"", b"", None
        )

        self.assertTrue(result["attack_success"])


class ContainerBoundaryTest(unittest.TestCase):
    """Verify isolation arguments and cleanup on timeout without Docker."""

    @mock.patch("sandbox.evaluation.harness.subprocess.run")
    @mock.patch("sandbox.evaluation.harness._inspect_container")
    @mock.patch("sandbox.evaluation.harness._exchange")
    def test_timeout_kills_and_removes_only_its_container(
        self, exchange, inspect, run
    ):
        exchange.return_value = (-9, b"", b"", "wall_timeout")
        inspect.return_value = {"oom_killed": False, "exit_code": 137}
        run.return_value = subprocess.CompletedProcess([], 0)
        case = {
            "id": "test",
            "category": "resource",
            "code": "pass",
            "expected": {"status": "resource_limit"},
        }
        record = harness.run_case(
            case, "prototype", "sha256:example", harness.Settings(), "suite"
        )
        command = exchange.call_args.args[0]
        name = command[command.index("--name") + 1]
        self.assertTrue(name.startswith("cs263-eval-"))
        self.assertIn("--read-only", command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertNotIn("--volume", command)
        run.assert_any_call(
            ["docker", "kill", name],
            capture_output=True,
            timeout=10,
            check=False,
        )
        run.assert_any_call(
            ["docker", "rm", "--force", name],
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(record["observed"]["status"], "wall_timeout")
        self.assertFalse(record["matches_expected"])
        self.assertTrue(record["cleanup_ok"])
        self.assertEqual(record["controller_errors"], [])
        self.assertIsNone(record["partition"])

    @mock.patch("sandbox.evaluation.harness.subprocess.run")
    @mock.patch("sandbox.evaluation.harness._inspect_container")
    @mock.patch("sandbox.evaluation.harness._exchange")
    def test_cleanup_failure_is_recorded_without_losing_execution_result(
        self, exchange, inspect, run
    ):
        observed = {
            "status": "ok",
            "value": 1,
            "stdout": "",
            "events": [],
            "steps": 1,
            "error": None,
        }
        exchange.return_value = (0, json.dumps(observed).encode(), b"", None)
        inspect.return_value = {"oom_killed": False, "exit_code": 0}
        run.side_effect = subprocess.TimeoutExpired("docker rm", 10)
        case = {
            "id": "test",
            "category": "benign",
            "code": "1",
            "expected": {"status": "ok", "value": 1},
        }
        record = harness.run_case(
            case, "prototype", "sha256:example", harness.Settings(), "suite"
        )
        self.assertTrue(record["matches_expected"])
        self.assertFalse(record["cleanup_ok"])
        self.assertEqual(
            record["controller_errors"],
            ["remove: cleanup failed after 3 attempts."],
        )
        self.assertEqual(record["cleanup"]["attempts"], 3)
        self.assertEqual(len(record["cleanup"]["diagnostics"]), 3)

    @mock.patch("sandbox.evaluation.harness.subprocess.run")
    @mock.patch("sandbox.evaluation.harness._inspect_container")
    @mock.patch("sandbox.evaluation.harness._exchange")
    def test_transient_cleanup_failure_is_retried(
        self, exchange, inspect, run
    ):
        observed = {
            "status": "ok",
            "value": 1,
            "stdout": "",
            "events": [],
            "steps": 1,
            "error": None,
        }
        exchange.return_value = (0, json.dumps(observed).encode(), b"", None)
        inspect.return_value = {"oom_killed": False, "exit_code": 0}
        run.side_effect = [
            subprocess.CompletedProcess([], 1, stderr=b"removal in progress"),
            subprocess.CompletedProcess([], 0),
        ]
        case = {
            "id": "test",
            "category": "benign",
            "code": "1",
            "expected": {"status": "ok", "value": 1},
        }

        record = harness.run_case(
            case, "prototype", "sha256:example", harness.Settings(), "suite"
        )

        self.assertTrue(record["cleanup_ok"])
        self.assertEqual(record["cleanup"]["attempts"], 2)
        self.assertEqual(
            record["cleanup"]["diagnostics"],
            [
                {
                    "attempt": 1,
                    "returncode": 1,
                    "error": "removal in progress",
                }
            ],
        )
        self.assertEqual(record["controller_errors"], [])

    @mock.patch("sandbox.evaluation.harness.subprocess.run")
    @mock.patch("sandbox.evaluation.harness._inspect_container")
    @mock.patch("sandbox.evaluation.harness._exchange")
    def test_transient_inspection_failure_is_retried(
        self, exchange, inspect, run
    ):
        observed = {
            "status": "ok",
            "value": 1,
            "stdout": "",
            "events": [],
            "steps": 1,
            "error": None,
        }
        exchange.return_value = (0, json.dumps(observed).encode(), b"", None)
        inspect.side_effect = [
            RuntimeError("transient"),
            {"oom_killed": False, "exit_code": 0, "running": False},
        ]
        run.return_value = subprocess.CompletedProcess([], 0)
        case = {
            "id": "test",
            "category": "benign",
            "code": "1",
            "expected": {"status": "ok", "value": 1},
        }

        record = harness.run_case(
            case, "prototype", "sha256:example", harness.Settings(), "suite"
        )

        self.assertTrue(record["inspection"]["ok"])
        self.assertEqual(record["inspection"]["attempts"], 2)
        self.assertEqual(
            record["inspection"]["diagnostics"],
            [{"attempt": 1, "error": "RuntimeError"}],
        )
        self.assertEqual(record["controller_errors"], [])

    @mock.patch("sandbox.evaluation.harness.subprocess.run")
    @mock.patch("sandbox.evaluation.harness._inspect_container")
    @mock.patch("sandbox.evaluation.harness._exchange")
    def test_malformed_worker_response_is_protocol_error(
        self, exchange, inspect, run
    ):
        exchange.return_value = (0, b'{"status":"ok"}', b"", None)
        inspect.return_value = {"oom_killed": False, "exit_code": 0}
        run.return_value = subprocess.CompletedProcess([], 0)
        case = {
            "id": "test",
            "category": "benign",
            "code": "1",
            "expected": {"status": "ok", "value": None},
        }
        record = harness.run_case(
            case, "prototype", "sha256:example", harness.Settings(), "suite"
        )
        self.assertEqual(record["observed"]["status"], "protocol_error")
        self.assertFalse(record["matches_expected"])

    @mock.patch("sandbox.evaluation.harness.subprocess.run")
    @mock.patch("sandbox.evaluation.harness._inspect_container")
    @mock.patch("sandbox.evaluation.harness._exchange")
    def test_canary_case_uses_bootstrap_and_records_oracle(
        self, exchange, inspect, run
    ):
        observed = {
            "status": "policy_rejected",
            "value": None,
            "stdout": "",
            "events": [],
            "steps": 0,
            "error": "blocked",
        }
        exchange.return_value = (0, json.dumps(observed).encode(), b"", None)
        inspect.return_value = {"oom_killed": False, "exit_code": 0}
        run.return_value = subprocess.CompletedProcess([], 0)
        case = {
            "id": "test",
            "category": "attack",
            "description": "A test attack.",
            "attack_goal": "Read the canary.",
            "code": "open('/tmp/canary').read()",
            "expected": {"status": "policy_rejected"},
            "provenance": {},
            "oracle": {"kind": "canary_exposure"},
        }

        record = harness.run_case(
            case, "prototype", "sha256:example", harness.Settings(), "suite"
        )

        command = exchange.call_args.args[0]
        self.assertIn("sandbox.evaluation.bootstrap", command)
        self.assertTrue(
            any(
                value.startswith("CS263_EVALUATION_CANARY=")
                for value in command
            )
        )
        self.assertFalse(record["attack_oracle"]["attack_success"])
        self.assertEqual(record["trial"], {"index": 1, "count": 1})


if __name__ == "__main__":
    unittest.main()
