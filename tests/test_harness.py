"""Tests for external control and result classification, without guest code."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cs263_sandbox import harness


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


class ContainerBoundaryTest(unittest.TestCase):
    """Verify isolation arguments and cleanup on timeout without Docker."""

    @mock.patch("cs263_sandbox.harness.subprocess.run")
    @mock.patch("cs263_sandbox.harness._inspect_container")
    @mock.patch("cs263_sandbox.harness._exchange")
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

    @mock.patch("cs263_sandbox.harness.subprocess.run")
    @mock.patch("cs263_sandbox.harness._inspect_container")
    @mock.patch("cs263_sandbox.harness._exchange")
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
            record["controller_errors"], ["remove: TimeoutExpired"]
        )

    @mock.patch("cs263_sandbox.harness.subprocess.run")
    @mock.patch("cs263_sandbox.harness._inspect_container")
    @mock.patch("cs263_sandbox.harness._exchange")
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


if __name__ == "__main__":
    unittest.main()
