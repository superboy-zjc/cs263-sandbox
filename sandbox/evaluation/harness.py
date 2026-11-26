"""Run each executor and case in its own constrained Docker container."""

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import time
import uuid

from sandbox.evaluation.bootstrap import CANARY_ENVIRONMENT_VARIABLE


REFERENCE_COMMIT = "96f33faaf028479119ec8d34507b47694cf14e34"
MAX_RESPONSE_BYTES = 131_072
MAX_STDERR_BYTES = 16_384
CLEANUP_ATTEMPTS = 3
INSPECTION_ATTEMPTS = 3
EXECUTOR_STATUSES = frozenset(
    {
        "ok",
        "unsupported",
        "policy_rejected",
        "resource_limit",
        "program_error",
        "internal_error",
        "output_error",
        "infrastructure_error",
    }
)
CASE_CATEGORIES = frozenset(
    {
        "attack",
        "benign",
        "compatibility",
        "correctness",
        "policy",
        "resource",
    }
)
COMPATIBILITY_PARTITIONS = frozenset({"development", "heldout"})
ATTACK_ORACLE_KINDS = frozenset(
    {"canary_exposure", "outer_termination"}
)
OUTER_TERMINATION_STATUSES = frozenset(
    {"crashed", "oom_killed", "protocol_limit", "wall_timeout"}
)


def _reject_constant(value: str):
    raise ValueError(f"Non-finite JSON constant: {value}")


@dataclass(frozen=True)
class Settings:
    """Container limits, independent of interpreter policy."""

    image: str = "cs263-sandbox:baseline"
    wall_seconds: float = 5.0
    memory_mib: int = 256

    def __post_init__(self):
        if not math.isfinite(self.wall_seconds) or self.wall_seconds <= 0:
            raise ValueError("Wall time must be finite and positive.")
        if type(self.memory_mib) is not int or self.memory_mib < 32:
            raise ValueError("Container memory must be at least 32 MiB.")


def load_cases(path: Path) -> tuple[list[dict], str]:
    """Load a small, explicit suite without executing any submitted code."""
    with path.open("rb") as stream:
        payload = stream.read(1_048_577)
    if len(payload) > 1_048_576:
        raise ValueError("Case file exceeds the 1 MiB limit.")
    try:
        suite = json.loads(payload, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as error:
        raise ValueError("Case file is not valid bounded JSON.") from error
    if (
        type(suite) is not dict
        or type(suite.get("schema_version")) is not int
        or suite["schema_version"] != 1
    ):
        raise ValueError("Unsupported case-file schema.")
    cases = suite.get("cases")
    if type(cases) is not list or not cases or len(cases) > 1000:
        raise ValueError("Suite must contain between 1 and 1,000 cases.")
    identifiers = set()
    for case in cases:
        if type(case) is not dict:
            raise ValueError("Each case must be an object.")
        identifier = case.get("id")
        if type(identifier) is not str or not identifier:
            raise ValueError("Each case needs a nonempty identifier.")
        if identifier in identifiers:
            raise ValueError(f"Duplicate case identifier: {identifier}")
        identifiers.add(identifier)
        if (
            type(case.get("category")) is not str
            or case["category"] not in CASE_CATEGORIES
        ):
            raise ValueError(f"Unknown category for {identifier}.")
        if type(case.get("code")) is not str:
            raise ValueError(f"Code must be a string for {identifier}.")
        if len(case["code"].encode("utf-8")) > 32_768:
            raise ValueError(f"Source exceeds 32 KiB for {identifier}.")
        expected = case.get("expected")
        if (
            type(expected) is not dict
            or type(expected.get("status")) is not str
            or expected.get("status") not in EXECUTOR_STATUSES
        ):
            raise ValueError(f"Missing or invalid expectation: {identifier}")
        if case["category"] == "attack":
            _validate_attack_case(case)
        if case["category"] == "compatibility":
            _validate_compatibility_case(case)
    return cases, hashlib.sha256(payload).hexdigest()


def _validate_attack_case(case: dict) -> None:
    """Require auditable provenance and an independent success oracle."""
    identifier = case["id"]
    for field in ("description", "attack_goal"):
        if type(case.get(field)) is not str or not case[field].strip():
            raise ValueError(f"Attack case {identifier} needs {field}.")

    provenance = case.get("provenance")
    required_provenance = (
        "source_title",
        "source_url",
        "source_locator",
        "adaptation",
    )
    if type(provenance) is not dict or any(
        type(provenance.get(field)) is not str
        or not provenance[field].strip()
        for field in required_provenance
    ):
        raise ValueError(
            f"Attack case {identifier} needs complete provenance."
        )
    if re.fullmatch(r"https://[^\s]+", provenance["source_url"]) is None:
        raise ValueError(f"Attack case {identifier} needs an HTTPS source URL.")

    oracle = case.get("oracle")
    if (
        type(oracle) is not dict
        or type(oracle.get("kind")) is not str
        or oracle["kind"] not in ATTACK_ORACLE_KINDS
    ):
        raise ValueError(f"Attack case {identifier} needs a valid oracle.")
    if oracle["kind"] == "outer_termination":
        statuses = oracle.get("success_statuses")
        if (
            type(statuses) is not list
            or not statuses
            or any(
                type(status) is not str
                or status not in OUTER_TERMINATION_STATUSES
                for status in statuses
            )
        ):
            raise ValueError(
                f"Attack case {identifier} has invalid termination statuses."
            )


def _validate_compatibility_case(case: dict) -> None:
    """Require enough metadata to reproduce an external compatibility case."""
    identifier = case["id"]
    if case.get("partition") not in COMPATIBILITY_PARTITIONS:
        raise ValueError(
            f"Compatibility case {identifier} needs a valid partition."
        )
    if case["expected"].get("status") != "ok":
        raise ValueError(
            f"Compatibility case {identifier} must target successful output."
        )
    if type(case.get("description")) is not str or not case[
        "description"
    ].strip():
        raise ValueError(
            f"Compatibility case {identifier} needs a description."
        )

    provenance = case.get("provenance")
    required_fields = (
        "source_title",
        "source_url",
        "source_locator",
        "dataset_sha256",
        "adaptation",
    )
    if type(provenance) is not dict or any(
        type(provenance.get(field)) is not str
        or not provenance[field].strip()
        for field in required_fields
    ):
        raise ValueError(
            f"Compatibility case {identifier} needs complete provenance."
        )
    if re.fullmatch(r"https://[^\s]+", provenance["source_url"]) is None:
        raise ValueError(
            f"Compatibility case {identifier} needs an HTTPS source URL."
        )
    if re.fullmatch(r"[0-9a-f]{64}", provenance["dataset_sha256"]) is None:
        raise ValueError(
            f"Compatibility case {identifier} needs a dataset SHA-256."
        )


def resolve_image(image: str) -> str:
    """Resolve the image tag once so all cases use the same local image."""
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Docker is unavailable.") from error
    image_id = completed.stdout.strip()
    if completed.returncode or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", image_id
    ):
        raise RuntimeError(
            "Evaluation image unavailable. Build containers/Dockerfile first."
        )
    return image_id


def _exchange(
    command: list[str], payload: bytes, timeout: float
) -> tuple[int | None, bytes, bytes, str | None]:
    """Exchange bounded pipe data while maintaining a wall-clock deadline."""
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    reason = None
    position = 0
    try:
        with selectors.DefaultSelector() as selector:
            streams = (
                (process.stdin, selectors.EVENT_WRITE, "stdin"),
                (process.stdout, selectors.EVENT_READ, "stdout"),
                (process.stderr, selectors.EVENT_READ, "stderr"),
            )
            for stream, event, name in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "wall_timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    stream = key.fileobj
                    if key.data == "stdin":
                        try:
                            position += os.write(
                                stream.fileno(),
                                payload[position : position + 4096],
                            )
                        except BrokenPipeError:
                            position = len(payload)
                        if position == len(payload):
                            selector.unregister(stream)
                            stream.close()
                        continue
                    chunk = os.read(stream.fileno(), 16_384)
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    buffer = buffers[key.data]
                    limit = (
                        MAX_RESPONSE_BYTES
                        if key.data == "stdout"
                        else MAX_STDERR_BYTES
                    )
                    remaining_capacity = limit - len(buffer)
                    buffer.extend(chunk[:remaining_capacity])
                    if len(chunk) > remaining_capacity:
                        reason = "protocol_limit"
                if reason:
                    break
            if reason is None:
                try:
                    process.wait(
                        timeout=max(0.001, deadline - time.monotonic())
                    )
                except subprocess.TimeoutExpired:
                    reason = "wall_timeout"
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:
                stream.close()
    return (
        process.returncode,
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
        reason,
    )


def _inspect_container(name: str) -> dict:
    """Collect termination evidence from Docker, independently of the worker."""
    completed = subprocess.run(
        ["docker", "inspect", "--format", "{{json .State}}", name],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError("Docker could not inspect the evaluation container.")
    try:
        state = json.loads(completed.stdout)
    except (ValueError, TypeError):
        raise RuntimeError("Docker returned invalid container state.") from None
    if type(state) is not dict:
        raise RuntimeError("Docker returned invalid container state.")
    return {
        "oom_killed": state.get("OOMKilled"),
        "exit_code": state.get("ExitCode"),
        "running": state.get("Running"),
    }


def _inspect_container_with_retries(
    name: str,
) -> tuple[dict, int, list[dict]]:
    """Inspect one exact container with bounded transient retries."""
    diagnostics = []
    for attempt in range(1, INSPECTION_ATTEMPTS + 1):
        try:
            evidence = _inspect_container(name)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            diagnostics.append(
                {"attempt": attempt, "error": type(error).__name__}
            )
        else:
            return evidence, attempt, diagnostics
        if attempt < INSPECTION_ATTEMPTS:
            time.sleep(0.05 * attempt)
    return {}, INSPECTION_ATTEMPTS, diagnostics


def _remove_container(name: str) -> tuple[bool, int, list[dict]]:
    """Remove one exact evaluation container with bounded transient retries."""
    diagnostics = []
    for attempt in range(1, CLEANUP_ATTEMPTS + 1):
        try:
            completed = subprocess.run(
                ["docker", "rm", "--force", name],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            diagnostics.append(
                {"attempt": attempt, "error": type(error).__name__}
            )
        else:
            if completed.returncode == 0:
                return True, attempt, diagnostics
            error_text = completed.stderr
            if isinstance(error_text, bytes):
                error_text = error_text.decode(errors="replace")
            diagnostics.append(
                {
                    "attempt": attempt,
                    "returncode": completed.returncode,
                    "error": (error_text or "Docker returned a failure.")[
                        :500
                    ],
                }
            )
        if attempt < CLEANUP_ATTEMPTS:
            time.sleep(0.05 * attempt)
    return False, CLEANUP_ATTEMPTS, diagnostics


def _failure(status: str, error: str) -> dict:
    return {
        "status": status,
        "value": None,
        "stdout": "",
        "steps": None,
        "events": [],
        "error": error,
    }


def matches_expected(observed: dict, expected: dict) -> bool:
    """Compare explicit expectations without assigning security scores."""
    if observed.get("status") != expected["status"]:
        return False
    for key in ("value", "stdout"):
        if key in expected:
            if key not in observed:
                return False
            if json.dumps(
                observed.get(key), sort_keys=True, allow_nan=False
            ) != (json.dumps(expected[key], sort_keys=True, allow_nan=False)):
                return False
    return True


def evaluate_attack_oracle(
    case: dict,
    observed: dict,
    worker_stdout: bytes,
    worker_stderr: bytes,
    canary: str | None,
) -> dict | None:
    """Evaluate attack success without trusting an executor's status label."""
    oracle = case.get("oracle")
    if oracle is None:
        return None
    kind = oracle["kind"]
    if kind == "canary_exposure":
        if canary is None:
            raise ValueError("Canary oracle requires a per-run canary.")
        marker = canary.encode("ascii")
        channels = []
        if marker in worker_stdout:
            channels.append("worker_stdout")
        if marker in worker_stderr:
            channels.append("worker_stderr")
        return {
            "kind": kind,
            "attack_success": bool(channels),
            "evidence_channels": channels,
        }
    if kind == "outer_termination":
        status = observed.get("status")
        return {
            "kind": kind,
            "attack_success": status in oracle["success_statuses"],
            "observed_status": status,
            "success_statuses": oracle["success_statuses"],
        }
    raise ValueError("Unknown attack oracle.")


def run_case(
    case: dict,
    executor: str,
    image_id: str,
    settings: Settings,
    suite_sha256: str,
    *,
    trial_index: int = 1,
    trial_count: int = 1,
) -> dict:
    """Run one case in fresh containment and return an auditable record."""
    if executor not in {"prototype", "reference"}:
        raise ValueError("Unknown executor.")
    if (
        type(trial_index) is not int
        or type(trial_count) is not int
        or trial_count < 1
        or trial_index < 1
        or trial_index > trial_count
    ):
        raise ValueError("Invalid trial index or count.")
    name = f"cs263-eval-{uuid.uuid4().hex}"
    request = json.dumps({"executor": executor, "code": case["code"]}).encode()
    if len(request) > 65_536:
        raise ValueError("Case exceeds the worker protocol limit.")
    oracle = case.get("oracle")
    canary = (
        secrets.token_hex(32)
        if oracle is not None and oracle["kind"] == "canary_exposure"
        else None
    )
    command = [
        "docker",
        "run",
        "--name",
        name,
        "--interactive",
        "--init",
        "--label",
        "org.cs263-sandbox.evaluation=true",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        f"{settings.memory_mib}m",
        "--memory-swap",
        f"{settings.memory_mib}m",
        "--cpus",
        "1",
        "--user",
        "65534:65534",
        "--log-driver",
        "none",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=8m",
        "--ulimit",
        "nofile=64:64",
        "--ulimit",
        "core=0:0",
        "--env",
        "CS263_ISOLATED_WORKER=1",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
    ]
    if canary is not None:
        command.extend(
            ["--env", f"{CANARY_ENVIRONMENT_VARIABLE}={canary}"]
        )
    command.extend(
        [
            "--entrypoint",
            "python",
            image_id,
            "-m",
            (
                "sandbox.evaluation.bootstrap"
                if canary is not None
                else "sandbox.evaluation.worker"
            ),
        ]
    )
    started = time.monotonic()
    evidence = {}
    inspection_attempts = 0
    inspection_diagnostics = []
    controller_errors = []
    execution_wall_ms = None
    cleanup_ok = False
    cleanup_attempts = 0
    cleanup_diagnostics = []
    output = b""
    stderr = b""
    observed = _failure("infrastructure_error", "Controller did not complete.")
    try:
        exit_code, output, stderr, reason = _exchange(
            command, request, settings.wall_seconds
        )
        execution_wall_ms = round((time.monotonic() - started) * 1000, 3)
        if reason:
            try:
                completed = subprocess.run(
                    ["docker", "kill", name],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                controller_errors.append(f"kill: {type(error).__name__}")
            else:
                if completed.returncode:
                    controller_errors.append(
                        "kill: Docker returned "
                        f"status {completed.returncode}."
                    )
        (
            evidence,
            inspection_attempts,
            inspection_diagnostics,
        ) = _inspect_container_with_retries(name)
        if not evidence:
            controller_errors.append(
                "inspect: state unavailable after "
                f"{inspection_attempts} attempts."
            )
        if reason:
            observed = _failure(reason, "External controller stopped the run.")
        elif evidence.get("oom_killed"):
            observed = _failure(
                "oom_killed", "Container exceeded memory limit."
            )
        elif exit_code:
            status = "infrastructure_error" if exit_code == 125 else "crashed"
            observed = _failure(status, stderr.decode(errors="replace")[:2000])
        else:
            try:
                observed = json.loads(output, parse_constant=_reject_constant)
                if (
                    type(observed) is not dict
                    or type(observed.get("status")) is not str
                    or observed.get("status") not in EXECUTOR_STATUSES
                    or "value" not in observed
                    or type(observed.get("stdout")) is not str
                    or type(observed.get("events")) is not list
                    or "steps" not in observed
                    or "error" not in observed
                ):
                    raise ValueError("Invalid worker response.")
            except (ValueError, UnicodeError, RecursionError):
                observed = _failure("protocol_error", "Invalid worker JSON.")
    except (OSError, subprocess.TimeoutExpired) as error:
        controller_errors.append(f"exchange: {type(error).__name__}")
        observed = _failure("infrastructure_error", "Docker command failed.")
    finally:
        cleanup_ok, cleanup_attempts, cleanup_diagnostics = _remove_container(
            name
        )
        if not cleanup_ok:
            controller_errors.append(
                f"remove: cleanup failed after {cleanup_attempts} attempts."
            )
    attack_oracle = evaluate_attack_oracle(
        case, observed, output, stderr, canary
    )
    return {
        "schema_version": 1,
        "case_id": case["id"],
        "category": case["category"],
        "partition": case.get("partition"),
        "trial": {"index": trial_index, "count": trial_count},
        "description": case.get("description"),
        "attack_goal": case.get("attack_goal"),
        "provenance": case.get("provenance"),
        "executor": executor,
        "reference_commit": REFERENCE_COMMIT,
        "case_sha256": hashlib.sha256(case["code"].encode()).hexdigest(),
        "suite_sha256": suite_sha256,
        "image_id": image_id,
        "limits": {
            "wall_seconds": settings.wall_seconds,
            "memory_mib": settings.memory_mib,
        },
        "expected": case["expected"],
        "observed": observed,
        "matches_expected": matches_expected(observed, case["expected"]),
        "attack_oracle": attack_oracle,
        "container": evidence,
        "inspection": {
            "ok": bool(evidence),
            "attempts": inspection_attempts,
            "diagnostics": inspection_diagnostics,
        },
        "container_name": name,
        "cleanup_ok": cleanup_ok,
        "cleanup": {
            "ok": cleanup_ok,
            "attempts": cleanup_attempts,
            "diagnostics": cleanup_diagnostics,
        },
        "controller_errors": controller_errors,
        "execution_wall_ms": execution_wall_ms,
        "elapsed_wall_ms": round((time.monotonic() - started) * 1000, 3),
    }
