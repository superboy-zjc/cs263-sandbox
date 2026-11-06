"""Execute one request inside the disposable evaluation container."""

import importlib.metadata
import json
import os
from pathlib import Path
import platform
import resource
import sys
import time


MAX_REQUEST_BYTES = 65_536
MAX_RESPONSE_BYTES = 131_072


def execute_request(request: dict) -> dict:
    """Run a validated request and attach worker measurements.

    This entry point requires the Docker worker environment. The environment
    marker prevents accidental local execution; it is not an isolation boundary.
    """
    if (
        os.environ.get("CS263_ISOLATED_WORKER") != "1"
        or not Path("/.dockerenv").exists()
    ):
        raise ValueError("Use the container-based benchmark command.")
    if type(request) is not dict:
        raise ValueError("The request must be a JSON object.")
    executor = request.get("executor")
    if executor not in {"prototype", "reference"}:
        raise ValueError("Unknown executor.")
    code = request.get("code")
    if type(code) is not str:
        raise ValueError("The request code must be a string.")

    started = time.monotonic()
    from sandbox.interpreter import Limits

    overrides = request.get("limits", {})
    if type(overrides) is not dict:
        raise ValueError("Limits must be a JSON object.")
    valid_names = Limits.__dataclass_fields__
    if any(name not in valid_names for name in overrides):
        raise ValueError("Unknown execution limit.")
    if any(type(value) is not int or value < 1 for value in overrides.values()):
        raise ValueError("Execution limits must be positive integers.")
    limits = Limits(**overrides)
    if executor == "prototype":
        from sandbox.interpreter import run

        result = run(code, limits=limits)
    else:
        from sandbox.evaluation.reference import run

        result = run(code, limits=vars(limits))
    result["effective_limits"] = {
        "prototype_interpreter": vars(limits)
        if executor == "prototype"
        else None,
        "reference_result_conversion": (
            {
                key: getattr(limits, key)
                for key in (
                    "max_output_chars",
                    "max_collection_items",
                    "max_int_bits",
                )
            }
            if executor == "reference"
            else None
        ),
    }
    result["worker_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    result["peak_memory_kib"] = resource.getrusage(
        resource.RUSAGE_SELF
    ).ru_maxrss
    result["runtime"] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packages": {
            distribution.metadata["Name"]: distribution.version
            for distribution in importlib.metadata.distributions()
        },
    }
    return result


def main() -> int:
    """Read one bounded JSON request and write one JSON response."""
    try:
        payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(payload) > MAX_REQUEST_BYTES:
            raise ValueError("Worker request exceeds the protocol limit.")
        result = execute_request(json.loads(payload))
        chunks = []
        encoded_size = 0
        for chunk in json.JSONEncoder(allow_nan=False).iterencode(result):
            encoded_size += len(chunk.encode("utf-8"))
            if encoded_size > MAX_RESPONSE_BYTES - 1:
                result["status"] = "output_error"
                result["value"] = None
                result["stdout"] = ""
                result["events"] = []
                result["error"] = "Worker response exceeds the protocol limit."
                response = json.dumps(result, allow_nan=False)
                break
            chunks.append(chunk)
        else:
            response = "".join(chunks)
    except Exception as error:
        response = json.dumps(
            {
                "status": "infrastructure_error",
                "value": None,
                "stdout": "",
                "steps": None,
                "events": [],
                "error": f"{type(error).__name__}: {str(error)[:2000]}",
            }
        )
    sys.stdout.write(response + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
