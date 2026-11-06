"""Adapter for an unchanged, pinned smolagents installation inside a worker.

This adapter does not sandbox code. The external controller must provide the
process, network, filesystem, wall-time, and memory boundary. Its result checks
constrain the measurement protocol after execution, not upstream side effects.
"""

import hashlib
import importlib
from importlib import metadata
import math
from pathlib import Path
import time
from typing import Any


REFERENCE_COMMIT = "96f33faaf028479119ec8d34507b47694cf14e34"
REFERENCE_VERSION = "1.27.0.dev0"
REFERENCE_EXECUTOR_SHA256 = (
    "41859e622bae8ad85ed861b7abef12b02f9106133a273c2f4d8a1e37a743d1ca"
)
_MAX_RESULT_DEPTH = 32
_MAX_RESULT_NODES = 10_000
_MAX_RESULT_JSON_BYTES = 65_536


class OutputValidationError(ValueError):
    """The executed program returned data outside the measurement protocol."""


def _load_executor() -> tuple[Any, type]:
    """Verify source provenance, then import the normal upstream package."""
    distribution = metadata.distribution("smolagents")
    if distribution.version != REFERENCE_VERSION:
        raise RuntimeError(
            "Installed smolagents version does not match the pin."
        )
    executor_path = Path(
        distribution.locate_file("smolagents/local_python_executor.py")
    )
    executor_sha256 = hashlib.sha256(executor_path.read_bytes()).hexdigest()
    if executor_sha256 != REFERENCE_EXECUTOR_SHA256:
        raise RuntimeError(
            "Installed upstream executor does not match the pin."
        )
    module = importlib.import_module("smolagents.local_python_executor")
    if Path(module.__file__).resolve() != executor_path.resolve():
        raise RuntimeError("Imported upstream executor has an unexpected path.")
    return module.LocalPythonExecutor, module.PrintContainer


def _positive_limit(limits: dict, name: str, default: int) -> int:
    """Read one positive integer limit without accepting bool as an integer."""
    value = limits.get(name, default)
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer.")
    return value


def _plain_result(value: Any, limits: dict) -> Any:
    """Copy exact plain-data types into a bounded JSON-compatible value.

    Tuple results become JSON arrays. Arbitrary objects, subclasses, cycles,
    non-string dictionary keys, and non-finite floats are rejected. No repr or
    user-defined iteration/conversion method is invoked.
    """
    max_items = _positive_limit(limits, "max_collection_items", 1000)
    max_int_bits = _positive_limit(limits, "max_int_bits", 4096)
    max_text_chars = _positive_limit(limits, "max_output_chars", 4096)
    remaining_nodes = _MAX_RESULT_NODES
    remaining_json_bytes = _MAX_RESULT_JSON_BYTES
    active_containers: set[int] = set()

    def charge(byte_count: int) -> None:
        nonlocal remaining_json_bytes
        remaining_json_bytes -= byte_count
        if remaining_json_bytes < 0:
            raise OutputValidationError("Result exceeds the JSON size budget.")

    def convert(item: Any, depth: int) -> Any:
        nonlocal remaining_nodes
        remaining_nodes -= 1
        if remaining_nodes < 0 or depth > _MAX_RESULT_DEPTH:
            raise OutputValidationError(
                "Result exceeds the node or depth limit."
            )
        item_type = type(item)
        if item is None or item_type is bool:
            charge(5)
            return item
        if item_type is int:
            bit_count = int.bit_length(item)
            if bit_count > max_int_bits:
                raise OutputValidationError(
                    "Result integer exceeds max_int_bits."
                )
            charge((bit_count * 30103 // 100000) + 3)
            return item
        if item_type is float:
            if not math.isfinite(item):
                raise OutputValidationError(
                    "Result contains a non-finite float."
                )
            charge(32)
            return item
        if item_type is str:
            if len(item) > max_text_chars:
                raise OutputValidationError(
                    "Result string exceeds max_output_chars."
                )
            # JSON ASCII escaping consumes at most 12 bytes per code point
            # (a supplementary character becomes a surrogate pair).
            charge(12 * len(item) + 2)
            return item
        if item_type not in (list, tuple, dict):
            raise OutputValidationError(
                "Result contains a non-plain data type."
            )
        if len(item) > max_items:
            raise OutputValidationError(
                "Result container exceeds max_collection_items."
            )
        item_id = id(item)
        if item_id in active_containers:
            raise OutputValidationError("Result contains a container cycle.")
        active_containers.add(item_id)
        charge(2 + 2 * len(item))
        try:
            if item_type is dict:
                converted = {}
                for key, child in dict.items(item):
                    if type(key) is not str:
                        raise OutputValidationError(
                            "Result dictionary keys must be strings."
                        )
                    converted_key = convert(key, depth + 1)
                    converted[converted_key] = convert(child, depth + 1)
                return converted
            return [convert(child, depth + 1) for child in item]
        finally:
            active_containers.remove(item_id)

    return convert(value, 0)


def _error_text(error: BaseException) -> str:
    """Describe an exception without invoking its potentially custom __str__."""
    error_type = type.__getattribute__(type(error), "__name__")
    arguments = BaseException.args.__get__(error)
    message = arguments[0] if arguments and type(arguments[0]) is str else ""
    return f"{error_type}: {message}"[:2000]


def _captured_stdout(
    state: dict, container_type: type, dictionary_descriptor: Any, limit: int
) -> tuple[str, bool]:
    """Read only the original print container's exact string field.

    The instance-dictionary descriptor is captured before executing guest code.
    No guest attribute lookup or string conversion is required on this path.
    """
    container = dict.get(state, "_print_outputs")
    if type(container) is not container_type:
        return "", False
    fields = dictionary_descriptor.__get__(container, container_type)
    if type(fields) is not dict:
        return "", False
    text = dict.get(fields, "value")
    if type(text) is not str:
        return "", False
    return text[:limit], True


def run(code: str, *, limits: dict | None = None) -> dict:
    """Execute one case through a fresh upstream executor in an isolated worker.

    Args:
        code: Submitted Python source; never pass hostile code on the host.
        limits: Shared protocol limits. These bound result conversion only;
            upstream execution retains its own policy and operation counter.

    Returns:
        A measurement result. An ``ok`` result means execution and conversion
        completed; it makes no claim about attack success or sandbox security.
    """
    started = time.perf_counter()
    events = []
    stdout = ""

    def result(
        status: str, value: Any = None, error: str | None = None
    ) -> dict:
        return {
            "status": status,
            "value": value,
            "stdout": stdout,
            "steps": None,
            "events": events,
            "error": error,
            "elapsed_ms": (time.perf_counter() - started) * 1000,
            "reference_commit": REFERENCE_COMMIT,
        }

    try:
        if type(code) is not str:
            raise ValueError("code must be a string.")
        if limits is not None and type(limits) is not dict:
            raise ValueError("limits must be a dictionary.")
        resolved_limits = {} if limits is None else limits
        max_output_chars = _positive_limit(
            resolved_limits, "max_output_chars", 4096
        )
        # Validate conversion limits before upstream execution begins.
        _positive_limit(resolved_limits, "max_collection_items", 1000)
        _positive_limit(resolved_limits, "max_int_bits", 4096)
        executor_type, print_container_type = _load_executor()
        print_dictionary_descriptor = type.__getattribute__(
            print_container_type, "__dict__"
        )["__dict__"]
        executor = executor_type(
            additional_authorized_imports=[],
            max_print_outputs_length=max_output_chars,
            timeout_seconds=None,
        )
        executor.send_tools({})
        captured_state = object.__getattribute__(executor, "state")
        if type(captured_state) is not dict:
            raise RuntimeError("Upstream state is not a plain dictionary.")
    except Exception as error:
        return result("infrastructure_error", error=_error_text(error))

    events.append({"kind": "reference_adapter", "phase": "execute"})
    try:
        output = executor(code)
    except BaseException as error:
        stdout, stdout_available = _captured_stdout(
            captured_state,
            print_container_type,
            print_dictionary_descriptor,
            max_output_chars,
        )
        events.append(
            {
                "kind": "reference_adapter",
                "phase": "execution_error",
                "captured_stdout_available": stdout_available,
            }
        )
        return result("program_error", error=_error_text(error))

    try:
        logs = object.__getattribute__(output, "logs")
        if type(logs) is not str:
            raise OutputValidationError(
                "Captured output is not a plain string."
            )
        stdout = logs[:max_output_chars]
        value = _plain_result(
            object.__getattribute__(output, "output"), resolved_limits
        )
    except Exception as error:
        events.append({"kind": "reference_adapter", "phase": "output_error"})
        return result("output_error", error=_error_text(error))

    events.append({"kind": "reference_adapter", "phase": "validated_output"})
    return result("ok", value=value)
