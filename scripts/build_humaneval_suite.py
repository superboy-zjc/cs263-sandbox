"""Build a deterministic benign compatibility suite from HumanEval.

The upstream programs are data and are never executed by this script.  The
generated cases must still be run through the container-based benchmark.
"""

import argparse
import ast
import copy
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any


UPSTREAM_COMMIT = "b9453e8f1865df0a0057a1383767caa400acfbcf"
DATASET_SHA256 = (
    "b796127e635a67f93fb35c04f4cb03cf06f38c8072ee7cee8833d7bee06979ef"
)
DATASET_URL = (
    "https://raw.githubusercontent.com/openai/human-eval/"
    f"{UPSTREAM_COMMIT}/data/HumanEval.jsonl.gz"
)
SELECTION_SEED = "cs263-humaneval-compatibility-v1"
UPSTREAM_TASK_COUNT = 164
SAMPLE_SIZE = 30
DEVELOPMENT_SIZE = 20
MAX_COMPRESSED_BYTES = 1_048_576
MAX_UNCOMPRESSED_BYTES = 8_388_608


class _Normalization(ast.NodeTransformer):
    """Remove type-only syntax without changing runtime solution operations."""

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.AST | None:
        if node.module == "typing":
            return None
        return self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> ast.AST | None:
        retained = [alias for alias in node.names if alias.name != "typing"]
        if not retained:
            return None
        node.names = retained
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node = self.generic_visit(node)
        node.returns = None
        for argument in (
            node.args.posonlyargs
            + node.args.args
            + node.args.kwonlyargs
        ):
            argument.annotation = None
        if node.args.vararg is not None:
            node.args.vararg.annotation = None
        if node.args.kwarg is not None:
            node.args.kwarg.annotation = None
        return node


def _load_records(path: Path) -> list[dict[str, Any]]:
    """Load the one pinned upstream artifact with explicit size bounds."""
    payload = path.read_bytes()
    if len(payload) > MAX_COMPRESSED_BYTES:
        raise ValueError(
            "Compressed HumanEval artifact exceeds the size limit."
        )
    digest = hashlib.sha256(payload).hexdigest()
    if digest != DATASET_SHA256:
        raise ValueError(
            "HumanEval artifact SHA-256 does not match the pinned dataset."
        )
    uncompressed = gzip.decompress(payload)
    if len(uncompressed) > MAX_UNCOMPRESSED_BYTES:
        raise ValueError("HumanEval artifact exceeds the expanded size limit.")

    records = []
    for line_number, line in enumerate(uncompressed.splitlines(), start=1):
        try:
            record = json.loads(line)
        except (UnicodeError, ValueError, RecursionError) as error:
            raise ValueError(
                f"HumanEval record {line_number} is invalid JSON."
            ) from error
        required = ("task_id", "prompt", "canonical_solution", "test")
        if type(record) is not dict or any(
            type(record.get(name)) is not str for name in required
        ):
            raise ValueError(
                f"HumanEval record {line_number} has an invalid schema."
            )
        records.append(record)
    if len(records) != UPSTREAM_TASK_COUNT:
        raise ValueError("HumanEval task count does not match the pin.")
    if len({record["task_id"] for record in records}) != len(records):
        raise ValueError("HumanEval task identifiers are not unique.")
    return records


def _selection_key(record: dict[str, Any]) -> str:
    material = f"{SELECTION_SEED}\0{record['task_id']}".encode()
    return hashlib.sha256(material).hexdigest()


def _json_value(value: Any) -> Any:
    """Convert literal expected values to the worker's plain JSON model."""
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float and math.isfinite(value):
        return value
    if value_type in (list, tuple):
        return [_json_value(item) for item in value]
    if value_type is dict and all(type(key) is str for key in value):
        return {key: _json_value(item) for key, item in value.items()}
    raise ValueError("Expected literal is outside the plain JSON result model.")


def _literal_candidate_call(node: ast.AST) -> ast.Call | None:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "candidate"
        and all(not isinstance(argument, ast.Starred) for argument in node.args)
        and all(keyword.arg is not None for keyword in node.keywords)
    ):
        return None
    try:
        for argument in node.args:
            ast.literal_eval(argument)
        for keyword in node.keywords:
            ast.literal_eval(keyword.value)
    except (TypeError, ValueError):
        return None
    return node


def _extract_check(
    assertion: ast.Assert,
) -> tuple[ast.Call, Any] | None:
    """Extract a candidate call with an exact literal or Boolean result."""
    expression = assertion.test
    if isinstance(expression, ast.Compare) and len(expression.ops) == 1:
        if not isinstance(expression.ops[0], (ast.Eq, ast.Is)):
            return None
        if len(expression.comparators) != 1:
            return None
        call = _literal_candidate_call(expression.left)
        if call is None:
            return None
        try:
            expected = _json_value(ast.literal_eval(expression.comparators[0]))
        except (TypeError, ValueError):
            return None
        return call, expected
    call = _literal_candidate_call(expression)
    if call is not None:
        return call, True
    if isinstance(expression, ast.UnaryOp) and isinstance(
        expression.op, ast.Not
    ):
        call = _literal_candidate_call(expression.operand)
        if call is not None:
            return call, False
    return None


def _normalized_program(record: dict[str, Any]) -> ast.Module:
    source = record["prompt"] + record["canonical_solution"]
    tree = ast.parse(source)
    normalized = _Normalization().visit(tree)
    if not isinstance(normalized, ast.Module):
        raise ValueError("Normalized HumanEval program is not a module.")
    ast.fix_missing_locations(normalized)
    return normalized


def _case(record: dict[str, Any], rank: int) -> dict[str, Any]:
    entry_point = record.get("entry_point")
    if type(entry_point) is not str or not entry_point:
        raise ValueError(f"{record['task_id']} has no entry point.")

    calls = []
    expected_values = []
    assertion_lines = []
    for node in ast.walk(ast.parse(record["test"])):
        if not isinstance(node, ast.Assert):
            continue
        extracted = _extract_check(node)
        if extracted is None:
            continue
        call, expected = extracted
        call = copy.deepcopy(call)
        call.func = ast.Name(id=entry_point, ctx=ast.Load())
        calls.append(call)
        expected_values.append(expected)
        assertion_lines.append(node.lineno)
    if not calls:
        raise ValueError(
            f"{record['task_id']} has no statically extractable exact checks."
        )

    program = _normalized_program(record)
    program.body.append(ast.Expr(value=ast.List(elts=calls, ctx=ast.Load())))
    ast.fix_missing_locations(program)
    code = ast.unparse(program) + "\n"
    task_number = int(record["task_id"].split("/", maxsplit=1)[1])
    slug = re.sub(r"[^a-z0-9]+", "_", entry_point.lower()).strip("_")
    partition = "development" if rank <= DEVELOPMENT_SIZE else "heldout"
    return {
        "id": f"humaneval_{task_number:03d}_{slug}",
        "category": "compatibility",
        "partition": partition,
        "description": (
            f"Run the canonical {record['task_id']} solution against "
            f"{len(calls)} exact upstream checks."
        ),
        "code": code,
        "expected": {
            "status": "ok",
            "value": expected_values,
            "stdout": "",
        },
        "provenance": {
            "source_title": "HumanEval: Hand-Written Evaluation Set",
            "source_url": DATASET_URL,
            "source_locator": record["task_id"],
            "dataset_sha256": DATASET_SHA256,
            "upstream_commit": UPSTREAM_COMMIT,
            "license": "MIT",
            "selection_rank": rank,
            "selection_key": _selection_key(record),
            "test_assertion_lines": assertion_lines,
            "adaptation": (
                "Removed only typing imports and function annotations; "
                "retained runtime operations; replaced exact literal/Boolean "
                "assertions with one final list of canonical function calls."
            ),
        },
    }


def build_suite(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Select before execution and return a deterministic suite document."""
    selected = sorted(records, key=_selection_key)[:SAMPLE_SIZE]
    cases = [_case(record, rank) for rank, record in enumerate(selected, 1)]
    return {
        "schema_version": 1,
        "suite": {
            "name": "HumanEval deterministic benign compatibility sample",
            "dataset_url": DATASET_URL,
            "dataset_sha256": DATASET_SHA256,
            "upstream_commit": UPSTREAM_COMMIT,
            "upstream_task_count": UPSTREAM_TASK_COUNT,
            "selection_seed": SELECTION_SEED,
            "selection_rule": "Sort all task IDs by SHA-256(seed + NUL + ID).",
            "sample_size": SAMPLE_SIZE,
            "development_size": DEVELOPMENT_SIZE,
            "heldout_size": SAMPLE_SIZE - DEVELOPMENT_SIZE,
        },
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/humaneval.json"),
    )
    args = parser.parse_args()
    suite = build_suite(_load_records(args.dataset))
    encoded = json.dumps(
        suite, allow_nan=False, ensure_ascii=False, indent=2
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded + "\n", encoding="utf-8")
    print(f"Wrote {len(suite['cases'])} cases to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
