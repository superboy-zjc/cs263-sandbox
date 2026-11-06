# Interpreter-based Python Sandbox for AI-Generated Code Safety

## Summary

As AI agents increasingly generate and execute code to accomplish everyday tasks, their security implications have become a growing concern. In particular, agents may be hijacked by malicious instructions encountered during task execution, potentially leading to unintended or harmful code execution. While virtualization and containerization provide robust isolation for executing LLM-generated code, their resource overhead makes them less suitable for resource-constrained environments, such as IoT devices. This creates a pressing need for lightweight, efficient, and secure sandboxing mechanisms.

In this project, we focus on **language-based sandboxing**, which enforces security restrictions at the programming-language level without relying on heavyweight system-level isolation. We will first survey existing sandboxing implementations and investigate an **interpreter-based sandbox** that introduces an additional layer of dynamic interpretation over Python's Abstract Syntax Tree (AST). By combining static analysis with runtime enforcement, our approach aims to detect and prevent malicious behaviors during Python code execution.

Finally, we will evaluate the proposed framework in terms of both security and performance, using a dataset of sandbox-escape techniques collected from published security research and Capture-the-Flag (CTF) competitions.

##  Steps

- **Survey sandboxing approaches:** Compare virtual machines, Docker containers, process-based isolation, and language-based sandboxing to explain the value of language-level controls.
- **Review existing Python sandboxes:** Examine their implementation strategies, including syntax restrictions, AST interpretation, and runtime checks, and identify their strengths and limitations.
- **Develop an interpreter-based prototype:** Execute a supported Python subset through a custom AST interpreter. Enforce whitelist and blacklist policies on actual call targets, attribute access, imports, and returned values as execution proceeds, including indirect access through variables. Capture results, apply execution limits, and record rejected operations with their reasons.
- **Evaluate security and efficiency:** Collect relevant cases from published datasets and CTF communities, then measure attack success, correctness on benign programs, and execution overhead.

## First experiment

A minimal AST interpreter and 15 project-authored regression cases are now
available. The initial subset supports basic data, arithmetic, assignments,
conditions, loops, simple functions, and a few reviewed builtins. See the
[execution policy](docs/policy.md) for supported behavior and limits. These are
smoke tests, not a research or CTF attack benchmark.

With Python 3.11 or later and Docker running, execute from the repository root:

```sh
docker build -f containers/Dockerfile -t cs263-sandbox:baseline .
python3 -m sandbox benchmark
```

The command compares the prototype with the pinned reference executor, using a
fresh container for every case. Containers have no network, no host mounts, a
read-only filesystem, an unprivileged user, and external CPU, memory, and time
limits. The container provides containment for the experiment; it is separate
from the prototype's language-level checks.

Results are written to `results/*.jsonl`. Each record contains the actual result,
expected result, rejection reasons, available execution events, timing, peak
worker memory, source and image fingerprints, runtime versions, and cleanup
evidence. Interpreter limits and outer-container terminations are reported
separately. An expectation mismatch is a regression observation, not a confirmed
sandbox escape. See [evaluation notes](docs/evaluation.md) for interpretation.

To run one case or one executor:

```sh
python3 -m sandbox benchmark --case user_function_return
python3 -m sandbox benchmark --executor prototype
```

Run the tests in a virtual environment. Docker integration is skipped unless
explicitly enabled:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

After building the image, check the real container deadline and cleanup:

```sh
CS263_DOCKER_TESTS=1 .venv/bin/python -m pytest tests/test_container.py -v
```

## Repository layout

`sandbox` is the single Python package. The interpreter uses the original
`Environment` and shared error types, with evaluation tools kept in a subpackage:

- `sandbox/interpreter.py`: dynamic AST execution and runtime policy checks.
- `sandbox/policy.py`: supported syntax, static validation, and resource limits.
- `sandbox/environment.py` and `sandbox/errors.py`: variable scopes and errors.
- `sandbox/evaluation/`: benchmark command, Docker controller, worker, and pinned
  reference adapter.
- `benchmarks/`, `tests/`, and `docs/`: regression cases, tests, and policy and
  evaluation notes.

The original stateful interface remains available:

```python
import ast
from sandbox.interpreter import Interpreter

interpreter = Interpreter()
interpreter.eval_node(ast.parse("x = 10\ny = x + 5"))
assert interpreter.environment.get("y") == 15
```

`sandbox.interpreter.run(code)` uses the same interpreter with fresh state and
returns the value, captured output, and execution diagnostics as a dictionary.
