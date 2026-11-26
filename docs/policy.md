# Prototype execution policy

This policy defines the intended behavior of the first AST interpreter prototype
and its comparison with other executors. It is an experimental restriction policy,
not a claim that Python is safe to run inside a shared host process. The initial
cases in `benchmarks/cases.json` are small, project-authored regression checks;
they are not a published attack dataset and cannot establish an escape rate.

## Implementation entry points

`sandbox/interpreter.py` is the only interpreter implementation. It uses
`Environment` from `sandbox/environment.py`, shared exceptions from
`sandbox/errors.py`, and syntax validation and limits from `sandbox/policy.py`.
The benchmark and reference adapter live separately in `sandbox/evaluation/`.

The original `Interpreter().eval_node(ast_node)` interface keeps its instance's
environment across calls, and modules return `None`. Its execution budgets are
also cumulative for that instance. `run(code)` creates a fresh interpreter per
call and returns structured diagnostics. Both entry points validate the complete
AST and apply the same runtime checks. Runtime errors remain exceptions through
`eval_node`; `run` reports them as a `program_error` result.

## Supported programs and results

The subset includes integers, booleans, strings, `None`, lists, tuples,
dictionaries, arithmetic and comparison operators, variable and subscript
assignment, tuple unpacking, conditionals, loops, list and generator
comprehensions, and user-defined functions with ordinary positional arguments
and `return`. Reviewed builtins are `abs`, `enumerate`, `int`, `isinstance`,
`len`, `list`, `map`, `max`, `min`, `print`, `range`, `sorted`, `str`, and
`sum`. Other syntax fails explicitly instead of being passed to Python's
`eval`, `exec`, or `compile` for execution. Imports, classes, context managers,
lambda expressions, arbitrary keyword arguments, and exception handling remain
outside the subset.

Generator expressions use the same bounded implementation as list
comprehensions and are materialized immediately. They are accepted for
compatibility with consumers such as `sum`, but they do not implement Python's
lazy, single-consumption generator-object semantics.

The last top-level expression supplies the execution result; a program ending
with a statement supplies `None`. This convenience does not change function
semantics: only `return` supplies a function result, and falling off the end of a
function returns `None`, even when its final statement is an expression. Printed
text is captured separately from the result.

Lists, tuples, and strings support bounded slice reads. Slice bounds and steps
must be integers or `None`; negative indices and steps follow Python behavior,
and a zero step is a program error. Slice assignment remains unsupported.

## Runtime checks and state

Policy checks apply to the operation and its resolved value at execution time.
Calling an alias of a reviewed builtin is permitted; merely giving an unreviewed
callable an allowed-looking name does not grant permission. The interpreter may
call only its own user-function representation and explicitly reviewed builtin
wrappers. Names beginning with `_`, including `_operations_count`, are reserved
and rejected for both reads and writes. Imports, reflection, and dynamic
evaluation are rejected explicitly. Attribute syntax is accepted only when it
is the direct target of a call using a reviewed method name. Runtime dispatch
then requires an exact built-in list, tuple, or string value and returns an
internal method token rather than a Python bound method. Reviewed methods
include bounded list mutation and lookup plus selected string lookup, splitting,
joining, case conversion, and prefix checks. Blocked names supplement the
default-deny callable policy rather than serving as the security boundary.

Each run receives a fresh environment, output buffer, and trusted budget state.
Counters and policy configuration live outside interpreted variables and cannot
be reset by assignments in the program. No caller-provided Python objects,
modules, callbacks, file handles, or other host capabilities enter that
environment. Inputs and outputs are restricted to validated plain data; builtin
wrappers must not expose host objects through their return values or errors.

## Resource limits and observable outcomes

The initial comparison uses these proposed limits consistently across runs:

| Resource | Limit | Intended enforcement |
| --- | ---: | --- |
| Interpreter steps | 10,000 | Charge executed AST operations and loop iterations against a private counter. |
| Captured output | 4,096 characters | Check output length while appending; never retain output beyond the limit. |
| Collection or range length | 1,000 items | Check construction and growth before allocation or mutation. |
| Integer size | 4,096 bits | Check integer operands and results; reject oversized powers before computing them. |
| Source text | 32,768 bytes | Bound input source, created strings, and string slices. |
| AST structure | 4,096 nodes, depth 64 | Reject large or deeply nested syntax before execution. |
| Function calls | Depth 32 | Stop recursive interpreted calls at a private depth limit. |

Step counting alone does not bound expensive individual host operations. Reviewed
wrappers and operators need size checks before work that could allocate large
objects. A separate worker boundary must impose wall-time and memory limits and
terminate workers that do not respond. These external limits also cover parsing,
interpreter bugs, and operations whose cost is not captured by AST steps.

The smoke suite expects `ok`, `policy_rejected`, `resource_limit`, or
`unsupported`. `policy_rejected` identifies a prohibited capability or reserved
name; `unsupported` identifies other syntax outside the implemented subset.
Resource exhaustion is distinct from either kind of rejection. Ordinary runtime
errors, worker timeouts, and crashes must be recorded distinctly by the harness,
not converted into successful policy rejections.

For observability, record the case and executor identifiers, effective limits,
outcome, rejection or failure reason, source location when available, step count,
captured-output size, elapsed time, and available worker resource measurements.
Successful runs additionally retain their value and captured output. Diagnostic
records should avoid host tracebacks and host object representations in program
output.

## Interpreting the comparison

The harness should retain each executor's actual outcome beside the expected
policy outcome. Count and report mismatches in status, returned value, or output,
including different handling of unsupported syntax and functions without
`return`. Report missing counters or unavailable measurements as unavailable.
Do not hide baseline differences or relabel a crash as an attack blocked. Report
which cases ran and which were excluded before expanding this synthetic suite
into a separately attributed research or CTF corpus.
