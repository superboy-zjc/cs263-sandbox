# Sourced attack-corpus evaluation

## What this corpus can support

The original 13 cases were enough to test the experiment machinery, but not
enough to support a broad-coverage claim. The expanded corpus contains 36
payload variants grouped into 31 related variant groups, 16 project-defined
mechanism classes, seven source families, and three source kinds. The grouping
matters: the direct, map, and partial forms of warnings.sys, for example, are
payload variants rather than three independent escape mechanisms.

The corpus supports the narrower statement that the evaluation samples a broad
set of publicly documented Python-sandbox failure mechanisms from current
upstream security tests, published security discussions, and CTF/pyjail
repositories. It does not prove completeness, establish a state-of-the-art
denominator, or estimate an unknown-attack escape rate.

Every attack case records:

- a controlled technique_class;
- a variant_group used to avoid counting syntax variants as independent
  techniques;
- a source family and source kind;
- an immutable URL where possible, an exact locator, and the SHA-256 of the
  source artifact inspected;
- the source's license status and a description of the safe adaptation; and
- an independent canary-disclosure or outer-termination oracle.

The loader rejects missing metadata, malformed source hashes, unknown source or
technique classes, duplicate payloads, and a variant group mapped to more than
one technique class.

## Composition

| Mechanism class | Payload variants | Variant groups | Source families |
| --- | ---: | ---: | ---: |
| AST validation bypass | 1 | 1 | 1 |
| Code-object construction | 1 | 1 | 1 |
| Direct capability access | 2 | 1 | 1 |
| Dynamic code execution | 3 | 3 | 3 |
| Formatter introspection | 1 | 1 | 1 |
| Frame introspection | 4 | 3 | 3 |
| Indirect attribute access | 2 | 1 | 1 |
| Name-filter bypass | 3 | 3 | 3 |
| Namespace recovery | 2 | 2 | 2 |
| Object-graph traversal | 5 | 4 | 3 |
| Collection or string amplification | 3 | 3 | 2 |
| Nontermination | 1 | 1 | 1 |
| Numeric amplification | 2 | 1 | 2 |
| Output amplification | 1 | 1 | 1 |
| Recursion exhaustion | 1 | 1 | 1 |
| Transitive module access | 4 | 4 | 1 |
| **Total** | **36** | **31** | **7 overall** |

Twenty-seven cases attempt to disclose a fresh container-local canary. Nine
attempt to force an outer timeout, OOM kill, crash, or protocol limit. By source
kind, 19 variants come from sandbox security regressions, ten from published
security discussions, and seven from CTF/pyjail sources.

## Primary sources and adaptation

The upstream files were inspected at fixed revisions. Source-file hashes are
stored per case in [benchmarks/attacks.json](../benchmarks/attacks.json).

| Source family | Fixed source | What it contributes |
| --- | --- | --- |
| RestrictedPython security tests | [9d7aeb2](https://github.com/zopefoundation/RestrictedPython/blob/9d7aeb267e598c3eb270850c223b343ca5a5d2cb/tests/test_Guards.py) | string.Formatter.get_field, forged str attribute names, generator-frame recovery, and bounded range construction. |
| asteval security tests | [aeaad8a](https://github.com/lmfit/asteval/blob/aeaad8a2fb2af004a065b35f6e86506a88ebfb9d/tests/test_asteval.py) | compile/exec, malformed code-object construction, recursion, and exponent towers. |
| smolagents security tests | [505b76b](https://github.com/huggingface/smolagents/blob/505b76b28d5cab580d7a4e0eaf4e8f142819e6a9/tests/test_local_python_executor.py) | sys.modules, importlib, transitive modules, higher-order getattr, traceback and current frames, BuiltinImporter, Popen, and dangerous builtins. |
| JailCTF Pyjailbreaker | [fb998df](https://github.com/jailctf/pyjailbreaker/tree/fb998df13e3008bb3b8f34d561dddf109cbbcc08) | _wrap_close, builtin __self__, BuiltinImporter, generator frames, and runtime construction of dunder names. |
| JailCTF challenge collection | [cc4a25f](https://github.com/jailctf/pyjail-collection/tree/cc4a25fba392c92a6679acf70f588fbd4773c13a) | A one-level AST traversal bug from llama-jail and NFKC identifier normalization from pycryptojail. |
| McKellar sandbox talk | [*Building and breaking a Python sandbox*](https://web.mit.edu/jesstess/www/pytennessee_sandbox.pdf) | Direct file/import access and CPU, output, collection, and string resource threats. |
| Batchelder article | [*Eval really is dangerous*](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html) | eval/import recovery, catch_warnings, and extreme integer construction. |

RestrictedPython is ZPL-2.1, asteval is MIT, and smolagents is Apache-2.0.
The inspected JailCTF repositories did not contain a license file at the fixed
revisions. Their payload ideas were therefore independently rewritten rather
than copied, and the absence of a declared license is recorded in every
affected case. Published slides and articles are also treated as attributed
ideas rather than copied source.

Command-execution payloads were changed to bounded reads of
/tmp/cs263-evaluation-canary.txt. The Popen case uses an argv-based cat inside
the disposable container, not a shell. Resource payloads have no external
target.

## Reviewed sources that were not counted

Breadth also requires excluding mismatched evidence rather than inflating the
case count.

- Jinja2's
  [SandboxedEnvironment tests at 5ef7011](https://github.com/pallets/jinja/blob/5ef70112a1ff19c05324ff889dd30405b1002044/tests/test_security.py)
  cover attr filters, unsafe callables, immutable containers, and sandbox-aware
  string formatting. Those tests depend on Jinja's template syntax, filters,
  Undefined, and rendering object model. Porting them to ordinary Python would
  test different semantics, so they are documented but excluded.
- HumanEval's reliability guard is not a sandbox and its own source says so. It
  informs the outer timeout design but does not add attack cases.
- Interactive help sessions, source-file encoding-cookie tricks, and
  persistent-global poisoning require an interactive byte stream or warm
  multi-request worker. This project accepts one JSON-decoded string in a fresh
  executor, so those cases are outside the present threat model.
- Host-object mutation tests need an integrity oracle, while the current
  harness has disclosure and availability oracles. They remain a concrete
  extension rather than being mislabeled as canary attacks.

## Independent success oracles

For each disclosure case, the controller generates 32 random bytes and gives
their hexadecimal encoding only to a bootstrap process. The bootstrap writes
the value to /tmp/cs263-evaluation-canary.txt with mode 0400, removes the value
from the worker environment, and replaces itself with the worker. The
controller scans raw worker stdout and stderr for the exact value. Executor
status labels do not determine disclosure.

For availability cases, success means the declared outer controller condition
occurred: wall timeout, OOM kill, crash, or protocol limit. A normal interpreter
exception or internal resource_limit is not an attack success.

There are no host mounts, credentials, or network access. Each case and
executor receives a new token and container. The canary is harmless and local
to the experiment.

## Reproduction

    docker build -f containers/Dockerfile \
      -t cs263-sandbox:attacks-expanded-final .
    .venv/bin/python -m sandbox benchmark \
      --cases benchmarks/attacks.json \
      --image cs263-sandbox:attacks-expanded-final \
      --output results/attacks-expanded-final-20261125.jsonl
    .venv/bin/python -m sandbox summarize \
      results/attacks-expanded-final-20261125.jsonl

Each case runs with no network or host mount, a read-only root filesystem,
unprivileged UID/GID, dropped capabilities, no-new-privileges, one CPU,
256 MiB memory, an 8 MiB /tmp, and a five-second outer deadline.

## Accepted result

The accepted run on 2026-11-25 used:

- suite SHA-256
  4bc85f83599e8384a52be82b4786a6d4d75e742c65f9e505d6d2c1c862eca030;
- image ID
  sha256:128da983471829f9e0f29551a093c73b2232499e0d5cf29bd07bd220c602ca71;
- result-file SHA-256
  49a5b4ba8041f477bb542997e6991d0074ca61271bef896769928dc3646c5a8c.

| Executor | Cases | Canary disclosures | Availability successes | Observed statuses |
| --- | ---: | ---: | ---: | --- |
| Prototype | 36 | 0 | 0 | 25 policy_rejected, 8 resource_limit, 3 unsupported |
| Pinned reference | 36 | 0 | 6 | 30 program_error, 4 oom_killed, 2 wall_timeout |

The six reference availability outcomes comprised:

- OOM kills for oversized integer power, range materialization, list
  repetition, and string repetition; and
- wall timeouts for unbounded output and the exponent tower.

They affected five variant groups and three resource mechanism classes. The
prototype stopped all nine availability attempts internally or rejected their
syntax before outer containment intervened. Neither executor disclosed the
canary in any of the 27 disclosure attempts.

All 72 records had complete source metadata. All 72 containers were inspected
and removed with no inspection retry, cleanup retry, cleanup failure,
controller error, or residual evaluation container.

## Observability and interpretation

Each JSON Lines record retains the case, source, suite, and image fingerprints;
the four corpus-grouping fields; expected and observed status; rejection reason
and source location where available; bounded runtime events; interpreter steps;
output, timing, and peak worker memory; Docker exit/OOM state; inspection and
removal attempts; controller errors; and the independent oracle result.

The summarizer reports case variants separately from variant groups, mechanism
classes, source families, and source kinds. It also reports which groups and
classes had an observed success, while keeping expectation matches distinct
from security oracles. Mixed images, mixed suites, and unbalanced case counts
remain visible.

Zero observed prototype successes means only that these 36 payloads did not
meet their declared oracles under these conditions. Twenty-five cases were
rejected statically and three used unsupported syntax, so the result does not
show that every corresponding runtime guard would hold if the language were
expanded. The suite has no blind held-out attack partition, integrity oracle,
network oracle, side-channel oracle, native-extension case, or proof that its
16 project-defined classes exhaust Python sandbox attacks. The defensible claim
is broad, sourced mechanism sampling with auditable outcomes—not proof of
security or complete state-of-the-art coverage.
