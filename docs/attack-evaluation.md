# Initial attack evaluation

This experiment adds a small, provenance-tracked attack suite to the regression
suite. Its purpose is to validate the evaluation method and exercise several
known Python sandbox-escape techniques. Thirteen cases are not enough to estimate
a general escape rate or establish that the prototype is secure.

## Threat model and cases

Ten cases attempt to disclose a file that is present inside the disposable
container but is not exposed by the prototype language. They cover direct file
and module access, recovery of builtins, dynamic evaluation, subclass traversal,
function-global traversal, module traversal, and indirect attribute access.
Three cases exercise unbounded looping, output amplification, and oversized
integer construction.

Every attack record in `benchmarks/attacks.json` includes a source title, HTTPS
URL, source locator, and explanation of the adaptation. The initial sources are:

- Jessica McKellar's
  [*Building and breaking a Python sandbox*](https://web.mit.edu/jesstess/www/pytennessee_sandbox.pdf)
  slides, for builtin, import, file-access, and resource-exhaustion threat
  patterns.
- Ned Batchelder's
  [*Eval really is dangerous*](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous),
  for `eval`, `__import__`, `catch_warnings`, and extreme-arithmetic patterns.
- JailCTF's [Pyjailbreaker](https://github.com/jailctf/pyjailbreaker)
  repository, for object-subclass and function-global gadget chains.
- Hugging Face's
  [smolagents security-fix commit `33a942e`](https://github.com/huggingface/smolagents/commit/33a942e62b6fbf6a35d41f1c735bda2d64c163d0),
  for direct and higher-order access to a module through `warnings.sys`.

Payloads that originally executed commands or modified files were adapted to
read only the experiment's canary. The source metadata describes each change.

## Independent success oracles

For an information-disclosure case, the controller creates 32 random bytes and
passes their hexadecimal encoding only to a bootstrap process. The bootstrap
writes the value to `/tmp/cs263-evaluation-canary.txt` with mode `0400`, removes
the value from the worker environment, and replaces itself with a fresh worker
process. The controller, which already knows the value, checks the raw worker
stdout and stderr for it. The executor's status label is not used to decide
whether disclosure occurred.

For a resource-exhaustion case, attack success means the outer controller had to
stop the container because of a declared wall-time, memory, crash, or protocol
limit. A normal executor exception is not automatically treated as either an
attack success or a policy rejection.

This design keeps the canary harmless and container-local. There are no host
mounts, credentials, or network access. The token changes for every executor and
case execution, so a payload cannot pass by printing a value stored in the
repository.

## Reproduction

From the repository root, build the pinned image and run both executors:

```sh
docker build -f containers/Dockerfile -t cs263-sandbox:baseline .
python3 -m sandbox benchmark \
  --cases benchmarks/attacks.json \
  --output results/attack-evaluation.jsonl
python3 -m sandbox summarize results/attack-evaluation.jsonl
```

Each case runs in a fresh container with no network, a read-only root filesystem,
an unprivileged user, dropped capabilities, one CPU, 256 MiB of memory, and a
five-second wall deadline. The writable `/tmp` is a new 8 MiB `tmpfs` used only
for the canary and ordinary temporary data.

## Initial result

The initial run on 2026-11-18 used attack-suite SHA-256
`89f2cc41ca657110a6467c83cf3a2720b0cd49e05397b94c254a676922c9563d`
and image ID
`sha256:db11a7f71284328609eeb427342d5fe26b0305d26f9f35411af1a2fe872e7650`.

| Executor | Cases | Observed attack successes | Outcomes | Cleanup |
| --- | ---: | ---: | --- | ---: |
| Prototype | 13 | 0 | 10 `policy_rejected`, 3 `resource_limit` | 13/13 |
| Pinned reference | 13 | 2 | 11 `program_error`, 1 `wall_timeout`, 1 `oom_killed` | 13/13 |

Neither executor exposed the canary in the ten information-disclosure cases. The
two observed reference successes were availability outcomes: unbounded output
reached the external wall deadline, and oversized integer construction exhausted
the container memory limit. These reference results are behavioral comparisons,
not vulnerability claims; the upstream project documents its local executor as
[not being a security boundary](https://github.com/huggingface/smolagents/blob/main/SECURITY.md).

The prototype stopped all three availability cases using its own incremental
limits before outer containment intervened. All 26 containers were removed, and
no controller error was recorded.

## Observability and interpretation

Each JSON Lines record retains the source and suite hashes, resolved image ID,
expected and observed outcomes, rejection reason and source location when
available, bounded execution events, step and output accounting, timing, worker
peak memory, external container state, cleanup evidence, provenance, and the
independent oracle result. `python -m sandbox summarize` reports regression
matches separately from observed attack successes.

A zero in the attack-success column means only that these payloads did not meet
their declared oracle in this environment. It does not prove the absence of file
access through other payloads, and an information-disclosure payload that reads
the canary without emitting it would not be detected. Static rejection also does
not demonstrate that a corresponding runtime check would hold if more syntax
were enabled. Future work should add independently sourced cases, group related
variants before train/held-out splits, include benign programs that use adjacent
language features, and repeat performance measurements before making efficiency
claims.
