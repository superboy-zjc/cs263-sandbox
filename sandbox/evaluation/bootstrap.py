"""Create a per-run canary before starting the isolated worker."""

import os
from pathlib import Path
import re
import sys


CANARY_ENVIRONMENT_VARIABLE = "CS263_EVALUATION_CANARY"
CANARY_PATH = Path("/tmp/cs263-evaluation-canary.txt")
_CANARY_PATTERN = re.compile(r"[0-9a-f]{64}")


def prepare_canary(path: Path, environment: dict[str, str]) -> dict[str, str]:
    """Write the one-run canary and return an environment without its value.

    The bootstrap process is the only process that receives the canary through
    the environment. The worker is started with a copy that omits the value, so
    submitted code must cross the intended language boundary and read the file
    to expose it.
    """
    worker_environment = environment.copy()
    token = worker_environment.pop(CANARY_ENVIRONMENT_VARIABLE, None)
    if token is None or _CANARY_PATTERN.fullmatch(token) is None:
        raise ValueError("A valid per-run evaluation canary is required.")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o400)
    try:
        payload = token.encode("ascii")
        position = 0
        while position < len(payload):
            written = os.write(descriptor, payload[position:])
            if written <= 0:
                raise OSError("Could not write the evaluation canary.")
            position += written
        os.fchmod(descriptor, 0o400)
    finally:
        os.close(descriptor)
    return worker_environment


def main() -> None:
    """Replace this process with a worker that cannot see the canary in env."""
    worker_environment = prepare_canary(CANARY_PATH, dict(os.environ))
    os.execve(
        sys.executable,
        [sys.executable, "-m", "sandbox.evaluation.worker"],
        worker_environment,
    )


if __name__ == "__main__":
    main()
