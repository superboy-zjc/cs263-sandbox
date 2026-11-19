"""Tests for the isolated worker canary bootstrap."""

from pathlib import Path

import pytest

from sandbox.evaluation import bootstrap


def test_prepare_canary_writes_file_and_removes_environment_value(tmp_path):
    token = "a" * 64
    environment = {
        bootstrap.CANARY_ENVIRONMENT_VARIABLE: token,
        "PRESERVED": "value",
    }
    path = tmp_path / "canary.txt"

    worker_environment = bootstrap.prepare_canary(path, environment)

    assert path.read_text(encoding="ascii") == token
    assert bootstrap.CANARY_ENVIRONMENT_VARIABLE not in worker_environment
    assert worker_environment["PRESERVED"] == "value"
    assert environment[bootstrap.CANARY_ENVIRONMENT_VARIABLE] == token
    assert path.stat().st_mode & 0o777 == 0o400


@pytest.mark.parametrize("token", [None, "short", "g" * 64, "A" * 64])
def test_prepare_canary_rejects_invalid_token(tmp_path, token):
    environment = {}
    if token is not None:
        environment[bootstrap.CANARY_ENVIRONMENT_VARIABLE] = token

    with pytest.raises(ValueError, match="valid per-run"):
        bootstrap.prepare_canary(Path(tmp_path) / "canary.txt", environment)


def test_prepare_canary_refuses_to_overwrite_existing_file(tmp_path):
    path = tmp_path / "canary.txt"
    path.write_text("existing", encoding="ascii")

    with pytest.raises(FileExistsError):
        bootstrap.prepare_canary(
            path, {bootstrap.CANARY_ENVIRONMENT_VARIABLE: "b" * 64}
        )

    assert path.read_text(encoding="ascii") == "existing"
