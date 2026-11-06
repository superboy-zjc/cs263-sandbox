#!/usr/bin/env python3
"""Download and verify the immutable upstream smolagents reference archive."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.request


REFERENCE_COMMIT = "96f33faaf028479119ec8d34507b47694cf14e34"
REFERENCE_ARCHIVE_SHA256 = (
    "3c200289ee78a84a71c835d5d895042834aeee9280c34f8890295304f675e3b0"
)
REFERENCE_URL = (
    "https://codeload.github.com/huggingface/smolagents/tar.gz/"
    + REFERENCE_COMMIT
)
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


def fetch_reference(destination: Path) -> Path:
    """Download a checksum-verified archive without importing upstream code.

    Args:
        destination: Archive destination. Reuse it if already checksum-verified.

    Returns:
        The path to the verified archive.

    Raises:
        FileExistsError: The destination exists with different contents.
        ValueError: The response is oversized or its checksum does not match.
        OSError: Downloading or writing the archive fails.
    """
    destination = destination.resolve()
    if destination.exists():
        if destination.stat().st_size > MAX_ARCHIVE_BYTES:
            raise FileExistsError("Existing archive exceeds the size limit.")
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        if digest != REFERENCE_ARCHIVE_SHA256:
            raise FileExistsError(
                "Existing archive has an unexpected checksum."
            )
        return destination

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".smolagents-download-", dir=destination.parent, delete=False
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            digest = hashlib.sha256()
            downloaded_bytes = 0
            request = urllib.request.Request(
                REFERENCE_URL,
                headers={"User-Agent": "cs263-sandbox-reference/1"},
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                while chunk := response.read(64 * 1024):
                    downloaded_bytes += len(chunk)
                    if downloaded_bytes > MAX_ARCHIVE_BYTES:
                        raise ValueError(
                            "Reference archive exceeds the size limit."
                        )
                    digest.update(chunk)
                    temporary_file.write(chunk)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        if digest.hexdigest() != REFERENCE_ARCHIVE_SHA256:
            raise ValueError(
                "Reference archive checksum does not match the pin."
            )
        # A hard link publishes the complete file without overwriting a file
        # created by another fetcher while the download was in progress.
        os.link(temporary_path, destination)
        return destination
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> None:
    """Fetch the pinned archive and print its provenance as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    archive = fetch_reference(arguments.output)
    print(
        json.dumps(
            {
                "reference_commit": REFERENCE_COMMIT,
                "archive_sha256": REFERENCE_ARCHIVE_SHA256,
                "archive_path": str(archive),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
