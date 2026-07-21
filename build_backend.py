"""Thin setuptools backend wrapper for reproducible source distributions."""

from __future__ import annotations

import copy
import gzip
import os
import tarfile
import tempfile
from pathlib import Path
from typing import cast

from setuptools import build_meta as _setuptools_backend  # type: ignore[import-untyped]

build_wheel = _setuptools_backend.build_wheel
build_editable = _setuptools_backend.build_editable
get_requires_for_build_wheel = _setuptools_backend.get_requires_for_build_wheel
get_requires_for_build_sdist = _setuptools_backend.get_requires_for_build_sdist
get_requires_for_build_editable = _setuptools_backend.get_requires_for_build_editable
prepare_metadata_for_build_wheel = _setuptools_backend.prepare_metadata_for_build_wheel
prepare_metadata_for_build_editable = _setuptools_backend.prepare_metadata_for_build_editable

_MAX_GZIP_TIMESTAMP = (1 << 32) - 1


def _source_date_epoch() -> int | None:
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if raw_epoch is None:
        return None
    try:
        epoch = int(raw_epoch, 10)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
    if not 0 <= epoch <= _MAX_GZIP_TIMESTAMP:
        raise ValueError(f"SOURCE_DATE_EPOCH must be between 0 and {_MAX_GZIP_TIMESTAMP}")
    return epoch


def _normalize_sdist(path: Path, *, epoch: int) -> None:
    """Rewrite one setuptools tarball with stable archive metadata."""

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, path.stat().st_mode & 0o777)
        raw_output = os.fdopen(descriptor, "wb")
        descriptor = -1
        with (
            raw_output,
            tarfile.open(path, mode="r:gz") as source,
            gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=raw_output,
                mtime=epoch,
            ) as compressed_output,
            tarfile.open(
                fileobj=compressed_output,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as target,
        ):
            members = sorted(source.getmembers(), key=lambda member: member.name)
            for member in members:
                normalized = copy.copy(member)
                normalized.mtime = epoch
                normalized.uid = 0
                normalized.gid = 0
                normalized.uname = ""
                normalized.gname = ""
                normalized.pax_headers = {}
                contents = source.extractfile(member) if member.isfile() else None
                try:
                    target.addfile(normalized, contents)
                finally:
                    if contents is not None:
                        contents.close()
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def build_sdist(
    sdist_directory: str,
    config_settings: dict[str, object] | None = None,
) -> str:
    """Delegate to setuptools and normalize only when SOURCE_DATE_EPOCH is set."""

    epoch = _source_date_epoch()
    filename = cast(
        str,
        _setuptools_backend.build_sdist(sdist_directory, config_settings),
    )
    if epoch is not None:
        _normalize_sdist(Path(sdist_directory, filename), epoch=epoch)
    return filename
