"""Private, deterministic fingerprints of the trusted startup configuration.

These fingerprints detect deployment drift. They are not remote attestation of a
host, of imported third-party code, or of mutable container image tags.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import socket
import sys
from collections.abc import Mapping
from datetime import date, datetime, timedelta
from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from pajin.runtime.safe_files import read_bounded_regular_bytes

_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_PACKAGE_BYTES = 128 * 1024 * 1024
_MAX_PACKAGE_FILES = 4096
_MAX_CONFIGURATION_BYTES = 8 * 1024 * 1024
_INVENTORY_ENV = frozenset({
    "PAJIN_RUNTIME_INVENTORY_PATH",
    "PAJIN_RUNTIME_INVENTORY_SHA256",
    "PAJIN_RUNTIME_COMPONENT_ID",
})
# Shell bookkeeping differs between a fingerprint command and the later daemon.
# Every other inherited variable is conservatively part of the configuration.
_BOOKKEEPING_ENV = frozenset({"_", "SHLVL", "OLDPWD"})
_CONFIGURATION_FILE_ENV = (
    "PAJIN_CP_TLS_CERT_FILE",
    "PAJIN_CP_TLS_KEY_FILE",
    "PAJIN_CP_WORKER_MTLS_CA_FILE",
    "PAJIN_CP_TLS_CA_FILE",
    "PAJIN_CP_MTLS_CERT_FILE",
    "PAJIN_CP_MTLS_KEY_FILE",
    "PAJIN_CP_PENTEST_RECON_DEPLOYMENT_PATH",
    "PAJIN_CP_PENTEST_REPLAY_DEPLOYMENT_PATH",
    "PAJIN_CP_PENTEST_WORKFLOW_DEPLOYMENT_PATH",
    "PAJIN_CP_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_PATH",
    "PAJIN_CP_MEASURED_PRODUCT_DEPLOYMENT_PATH",
    "PAJIN_CAPABILITY_GRAPH_DEPLOYMENT_PATH",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)
_SETTINGS_FILE_FIELDS = (
    "pentest_recon_deployment_path",
    "pentest_replay_deployment_path",
    "pentest_workflow_deployment_path",
    "pentest_workflow_coordination_deployment_path",
    "measured_product_deployment_path",
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def _private_value(value: object, *, depth: int = 0) -> object:
    """Encode settings without repr, lossy coercion, or unsupported collaborators."""
    if depth > 64:
        raise ValueError("runtime configuration is too deeply nested")
    if isinstance(value, Enum):
        return {
            "enum": f"{type(value).__module__}.{type(value).__qualname__}",
            "value": _private_value(value.value, depth=depth + 1),
        }
    if value is None or type(value) in {str, bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("runtime configuration contains a non-finite value")
        return value
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, Path):
        return {"path": os.path.abspath(value)}
    if isinstance(value, (datetime, date)):
        return {"type": type(value).__name__, "value": value.isoformat()}
    if isinstance(value, timedelta):
        return {"timedelta": [value.days, value.seconds, value.microseconds]}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            "dataclass": f"{type(value).__module__}.{type(value).__qualname__}",
            "fields": {
                item.name: _private_value(getattr(value, item.name), depth=depth + 1)
                for item in dataclasses.fields(value)
            },
        }
    if isinstance(value, BaseModel):
        return {
            "model": f"{type(value).__module__}.{type(value).__qualname__}",
            "fields": _private_value(value.model_dump(mode="python"), depth=depth + 1),
        }
    if isinstance(value, Mapping):
        pairs = [
            [_private_value(key, depth=depth + 1), _private_value(item, depth=depth + 1)]
            for key, item in value.items()
        ]
        return {"mapping": sorted(pairs, key=lambda pair: _json_bytes(pair[0]))}
    if isinstance(value, (tuple, list, set, frozenset)):
        items = [_private_value(item, depth=depth + 1) for item in value]
        if isinstance(value, (set, frozenset)):
            items.sort(key=_json_bytes)
        return {"type": type(value).__name__, "items": items}
    raise ValueError("runtime configuration contains an unsupported value")


def configuration_fingerprint(configuration: object | None = None) -> str:
    """Hash all effective settings, inherited inputs and declared config-file bytes.

    Mutable stores/output directories are bound by their configured locations, not
    by their changing contents. Only the final digest may leave this function.
    """
    environment = {
        name: value for name, value in os.environ.items()
        if name not in _INVENTORY_ENV | _BOOKKEEPING_ENV
    }
    files = {
        name: Path(environment[name]) for name in _CONFIGURATION_FILE_ENV
        if name in environment
    }
    if configuration is not None:
        for name in _SETTINGS_FILE_FIELDS:
            path = getattr(configuration, name, None)
            if path is not None:
                if not isinstance(path, Path):
                    raise ValueError("runtime deployment file setting must be a path")
                files[f"settings.{name}"] = path
    file_digests = {
        name: hashlib.sha256(read_bounded_regular_bytes(
            path,
            max_bytes=_MAX_FILE_BYTES,
            label="runtime configuration file",
            require_single_link=True,
        )).hexdigest()
        for name, path in files.items()
    }
    payload = _json_bytes({
        "version": "pajin.runtime.configuration/v1",
        "environment": environment,
        "settings": _private_value(configuration),
        "files": file_digests,
        "workingDirectory": str(Path.cwd()),
        "hostname": socket.gethostname(),
        "pythonExecutable": sys.executable,
        "pythonPrefix": sys.prefix,
        "pythonPath": sys.path[1:],
    })
    if len(payload) > _MAX_CONFIGURATION_BYTES:
        raise ValueError("runtime configuration exceeds its byte limit")
    return hashlib.sha256(payload).hexdigest()


def package_fingerprint() -> str:
    """Hash PAJIN source/assets and interpreter/distribution metadata, without cache."""
    root = Path(__file__).parent.parent
    files: list[tuple[str, str]] = []
    total_bytes = 0

    def reject_unreadable_directory(error: OSError) -> None:
        raise ValueError("runtime package directory could not be inspected") from error

    for directory, directories, filenames in os.walk(
        root, followlinks=False, onerror=reject_unreadable_directory,
    ):
        base = Path(directory)
        for name in directories:
            if (base / name).is_symlink() or (base / name).is_junction():
                raise ValueError("runtime package contains a linked directory")
        directories[:] = sorted(name for name in directories if name != "__pycache__")
        for name in sorted(filenames):
            path = base / name
            if path.suffix == ".pyc":
                continue
            if len(files) >= _MAX_PACKAGE_FILES:
                raise ValueError("runtime package exceeds its file limit")
            content = read_bounded_regular_bytes(
                path, max_bytes=_MAX_FILE_BYTES, label="runtime package file",
            )
            total_bytes += len(content)
            if total_bytes > _MAX_PACKAGE_BYTES:
                raise ValueError("runtime package exceeds its byte limit")
            files.append((path.relative_to(root).as_posix(), hashlib.sha256(content).hexdigest()))
    if not files:
        raise ValueError("runtime package source is unavailable")
    distributions = sorted(
        (
            distribution.metadata["Name"],
            distribution.version,
            hashlib.sha256((distribution.read_text("METADATA") or "").encode()).hexdigest(),
            hashlib.sha256((distribution.read_text("RECORD") or "").encode()).hexdigest(),
        )
        for distribution in importlib.metadata.distributions()
    )
    return hashlib.sha256(_json_bytes({
        "version": "pajin.runtime.package/v1",
        "files": files,
        "python": sys.version,
        "implementation": sys.implementation.name,
        "cacheTag": sys.implementation.cache_tag,
        "platform": sys.platform,
        "machine": platform.machine(),
        "distributions": distributions,
    })).hexdigest()
