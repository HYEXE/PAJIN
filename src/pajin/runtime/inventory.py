"""Out-of-band startup inventory for the code-owned Control Plane daemons."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pajin.runtime.inventory_fingerprint import configuration_fingerprint, package_fingerprint
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes

RuntimeRole = Literal["control-plane", "worker", "replay-worker"]
_ROLES: tuple[RuntimeRole, ...] = ("control-plane", "worker", "replay-worker")
_Digest = Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[str, Field(strict=True, pattern=r"^[a-z][a-z0-9-]{0,63}$")]
_MAX_INVENTORY_BYTES = 64 * 1024
INVENTORY_PATH_ENV = "PAJIN_RUNTIME_INVENTORY_PATH"
INVENTORY_SHA256_ENV = "PAJIN_RUNTIME_INVENTORY_SHA256"
COMPONENT_ID_ENV = "PAJIN_RUNTIME_COMPONENT_ID"
HOST_ROOT_ENV = "PAJIN_HOST_RUNTIME_ROOT"


class RuntimeInventoryError(ValueError):
    """The configured runtime cannot be admitted under its pinned inventory."""


class RuntimeComponentFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    component_id: _Identifier = Field(alias="componentId")
    role: RuntimeRole
    package_sha256: _Digest = Field(alias="packageSha256")
    configuration_sha256: _Digest = Field(alias="configurationSha256")


class RuntimeInventory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    api_version: Literal[
        "pajin.dev/runtime-inventory/v1", "pajin.dev/runtime-inventory/v2",
        "pajin.dev/runtime-inventory/v3",
    ] = Field(alias="apiVersion")
    inventory_id: _Identifier = Field(alias="inventoryId")
    host_root_sha256: _Digest | None = Field(
        default=None, alias="hostRootSha256", exclude_if=lambda value: value is None,
    )
    recovery_policy: Literal["closed-local-sqlite-v1"] | None = Field(
        default=None, alias="recoveryPolicy", exclude_if=lambda value: value is None,
    )
    components: Annotated[
        tuple[RuntimeComponentFingerprint, ...], Field(min_length=1, max_length=64)
    ]

    @model_validator(mode="after")
    def require_unique_components(self) -> RuntimeInventory:
        if len({item.component_id for item in self.components}) != len(self.components):
            raise ValueError("runtime inventory component IDs must be unique")
        if (self.api_version != "pajin.dev/runtime-inventory/v1") != (
            self.host_root_sha256 is not None
        ):
            raise ValueError("runtime inventory v2/v3 requires a host root digest")
        if (self.api_version == "pajin.dev/runtime-inventory/v3") != (
            self.recovery_policy is not None
        ):
            raise ValueError("only runtime inventory v3 requires recovery enrollment")
        return self


def host_root_digest(root: Path) -> str:
    if not root.is_absolute() or ".." in root.parts:
        raise RuntimeInventoryError("host runtime root must be an absolute, unambiguous path")
    return hashlib.sha256(b"pajin.host-runtime-root/v1\0" + os.fsencode(root)).hexdigest()


def fingerprint_component(
    role: RuntimeRole, *, configuration: object | None = None,
) -> RuntimeComponentFingerprint:
    try:
        return RuntimeComponentFingerprint(
            componentId=os.environ.get(COMPONENT_ID_ENV, role),
            role=role,
            packageSha256=package_fingerprint(),
            configurationSha256=configuration_fingerprint(configuration),
        )
    except (OSError, TypeError, ValueError):
        raise RuntimeInventoryError("runtime fingerprint could not be verified") from None


def load_runtime_inventory(path: Path, expected_sha256: str) -> RuntimeInventory:
    try:
        if not path.is_absolute():
            raise ValueError("inventory path must be absolute")
        content = read_bounded_regular_bytes(
            path, max_bytes=_MAX_INVENTORY_BYTES,
            label="runtime inventory", require_single_link=True,
        )
        if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected_sha256):
            raise ValueError("inventory digest mismatch")
        return RuntimeInventory.model_validate(parse_strict_json_bytes(
            content, label="runtime inventory", max_bytes=_MAX_INVENTORY_BYTES,
        ))
    except (OSError, TypeError, ValueError):
        raise RuntimeInventoryError(
            "runtime inventory is invalid or does not match its pin"
        ) from None


def verify_runtime_inventory(
    role: RuntimeRole,
    *,
    configuration: object | None = None,
    injected_runtime: bool = False,
) -> RuntimeComponentFingerprint | None:
    """Fail before store initialization/claims; an absent pair preserves legacy startup.

    The inventory is configured by the trusted process owner. No request, saved
    database, or inventory body supplies the expected digest or chooses code.
    """
    path = os.environ.get(INVENTORY_PATH_ENV)
    digest = os.environ.get(INVENTORY_SHA256_ENV)
    if path is None and digest is None:
        if COMPONENT_ID_ENV in os.environ:
            raise RuntimeInventoryError("runtime component selection requires a pinned inventory")
        return None
    if not path or not digest or path != path.strip():
        raise RuntimeInventoryError(
            "runtime inventory path and SHA-256 must be configured together"
        )
    if injected_runtime:
        raise RuntimeInventoryError("runtime inventory requires code-owned deployment factories")
    inventory = load_runtime_inventory(Path(path), digest)
    root = os.environ.get(HOST_ROOT_ENV)
    if inventory.host_root_sha256 is not None:
        if (
            not root or root != root.strip()
            or host_root_digest(Path(root)) != inventory.host_root_sha256
        ):
            raise RuntimeInventoryError("runtime inventory requires its enrolled host root")
    elif root is not None:
        raise RuntimeInventoryError("host activity requires runtime inventory v2")
    current = fingerprint_component(role, configuration=configuration)
    expected = next(
        (item for item in inventory.components if item.component_id == current.component_id), None,
    )
    if expected != current:
        raise RuntimeInventoryError("runtime component differs from the pinned startup inventory")
    return current


def _effective_configuration(role: RuntimeRole) -> object | None:
    if role == "control-plane":
        from pajin.control_plane.api import ControlPlaneSettings

        return ControlPlaneSettings.from_env()
    return None


def main() -> None:
    """Print fingerprints/inventory to stdout; never create stores or overwrite pins."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("fingerprint", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--role", choices=_ROLES, required=True)
    compose = commands.add_parser("compose")
    compose.add_argument("--inventory-id", required=True)
    compose.add_argument("--host-root", type=Path)
    compose.add_argument("--enroll-recovery", action="store_true")
    compose.add_argument("components", nargs="+", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "compose":
            if arguments.enroll_recovery and arguments.host_root is None:
                raise RuntimeInventoryError("recovery enrollment requires a host root")
            components = [RuntimeComponentFingerprint.model_validate(parse_strict_json_bytes(
                read_bounded_regular_bytes(
                    path, max_bytes=_MAX_INVENTORY_BYTES,
                    label="runtime component fingerprint", require_single_link=True,
                ),
                label="runtime component fingerprint", max_bytes=_MAX_INVENTORY_BYTES,
            )) for path in arguments.components]
            inventory = RuntimeInventory(
                apiVersion=(
                    "pajin.dev/runtime-inventory/v3" if arguments.enroll_recovery else
                    "pajin.dev/runtime-inventory/v2" if arguments.host_root is not None
                    else "pajin.dev/runtime-inventory/v1"
                ),
                inventoryId=arguments.inventory_id,
                hostRootSha256=(
                    host_root_digest(arguments.host_root)
                    if arguments.host_root is not None else None
                ),
                recoveryPolicy=(
                    "closed-local-sqlite-v1" if arguments.enroll_recovery else None
                ),
                components=tuple(components),
            )
            print(inventory.model_dump_json(by_alias=True))
        else:
            configuration = _effective_configuration(arguments.role)
            current: RuntimeComponentFingerprint | None
            if arguments.command == "fingerprint":
                current = fingerprint_component(arguments.role, configuration=configuration)
            else:
                current = verify_runtime_inventory(arguments.role, configuration=configuration)
                if current is None:
                    raise RuntimeInventoryError("no runtime inventory is configured")
            print(current.model_dump_json(by_alias=True))
    except (OSError, TypeError, ValueError, RuntimeError):
        sys.stderr.write("Runtime inventory command failed; configuration was not admitted.\n")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
