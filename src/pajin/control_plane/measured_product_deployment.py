"""Digest-pinned startup composition of existing contextful measurement readers."""

from __future__ import annotations

import hmac
import stat
from collections.abc import Iterator
from dataclasses import dataclass, fields, is_dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator

from pajin.control_plane.measured_product_settings import (
    validate_measured_product_deployment_settings,
)
from pajin.control_plane.measured_product_sources import (
    AIProductRecipe,
    NetworkProductRecipe,
    _RecipeModel,
)
from pajin.control_plane.system_product import SystemProductReader, SystemProductRecipe
from pajin.control_plane.web_measured_product_deployment import WebProductRecipe
from pajin.runtime.safe_files import (
    atomic_write_text_no_follow,
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)
from pajin.workflow.ai_fixture_runtime import AIFixtureDockerProvider
from pajin.workflow.ai_measured_case_authority import registered_ai_measured_case_mapping
from pajin.workflow.ai_measured_product_flow import AIMeasuredProductSourceReopenContext
from pajin.workflow.ai_measured_product_reader import (
    AIMeasuredProductReader,
    AIMeasuredProductReadRegistration,
    AIMeasuredProductReadRegistry,
)
from pajin.workflow.network_fixture_runtime import NetworkFixtureDockerProvider
from pajin.workflow.network_measured_case_authority import registered_network_measured_case_mapping
from pajin.workflow.network_measured_product_flow import NetworkMeasuredProductSourceReopenContext
from pajin.workflow.network_measured_product_reader import (
    NetworkMeasuredProductReader,
    NetworkMeasuredProductReadRegistration,
    NetworkMeasuredProductReadRegistry,
)
from pajin.workflow.web_measured_product_reader import WebMeasuredProductReader

MAX_MEASURED_PRODUCT_DEPLOYMENT_BYTES = 32 * 1024 * 1024


class MeasuredProductDeploymentError(RuntimeError):
    """A safe startup diagnostic that never includes private verifier material."""


class MeasuredProductDeployment(_RecipeModel):
    api_version: Literal["pajin.dev/measured-product-deployment/v1alpha1"] = Field(
        default="pajin.dev/measured-product-deployment/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["MeasuredProductDeployment"] = "MeasuredProductDeployment"
    deployment_id: str = Field(alias="deploymentId", pattern=r"^[a-z][a-z0-9.-]{0,127}$")
    evidence_root: Path = Field(alias="evidenceRoot")
    web: WebProductRecipe | None = None
    network: NetworkProductRecipe | None = None
    ai: AIProductRecipe | None = None
    system: SystemProductRecipe | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def require_selection(self) -> Self:
        if self.web is None and self.network is None and self.ai is None and self.system is None:
            raise ValueError("measured product deployment requires at least one product")
        return self


@dataclass(frozen=True, slots=True)
class MeasuredProductReaders:
    web: WebMeasuredProductReader | None = None
    network: NetworkMeasuredProductReader | None = None
    ai: AIMeasuredProductReader | None = None
    system: SystemProductReader | None = None

    def diagnostic(self) -> dict[str, str]:
        result = {
            domain: "verified" if getattr(self, domain) is not None else "not-configured"
            for domain in ("web", "network", "ai")
        }
        # Preserve the legacy diagnostic shape for existing deployments.
        if self.system is not None:
            result["system"] = "verified"
        return result


def _paths(value: object) -> Iterator[Path]:
    if isinstance(value, Path):
        yield value
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from _paths(getattr(value, name))
    elif is_dataclass(value) and not isinstance(value, type):
        for item in fields(value):
            yield from _paths(getattr(value, item.name))
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _paths(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _paths(item)


def _validate_durable_paths(deployment: MeasuredProductDeployment) -> None:
    root = deployment.evidence_root
    if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError("measured product evidence root must be an existing exact directory")
    for path in set(_paths(deployment)):
        if (
            not path.is_absolute()
            or path.resolve(strict=True) != path
            or not path.is_relative_to(root)
        ):
            raise ValueError("measured product durable coordinate is not an exact retained path")
        metadata = path.stat()
        if not stat.S_ISDIR(metadata.st_mode) and (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        ):
            raise ValueError("measured product durable coordinate is not a regular retained entry")


def write_measured_product_deployment(path: Path, deployment: MeasuredProductDeployment) -> str:
    """Export a private inventory; the returned hash must be pinned out of band."""
    _validate_durable_paths(deployment)
    content = deployment.model_dump_json(by_alias=True) + "\n"
    raw = content.encode("utf-8")
    if len(raw) > MAX_MEASURED_PRODUCT_DEPLOYMENT_BYTES:
        raise ValueError("measured product deployment exceeds its byte limit")
    atomic_write_text_no_follow(path, content, label="measured product deployment")
    return sha256(raw).hexdigest()


def load_measured_product_readers(path: Path | None, digest: str | None) -> MeasuredProductReaders:
    """Rebuild fixed production verifiers and preflight every selected reader."""
    validate_measured_product_deployment_settings(path, digest)
    if path is None:
        return MeasuredProductReaders()
    assert digest is not None
    stage = "bundle-read"
    try:
        raw = read_bounded_regular_bytes(
            path,
            max_bytes=MAX_MEASURED_PRODUCT_DEPLOYMENT_BYTES,
            label="measured product deployment",
            require_single_link=True,
        )
        stage = "bundle-digest"
        if not hmac.compare_digest(sha256(raw).hexdigest(), digest):
            raise ValueError("deployment digest differs")
        stage = "bundle-schema"
        parse_strict_json_bytes(
            raw,
            label="measured product deployment",
            max_bytes=MAX_MEASURED_PRODUCT_DEPLOYMENT_BYTES,
            max_nodes=2_000_000,
        )
        deployment = MeasuredProductDeployment.model_validate_json(raw)
        stage = "durable-paths"
        _validate_durable_paths(deployment)
        web = None
        network = None
        ai = None
        system = None
        if deployment.web is not None:
            stage = "web-reconstruction"
            web = deployment.web.build_reader(deployment_id=deployment.deployment_id)
            stage = "web-verification"
            web.read()
        if deployment.network is not None:
            stage = "network-reconstruction"
            outcome = deployment.network.reopen()
            context = NetworkMeasuredProductSourceReopenContext(
                measured_cases=registered_network_measured_case_mapping(),
                provider=NetworkFixtureDockerProvider(),
            )
            registration = NetworkMeasuredProductReadRegistration.from_outcome(
                deployment_id=deployment.deployment_id,
                outcome=outcome,
                reopen_context=context,
            )
            network = NetworkMeasuredProductReader(
                deployment_id=deployment.deployment_id,
                resolver=NetworkMeasuredProductReadRegistry((registration,)),
            )
            stage = "network-verification"
            network.read()
        if deployment.ai is not None:
            stage = "ai-reconstruction"
            ai_registration = AIMeasuredProductReadRegistration.from_outcome(
                deployment_id=deployment.deployment_id,
                outcome=deployment.ai.reopen(),
                reopen_context=AIMeasuredProductSourceReopenContext(
                    measured_cases=registered_ai_measured_case_mapping(),
                    provider=AIFixtureDockerProvider(),
                ),
            )
            ai = AIMeasuredProductReader(
                deployment_id=deployment.deployment_id,
                resolver=AIMeasuredProductReadRegistry((ai_registration,)),
            )
            stage = "ai-verification"
            ai.read()
        if deployment.system is not None:
            stage = "system-reconstruction"
            system = SystemProductReader(deployment.system)
            stage = "system-verification"
            system.preflight()
        return MeasuredProductReaders(web=web, network=network, ai=ai, system=system)
    except Exception:
        raise MeasuredProductDeploymentError(
            f"measured product startup failed at {stage}; "
            "verify the pinned deployment and retained evidence"
        ) from None
