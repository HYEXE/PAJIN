"""Pinned deployment authority for the Worker-side Graph/Capability bridge."""

from __future__ import annotations

import hmac
import json
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from re import fullmatch

from pydantic import Field, ValidationError, field_validator, model_validator

from pajin.capabilities import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CapabilityGraphRunAuditAnchor,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityUseProfile,
    ExistingModeCapabilityActivation,
    activate_existing_mode_capabilities,
    admit_existing_mode_capability_releases,
    existing_mode_capability_bundle,
)
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.graph import (
    GraphActionPermitAuthority,
    GraphActionPermitDispatcher,
    MissionEnvelope,
    SQLiteGraphStore,
)
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_events
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mock import MockAgentProbe

CAPABILITY_GRAPH_DEPLOYMENT_API_VERSION = "pajin.dev/capability-graph-worker-deployment/v1alpha1"
_MAX_DEPLOYMENT_BYTES = 8 * 1024 * 1024
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"


class CapabilityGraphDeploymentError(RuntimeError):
    """Raised when Worker deployment authority cannot be established safely."""


class CapabilityGraphCompilerIdentity(StrictModel):
    """Exact compiler identity already pinned by the durable Graph Permit Store."""

    compiler_id: str = Field(
        alias="compilerId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    compiler_version: str = Field(
        alias="compilerVersion",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    compiler_digest: str = Field(
        alias="compilerDigest",
        pattern=r"^[a-f0-9]{64}$",
    )


class CapabilityGraphWorkerDeployment(StrictModel):
    """Out-of-band, digest-pinned authority admitted when the Worker starts."""

    api_version: str = Field(
        default=CAPABILITY_GRAPH_DEPLOYMENT_API_VERSION,
        alias="apiVersion",
        pattern=r"^pajin\.dev/capability-graph-worker-deployment/v1alpha1$",
    )
    kind: str = Field(
        default="CapabilityGraphWorkerDeployment",
        pattern=r"^CapabilityGraphWorkerDeployment$",
    )
    deployment_id: str = Field(
        alias="deploymentId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    campaign: CampaignManifest
    campaign_digest: str = Field(
        alias="campaignDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    mission_envelope: MissionEnvelope = Field(alias="missionEnvelope")
    lifecycle_policy: CapabilityLifecyclePolicy = Field(alias="lifecyclePolicy")
    trust_keys: tuple[CapabilityLifecycleTrustKey, ...] = Field(
        alias="trustKeys",
        min_length=2,
        max_length=32,
    )
    releases: tuple[CapabilityReleaseBundle, ...] = Field(
        min_length=7,
        max_length=7,
    )
    activated_releases: tuple[CapabilityReleaseRef, ...] = Field(
        alias="activatedReleases",
        min_length=1,
        max_length=7,
    )
    profile: CapabilityUseProfile
    release_set_digest: str = Field(
        alias="releaseSetDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    activation_set_digest: str = Field(
        alias="activationSetDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    graph_database: str = Field(alias="graphDatabase", min_length=1, max_length=4_096)
    run_root: str = Field(alias="runRoot", min_length=1, max_length=4_096)
    compiler: CapabilityGraphCompilerIdentity
    permit_ttl_seconds: int = Field(
        default=30,
        alias="permitTtlSeconds",
        strict=True,
        ge=1,
        le=300,
    )

    @field_validator("graph_database", "run_root")
    @classmethod
    def require_absolute_state_path(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute() or path == Path(path.anchor):
            raise ValueError(
                "Capability Graph deployment state paths must be bounded absolute paths"
            )
        return str(path)

    @model_validator(mode="after")
    def bind_campaign_and_state_roots(self) -> CapabilityGraphWorkerDeployment:
        if capability_graph_campaign_digest(self.campaign) != self.campaign_digest:
            raise ValueError("Capability Graph deployment Campaign digest differs")
        if (
            self.mission_envelope.campaign_id != self.campaign.metadata.name
            or self.mission_envelope.source_campaign_digest != self.campaign_digest
            or (
                self.mission_envelope.compiler_id,
                self.mission_envelope.compiler_version,
                self.mission_envelope.compiler_digest,
            )
            != (
                self.compiler.compiler_id,
                self.compiler.compiler_version,
                self.compiler.compiler_digest,
            )
        ):
            raise ValueError("Capability Graph deployment MissionEnvelope authority differs")
        graph_database = Path(self.graph_database)
        run_root = Path(self.run_root)
        if graph_database == run_root or graph_database.parent == run_root:
            raise ValueError("Capability Graph database must be separated from the Run audit root")
        release_keys = [(item.release_id, item.release_digest) for item in self.activated_releases]
        if release_keys != sorted(set(release_keys)):
            raise ValueError(
                "Capability Graph activated releases must be unique and canonically sorted"
            )
        return self


@dataclass(frozen=True, slots=True)
class CapabilityGraphDeploymentRuntime:
    """Verified in-process objects; Jobs can select inputs but not runtime code."""

    deployment: CapabilityGraphWorkerDeployment
    activation: ExistingModeCapabilityActivation
    tools: ToolRegistry
    graph_store: SQLiteGraphStore
    permits: GraphActionPermitDispatcher
    clock: Callable[[], datetime]

    def open_run_store(self, run_id: str) -> RunStore:
        """Create or reopen the exact Graph Run audit directory."""

        if fullmatch(_RUN_ID_PATTERN, run_id) is None:
            raise CapabilityGraphDeploymentError(
                "Capability Graph Run ID is not a generated RunStore identifier"
            )
        if run_id != self.deployment.mission_envelope.run_id:
            raise CapabilityGraphDeploymentError(
                "Capability Graph Run differs from the deployed MissionEnvelope"
            )
        root = Path(self.deployment.run_root)
        campaign = self.deployment.campaign.metadata.name
        campaign_path = root / campaign
        run_path = campaign_path / run_id
        self._reject_linked_run_path(root, campaign_path, run_path)
        if run_path.exists():
            store = RunStore(run_id, run_path)
        else:
            try:
                store = RunStore.create(root, campaign, run_id=run_id)
            except FileExistsError:
                self._reject_linked_run_path(root, campaign_path, run_path)
                store = RunStore(run_id, run_path)
        self._ensure_run_audit_anchor(store)
        return store

    def _ensure_run_audit_anchor(self, store: RunStore) -> None:
        deployment = self.deployment
        anchor = CapabilityGraphRunAuditAnchor(
            deploymentId=deployment.deployment_id,
            campaignId=deployment.campaign.metadata.name,
            campaignDigest=deployment.campaign_digest,
            runId=store.run_id,
            envelopeId=deployment.mission_envelope.envelope_id,
            envelopeDigest=deployment.mission_envelope.envelope_digest,
            releaseSetDigest=deployment.release_set_digest,
            activationSetDigest=deployment.activation_set_digest,
            compilerId=deployment.compiler.compiler_id,
            compilerVersion=deployment.compiler.compiler_version,
            compilerDigest=deployment.compiler.compiler_digest,
        )
        try:
            store.append_unique_event(
                CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
                anchor.model_dump(mode="json", by_alias=True),
                occurred_at=self.clock(),
            )
            with suppress(RunIntegrityError):
                store.seal()
            events = load_verified_run_events(
                store.path,
                expected_run_id=store.run_id,
            )
            anchors = tuple(
                event
                for event in events
                if event.event_type == CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE
            )
            if len(anchors) != 1 or anchors[0].payload != anchor.model_dump(
                mode="json",
                by_alias=True,
            ):
                raise CapabilityGraphDeploymentError(
                    "Capability Graph Run audit anchor differs from deployment"
                )
        except CapabilityGraphDeploymentError:
            raise
        except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
            raise CapabilityGraphDeploymentError(
                "Capability Graph Run audit anchor could not be verified"
            ) from exc

    @staticmethod
    def _reject_linked_run_path(*paths: Path) -> None:
        for path in paths:
            if path.is_symlink() or path.is_junction():
                raise CapabilityGraphDeploymentError(
                    "Capability Graph Run audit path cannot contain a link boundary"
                )


def capability_graph_campaign_digest(campaign: CampaignManifest) -> str:
    """Fingerprint one canonical Campaign used by the deployment and envelope."""

    canonical = CampaignManifest.model_validate(campaign.model_dump(mode="python", by_alias=True))
    payload = canonical.model_dump(mode="json", by_alias=True)
    rules = payload["spec"]["rulesOfEngagement"]
    for field_name in (
        "allowedMethods",
        "allowedToolCategories",
        "prohibit",
        "stopOn",
    ):
        rules[field_name] = sorted(rules[field_name])
    for window in rules["testingWindows"]:
        window["days"] = sorted(window["days"])
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def load_capability_graph_deployment(
    path: Path,
    *,
    expected_sha256: str,
    clock: Callable[[], datetime] | None = None,
) -> CapabilityGraphDeploymentRuntime:
    """Load, pin, verify, and activate one organization-issued deployment."""

    if fullmatch(r"^[a-f0-9]{64}$", expected_sha256) is None:
        raise CapabilityGraphDeploymentError("Capability Graph deployment SHA-256 is malformed")
    try:
        content = read_bounded_regular_bytes(
            path,
            max_bytes=_MAX_DEPLOYMENT_BYTES,
            label="Capability Graph Worker deployment",
            require_single_link=True,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise CapabilityGraphDeploymentError(
            "Capability Graph Worker deployment could not be read safely"
        ) from exc
    observed_sha256 = sha256(content).hexdigest()
    if not hmac.compare_digest(observed_sha256, expected_sha256):
        raise CapabilityGraphDeploymentError("Capability Graph Worker deployment SHA-256 differs")
    try:
        decoded = parse_strict_json_bytes(
            content,
            label="Capability Graph Worker deployment",
            max_bytes=_MAX_DEPLOYMENT_BYTES,
            max_depth=64,
            max_nodes=100_000,
        )
        deployment = CapabilityGraphWorkerDeployment.model_validate(decoded)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CapabilityGraphDeploymentError(
            "Capability Graph Worker deployment contract is invalid"
        ) from exc

    selected_clock = clock or (lambda: datetime.now(UTC))
    try:
        tools = _existing_mode_tool_registry()
        rollout = admit_existing_mode_capability_releases(
            bundle=existing_mode_capability_bundle(tools),
            policy=deployment.lifecycle_policy,
            trust_keys=deployment.trust_keys,
            releases=deployment.releases,
            clock=selected_clock,
        )
        if rollout.release_set.release_set_digest != deployment.release_set_digest:
            raise CapabilityGraphDeploymentError("Capability Graph release-set digest differs")
        activation = activate_existing_mode_capabilities(
            rollout=rollout,
            releases=deployment.activated_releases,
            profile=deployment.profile,
        )
        if activation.activation_set.activation_set_digest != deployment.activation_set_digest:
            raise CapabilityGraphDeploymentError("Capability Graph activation-set digest differs")
        activated_capabilities = {
            item.action_capability.reference() for item in activation.activation_set.bindings
        }
        if set(deployment.mission_envelope.allowed_capabilities) != activated_capabilities:
            raise CapabilityGraphDeploymentError(
                "Capability Graph MissionEnvelope differs from the activated Capability set"
            )
        graph_store = SQLiteGraphStore(
            Path(deployment.graph_database),
            campaign_id=deployment.campaign.metadata.name,
        )
        compiler = deployment.compiler
        authority = GraphActionPermitAuthority(
            campaign_id=deployment.campaign.metadata.name,
            compiler_id=compiler.compiler_id,
            compiler_version=compiler.compiler_version,
            compiler_digest=compiler.compiler_digest,
            capabilities=activation.action_registry(),
            permit_store=graph_store.permit_store,
            clock=selected_clock,
            permit_ttl=timedelta(seconds=deployment.permit_ttl_seconds),
        )
    except CapabilityGraphDeploymentError:
        raise
    except Exception as exc:
        raise CapabilityGraphDeploymentError(
            "Capability Graph Worker deployment authority failed verification"
        ) from exc
    return CapabilityGraphDeploymentRuntime(
        deployment=deployment,
        activation=activation,
        tools=tools,
        graph_store=graph_store,
        permits=GraphActionPermitDispatcher(authority),
        clock=selected_clock,
    )


def _existing_mode_tool_registry() -> ToolRegistry:
    """Build the closed CAP-005 Tool inventory without plugin discovery."""

    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
    ):
        tools.register(tool)
    return tools
