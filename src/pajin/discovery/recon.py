"""One bounded Recon wave that feeds trusted Surface admission."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from re import fullmatch
from typing import Literal, Protocol, cast

from pydantic import Field, model_validator

from pajin.discovery.adapters import DiscoveryAdapterReference, DiscoverySurfaceKind
from pajin.discovery.admission import (
    SurfaceCandidate,
    TrustedSurfaceAdmission,
    TrustedSurfaceProducer,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import AttackSurfaceSet, tool_interface_surface_locator
from pajin.discovery.projection import (
    SurfaceProjectionPublication,
    publish_surface_projection,
)
from pajin.domain.models import CampaignManifest, StrictModel, ToolRequest, ToolResult
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController, BudgetExceeded, ExecutionCancellationContext
from pajin.runtime.error_safety import audit_safe_exception_type
from pajin.runtime.store import RunStore
from pajin.runtime.worker import WorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger, ToolGateway
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import RegisteredMCPDiscoveryTool, RegisteredMCPTool
from pajin.workflow.cancellation import (
    await_with_campaign_deadline,
    ensure_cancellation_context,
    record_engine_cleanup,
)

RECON_API_VERSION = "pajin.dev/discovery-recon/v1alpha1"
_PLANNER_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_MAX_RECON_ARGUMENT_BYTES = 1_000_000


class ReconWaveError(RuntimeError):
    """Raised when a Recon wave cannot complete its fail-closed contract."""


class ReconWavePlan(StrictModel):
    """Canonical plan for exactly one non-recursive Recon specialist wave."""

    api_version: Literal["pajin.dev/discovery-recon/v1alpha1"] = Field(
        default="pajin.dev/discovery-recon/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ReconWavePlan"] = "ReconWavePlan"
    planner_id: str = Field(
        alias="plannerId",
        min_length=1,
        max_length=160,
        pattern=_PLANNER_ID_PATTERN,
    )
    target_id: str = Field(alias="targetId", min_length=1, max_length=200)
    request: ToolRequest
    adapter_reference: DiscoveryAdapterReference | None = Field(
        default=None,
        alias="adapterReference",
    )
    required_surface_kinds: tuple[DiscoverySurfaceKind, ...] = Field(
        default=(),
        alias="requiredSurfaceKinds",
        max_length=20,
    )
    max_tool_calls: Literal[1] = Field(default=1, alias="maxToolCalls")
    stop_condition: Literal["single-wave-complete"] = Field(
        default="single-wave-complete",
        alias="stopCondition",
    )

    @model_validator(mode="after")
    def bind_specialist_identity(self) -> ReconWavePlan:
        expected = f"recon-specialist:{self.planner_id}"
        if self.request.agent_id != expected:
            raise ValueError("Recon request is not bound to its planned specialist")
        if tuple(self.required_surface_kinds) != tuple(sorted(set(self.required_surface_kinds))):
            raise ValueError("required Recon Surface kinds must be unique and sorted")
        if self.adapter_reference is None and self.required_surface_kinds:
            raise ValueError("required Recon Surface kinds require an exact adapter reference")
        return self


class ReconPlanner(Protocol):
    """Code-owned planner for one bounded Recon request."""

    planner_id: str

    def plan(self, campaign: CampaignManifest) -> ReconWavePlan:
        """Return exactly one Recon request for a declared Campaign target."""


class HTTPFileUploadReconPlanner:
    """Plan one exact HTTP GET that must publish a file-upload Surface."""

    planner_id = "pajin.walk.file-upload-recon.v1"

    def __init__(
        self,
        *,
        tool: HTTPGetTool,
        target_id: str,
        adapter_reference: DiscoveryAdapterReference,
    ) -> None:
        if not isinstance(tool, HTTPGetTool):
            raise TypeError("file-upload Recon planner requires an HTTPGetTool")
        if not isinstance(target_id, str) or not target_id:
            raise ValueError("file-upload Recon planner requires a target ID")
        try:
            reference = DiscoveryAdapterReference.model_validate(
                adapter_reference.model_dump(mode="python", by_alias=True)
            )
        except (AttributeError, ValueError) as exc:
            raise ValueError(
                "file-upload Recon planner requires an exact adapter reference"
            ) from exc
        expected_adapter_id = f"pajin.discovery.http-openapi-file-upload:{tool.spec.tool_id}"
        if reference.adapter_id != expected_adapter_id or reference.adapter_version != "1.0.0":
            raise ValueError("file-upload Recon planner requires the DISC-003B adapter")
        self._tool_id = tool.spec.tool_id
        self._tool_version = tool.spec.version
        self._target_id = target_id
        self._adapter_reference = reference

    def plan(self, campaign: CampaignManifest) -> ReconWavePlan:
        targets = [target for target in campaign.spec.targets if target.id == self._target_id]
        if len(targets) != 1:
            raise ReconWaveError("file-upload Recon planner target is not declared exactly once")
        target = targets[0]
        request_digest = discovery_digest(
            "pajin.discovery.recon-request/v1",
            {
                "campaign": campaign.metadata.name,
                "targetId": target.id,
                "target": target.endpoint,
                "toolId": self._tool_id,
                "toolVersion": self._tool_version,
                "method": "GET",
                "arguments": {},
                "adapterReference": self._adapter_reference.model_dump(
                    mode="json",
                    by_alias=True,
                ),
                "requiredSurfaceKinds": ["http-file-upload"],
            },
        )
        return ReconWavePlan(
            plannerId=self.planner_id,
            targetId=target.id,
            request=ToolRequest(
                request_id=f"recon_{request_digest[:32]}",
                agent_id=f"recon-specialist:{self.planner_id}",
                tool_id=self._tool_id,
                target=target.endpoint,
                method="GET",
                arguments={},
            ),
            adapterReference=self._adapter_reference.model_copy(deep=True),
            requiredSurfaceKinds=("http-file-upload",),
        )


class HTTPRAGInjectionReconPlanner:
    """Plan one exact HTTP GET for co-admitted upload and RAG Surfaces."""

    planner_id = "pajin.walk.rag-injection-recon.v1"

    def __init__(
        self,
        *,
        tool: HTTPGetTool,
        target_id: str,
        adapter_reference: DiscoveryAdapterReference,
    ) -> None:
        if not isinstance(tool, HTTPGetTool):
            raise TypeError("RAG-injection Recon planner requires an HTTPGetTool")
        if not isinstance(target_id, str) or not target_id:
            raise ValueError("RAG-injection Recon planner requires a target ID")
        try:
            reference = DiscoveryAdapterReference.model_validate(
                adapter_reference.model_dump(mode="python", by_alias=True)
            )
        except (AttributeError, ValueError) as exc:
            raise ValueError(
                "RAG-injection Recon planner requires an exact adapter reference"
            ) from exc
        expected_adapter_id = f"pajin.discovery.http-openapi-rag:{tool.spec.tool_id}"
        if reference.adapter_id != expected_adapter_id or reference.adapter_version != "1.0.0":
            raise ValueError("RAG-injection Recon planner requires the DISC-003C adapter")
        self._tool_id = tool.spec.tool_id
        self._tool_version = tool.spec.version
        self._target_id = target_id
        self._adapter_reference = reference

    def plan(self, campaign: CampaignManifest) -> ReconWavePlan:
        targets = [target for target in campaign.spec.targets if target.id == self._target_id]
        if len(targets) != 1:
            raise ReconWaveError("RAG-injection Recon planner target is not declared exactly once")
        target = targets[0]
        required_surface_kinds: tuple[DiscoverySurfaceKind, ...] = (
            "http-file-upload",
            "http-rag",
        )
        request_digest = discovery_digest(
            "pajin.discovery.recon-request/v1",
            {
                "campaign": campaign.metadata.name,
                "targetId": target.id,
                "target": target.endpoint,
                "toolId": self._tool_id,
                "toolVersion": self._tool_version,
                "method": "GET",
                "arguments": {},
                "adapterReference": self._adapter_reference.model_dump(
                    mode="json",
                    by_alias=True,
                ),
                "requiredSurfaceKinds": list(required_surface_kinds),
            },
        )
        return ReconWavePlan(
            plannerId=self.planner_id,
            targetId=target.id,
            request=ToolRequest(
                request_id=f"recon_{request_digest[:32]}",
                agent_id=f"recon-specialist:{self.planner_id}",
                tool_id=self._tool_id,
                target=target.endpoint,
                method="GET",
                arguments={},
            ),
            adapterReference=self._adapter_reference.model_copy(deep=True),
            requiredSurfaceKinds=required_surface_kinds,
        )


class RegisteredMCPReconPlanner:
    """Plan one deterministic call to a code-registered local MCP interface."""

    planner_id = "pajin.discovery.mcp-interface-recon.v1"

    def __init__(
        self,
        *,
        tool: RegisteredMCPTool,
        target_id: str,
        arguments: Mapping[str, object],
    ) -> None:
        if not isinstance(tool, RegisteredMCPTool):
            raise TypeError("registered MCP Recon planner requires a RegisteredMCPTool")
        if not isinstance(target_id, str) or not target_id:
            raise ValueError("registered MCP Recon planner requires a target ID")
        try:
            encoded = canonical_json_bytes(
                dict(arguments),
                label="registered MCP Recon arguments",
                max_bytes=_MAX_RECON_ARGUMENT_BYTES,
            )
            canonical_arguments = json.loads(encoded)
        except (RecursionError, TypeError, ValueError) as exc:
            raise ValueError("registered MCP Recon arguments must be bounded JSON") from exc
        if not isinstance(canonical_arguments, dict):
            raise ValueError("registered MCP Recon arguments must be an object")
        self._tool_id = tool.spec.tool_id
        self._tool_version = tool.spec.version
        self._target_id = target_id
        self._arguments = cast(dict[str, object], canonical_arguments)

    def plan(self, campaign: CampaignManifest) -> ReconWavePlan:
        targets = [target for target in campaign.spec.targets if target.id == self._target_id]
        if len(targets) != 1:
            raise ReconWaveError("Recon planner target is not declared exactly once")
        target = targets[0]
        request_digest = discovery_digest(
            "pajin.discovery.recon-request/v1",
            {
                "campaign": campaign.metadata.name,
                "targetId": target.id,
                "target": target.endpoint,
                "toolId": self._tool_id,
                "toolVersion": self._tool_version,
                "method": "POST",
                "arguments": self._arguments,
            },
        )
        return ReconWavePlan(
            plannerId=self.planner_id,
            targetId=target.id,
            request=ToolRequest(
                request_id=f"recon_{request_digest[:32]}",
                agent_id=f"recon-specialist:{self.planner_id}",
                tool_id=self._tool_id,
                target=target.endpoint,
                method="POST",
                arguments=json.loads(json.dumps(self._arguments)),
            ),
        )


class RegisteredMCPBoundaryReconPlanner:
    """Plan one argument-free enumeration of a code-registered MCP server."""

    planner_id = "pajin.discovery.mcp-boundary-recon.v1"

    def __init__(
        self,
        *,
        tool: RegisteredMCPDiscoveryTool,
        target_id: str,
    ) -> None:
        if not isinstance(tool, RegisteredMCPDiscoveryTool):
            raise TypeError("registered MCP boundary planner requires a RegisteredMCPDiscoveryTool")
        if not isinstance(target_id, str) or not target_id:
            raise ValueError("registered MCP boundary planner requires a target ID")
        self._tool_id = tool.spec.tool_id
        self._tool_version = tool.spec.version
        self._target_id = target_id

    def plan(self, campaign: CampaignManifest) -> ReconWavePlan:
        targets = [target for target in campaign.spec.targets if target.id == self._target_id]
        if len(targets) != 1:
            raise ReconWaveError("Recon planner target is not declared exactly once")
        target = targets[0]
        request_digest = discovery_digest(
            "pajin.discovery.recon-request/v1",
            {
                "campaign": campaign.metadata.name,
                "targetId": target.id,
                "target": target.endpoint,
                "toolId": self._tool_id,
                "toolVersion": self._tool_version,
                "method": "POST",
                "arguments": {},
            },
        )
        return ReconWavePlan(
            plannerId=self.planner_id,
            targetId=target.id,
            request=ToolRequest(
                request_id=f"recon_{request_digest[:32]}",
                agent_id=f"recon-specialist:{self.planner_id}",
                tool_id=self._tool_id,
                target=target.endpoint,
                method="POST",
                arguments={},
            ),
        )


class MCPInterfaceSurfaceAdapter:
    """Admit only the exact MCP interface identity returned by a registered Tool."""

    def __init__(self, *, tool: RegisteredMCPTool, input_schema_digest: str) -> None:
        if not isinstance(tool, RegisteredMCPTool):
            raise TypeError("MCP Surface adapter requires a RegisteredMCPTool")
        if fullmatch(_SHA256_PATTERN, input_schema_digest) is None:
            raise ValueError("MCP input schema digest must be lowercase SHA-256")
        registration = tool.registration
        self.tool_id = tool.spec.tool_id
        self.adapter_id = f"pajin.discovery.mcp-interface:{self.tool_id}"
        self.adapter_version = "1.0.0"
        self.producer_id = f"pajin.discovery.mcp-interface.v1:{self.tool_id}"
        self.supported_surface_kinds: tuple[DiscoverySurfaceKind, ...] = ("tool-interface",)
        self.requires_trusted_network_receipt = False
        self._tool_version = tool.spec.version
        self._registry_id = registration.server_id
        self._remote_tool_id = registration.remote_tool_name
        self._input_schema_digest = input_schema_digest

    def stable_execution_context(self) -> Mapping[str, object]:
        """Bind every non-secret MCP identity used to interpret Tool results."""

        return {
            "toolId": self.tool_id,
            "toolVersion": self._tool_version,
            "registryId": self._registry_id,
            "remoteToolId": self._remote_tool_id,
            "inputSchemaDigest": self._input_schema_digest,
        }

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> list[SurfaceCandidate]:
        if (
            request.tool_id != self.tool_id
            or result.tool_id != self.tool_id
            or result.request_id != request.request_id
            or request.method != "POST"
            or not result.success
            or result.error is not None
        ):
            raise ValueError("MCP Recon result identity is invalid")
        data = result.data
        if (
            data.get("target") != request.target
            or data.get("mcpServerId") != self._registry_id
            or data.get("mcpToolName") != self._remote_tool_id
            or not isinstance(data.get("mcpContent"), list)
        ):
            raise ValueError("MCP Recon result differs from its registered interface")
        return [
            SurfaceCandidate(
                locator=tool_interface_surface_locator(
                    registry_id=self._registry_id,
                    tool_id=self._remote_tool_id,
                    tool_version=self._tool_version,
                    input_schema_digest=self._input_schema_digest,
                ),
                confidence=1.0,
            )
        ]


@dataclass(frozen=True, slots=True)
class ReconWaveOutcome:
    """Verified result of one source Run, admission, and projection Run."""

    source_run_id: str
    source_run_path: Path
    projection_run_path: Path
    plan: ReconWavePlan
    tool_result: ToolResult
    surface_set: AttackSurfaceSet
    publication: SurfaceProjectionPublication


@dataclass(slots=True)
class _ReconSourceState:
    budget: BudgetController
    rate_limits: RequestRateLimitLedger
    ledger: CapabilityLedger | None = None
    stage: str = "initialization"
    terminalized: bool = False


class SingleReconWaveRunner:
    """Execute, seal, admit, and publish exactly one opt-in Recon request."""

    def __init__(
        self,
        *,
        planner: ReconPlanner,
        producer: TrustedSurfaceProducer,
        tools: ToolRegistry,
        policy: PolicyEngine,
        worker: WorkerBackend,
        output_root: Path,
    ) -> None:
        planner_id = getattr(planner, "planner_id", None)
        if not isinstance(planner_id, str) or fullmatch(_PLANNER_ID_PATTERN, planner_id) is None:
            raise ValueError("Recon planner identity is invalid")
        self._planner = planner
        self._producer = producer
        self._tools = tools
        self._policy = policy
        self._worker = worker
        self._output_root = output_root

    async def run(
        self,
        campaign: CampaignManifest,
        *,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> ReconWaveOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="python", by_alias=True)
        )
        if budget is not None and budget.budgets != authoritative_campaign.spec.budgets:
            raise ValueError("shared budget does not match the Campaign budget contract")
        if cancellation is not None and cancellation.binding is not None:
            raise ValueError("execution cancellation context is already bound to another Run")
        budget = budget or BudgetController(authoritative_campaign.spec.budgets)
        rate_limits = rate_limits or RequestRateLimitLedger()
        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        run_cancellation = (
            cancellation.fork_for_run(
                engine="single-recon-wave",
                run_id=store.run_id,
                path=store.path,
            )
            if cancellation is not None
            else None
        )
        state = _ReconSourceState(budget=budget, rate_limits=rate_limits)
        try:
            plan, result, evidence_reference = await await_with_campaign_deadline(
                self._execute_source(authoritative_campaign, store, state),
                budget,
                run_cancellation,
            )
        except asyncio.CancelledError as exc:
            context = ensure_cancellation_context(
                run_cancellation,
                engine="single-recon-wave",
                store=store,
            )
            receipt = record_engine_cleanup(store, context)
            self._terminalize_source(
                store,
                state,
                status="cancelled",
                error_type=audit_safe_exception_type(exc),
                cancellation_receipt=receipt,
            )
            raise
        except BudgetExceeded as exc:
            self._terminalize_source(
                store,
                state,
                status="budget-exhausted",
                error_type=audit_safe_exception_type(exc),
            )
            raise
        except Exception as exc:
            self._terminalize_source(
                store,
                state,
                status="failed",
                error_type=audit_safe_exception_type(exc),
            )
            raise

        budget.check_duration()
        admission = self._producer.produce_from_run(
            store.path,
            evidence_reference=evidence_reference,
            expected_run_id=store.run_id,
            admitted_at=datetime.now(UTC),
        )
        self._validate_admission_authority(plan, admission)
        projection_store = RunStore.create(
            self._output_root,
            authoritative_campaign.metadata.name,
        )
        publication = publish_surface_projection(projection_store, admission)
        return ReconWaveOutcome(
            source_run_id=store.run_id,
            source_run_path=store.path,
            projection_run_path=projection_store.path,
            plan=plan.model_copy(deep=True),
            tool_result=result.model_copy(deep=True),
            surface_set=admission.surface_set.model_copy(deep=True),
            publication=publication,
        )

    async def _execute_source(
        self,
        campaign: CampaignManifest,
        store: RunStore,
        state: _ReconSourceState,
    ) -> tuple[ReconWavePlan, ToolResult, str]:
        store.append_event(
            "campaign.started",
            {
                "campaign": campaign.metadata.name,
                "mode": campaign.spec.mode.value,
                "purpose": "single-recon-wave",
            },
        )
        store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))

        state.stage = "recon-planning"
        proposed = self._planner.plan(campaign.model_copy(deep=True))
        plan = ReconWavePlan.model_validate(proposed.model_dump(mode="python", by_alias=True))
        self._validate_plan_authority(campaign, plan)
        store.write_json("recon-plan.json", plan.model_dump(mode="json", by_alias=True))
        store.append_event(
            "discovery.recon-plan.created",
            {
                "plannerId": plan.planner_id,
                "targetId": plan.target_id,
                "requestId": plan.request.request_id,
                "toolId": plan.request.tool_id,
                "adapterReference": (
                    plan.adapter_reference.model_dump(mode="json", by_alias=True)
                    if plan.adapter_reference is not None
                    else None
                ),
                "requiredSurfaceKinds": list(plan.required_surface_kinds),
                "maxToolCalls": plan.max_tool_calls,
                "stopCondition": plan.stop_condition,
            },
        )

        state.stage = "recon-capability-issuance"
        ledger = CapabilityLedger(max_depth=campaign.spec.budgets.max_spawn_depth)
        state.ledger = ledger
        can_delegate = campaign.spec.budgets.max_spawn_depth >= 1
        root = ledger.issue_root(
            campaign,
            subject=(
                f"recon-supervisor:{plan.planner_id}" if can_delegate else plan.request.agent_id
            ),
            tools={plan.request.tool_id},
            targets={plan.request.target},
        )
        store.append_event("capability.issued", root.model_dump(mode="json"))
        grant = root
        if can_delegate:
            grant = ledger.delegate(
                root.grant_id,
                subject=plan.request.agent_id,
                tools={plan.request.tool_id},
                targets={plan.request.target},
                max_risk_tier=root.max_risk_tier,
                max_calls=1,
            )
            store.append_event("capability.issued", grant.model_dump(mode="json"))

        gateway = ToolGateway(
            policy=self._policy,
            tools=self._tools,
            worker=self._worker,
            store=store,
            rate_limits=state.rate_limits,
        )
        state.stage = "recon-tool-execution"
        state.budget.check_tool_call()
        if not ledger.can_consume(grant.grant_id):
            raise CapabilityError("Recon capability has no remaining authorized call")
        outcome = await gateway.execute(campaign, grant, plan.request, used_calls=0)
        if outcome.executed:
            ledger.consume(grant.grant_id)
            state.budget.record_tool_call()
        result = outcome.result.model_copy(deep=True)
        if (
            not outcome.executed
            or not result.success
            or result.error is not None
            or len(result.evidence) != 1
        ):
            raise ReconWaveError("single Recon Tool call failed closed")
        evidence_reference = result.evidence[0]

        state.stage = "recon-source-finalization"
        store.append_event(
            "discovery.recon-wave.completed",
            {
                "plannerId": plan.planner_id,
                "requestId": result.request_id,
                "toolId": result.tool_id,
                "evidence": evidence_reference,
                "adapterReference": (
                    plan.adapter_reference.model_dump(mode="json", by_alias=True)
                    if plan.adapter_reference is not None
                    else None
                ),
                "requiredSurfaceKinds": list(plan.required_surface_kinds),
                "toolCalls": 1,
                "stopCondition": plan.stop_condition,
            },
        )
        self._write_source_state(
            store,
            state,
            status="completed",
            extra={"evidence": evidence_reference, "stopCondition": plan.stop_condition},
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "single-recon-wave", "evidence": evidence_reference},
        )
        state.terminalized = True
        store.seal()
        return plan, result, evidence_reference

    def _validate_plan_authority(
        self,
        campaign: CampaignManifest,
        plan: ReconWavePlan,
    ) -> None:
        if plan.planner_id != self._planner.planner_id:
            raise ReconWaveError("Recon plan identity differs from the registered planner")
        targets = [target for target in campaign.spec.targets if target.id == plan.target_id]
        if len(targets) != 1 or plan.request.target != targets[0].endpoint:
            raise ReconWaveError("Recon plan target differs from Campaign authority")
        try:
            spec = self._tools.spec(plan.request.tool_id)
        except (KeyError, ValueError) as exc:
            raise ReconWaveError("Recon plan Tool is not registered") from exc
        if spec.tool_id != plan.request.tool_id:
            raise ReconWaveError("Recon plan Tool identity is invalid")

    @staticmethod
    def _validate_admission_authority(
        plan: ReconWavePlan,
        admission: TrustedSurfaceAdmission,
    ) -> None:
        if (
            plan.adapter_reference is not None
            and admission.adapter_reference != plan.adapter_reference
        ):
            raise ReconWaveError("Recon admission adapter differs from the planned authority")
        if not plan.required_surface_kinds:
            return
        actual_kinds = {surface.locator.kind for surface in admission.surface_set.surfaces}
        missing = set(plan.required_surface_kinds) - actual_kinds
        if missing:
            raise ReconWaveError("Recon admission lacks a required Surface kind")

    @staticmethod
    def _write_source_state(
        store: RunStore,
        state: _ReconSourceState,
        *,
        status: str,
        extra: dict[str, object] | None = None,
    ) -> None:
        if state.ledger is not None:
            store.write_json("capabilities.json", state.ledger.snapshot())
        store.write_json("budget.json", state.budget.snapshot())
        store.write_json("rate-limits.json", state.rate_limits.snapshot())
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": status,
                "stage": state.stage,
                "purpose": "single-recon-wave",
                **(extra or {}),
            },
        )

    def _terminalize_source(
        self,
        store: RunStore,
        state: _ReconSourceState,
        *,
        status: str,
        error_type: str,
        cancellation_receipt: str | None = None,
    ) -> None:
        if state.terminalized:
            return
        payload: dict[str, object] = {
            "stage": state.stage,
            "errorType": error_type,
            "purpose": "single-recon-wave",
        }
        extra: dict[str, object] = {"errorType": error_type}
        if cancellation_receipt is not None:
            payload["cancellationReceipt"] = cancellation_receipt
            extra["cancellationReceipt"] = cancellation_receipt
        self._write_source_state(store, state, status=status, extra=extra)
        store.append_event(f"campaign.{status}", payload)
        store.seal()
        state.terminalized = True
