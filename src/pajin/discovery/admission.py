"""Trusted admission from sealed Recon evidence into non-executable Surfaces."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from hashlib import sha256
from itertools import islice
from pathlib import Path, PurePosixPath
from re import fullmatch, sub
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

from pydantic import TypeAdapter

from pajin.discovery.adapters import (
    DiscoveryAdapterError,
    DiscoveryAdapterReference,
    DiscoveryAdapterRegistry,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import (
    AttackSurface,
    AttackSurfaceSet,
    HTTPAuthenticationSurfaceLocator,
    HTTPRouteSurfaceLocator,
    HTTPSurfaceLocator,
    SurfaceEvidenceReference,
    SurfaceLocator,
    SurfaceObservation,
    attack_surface,
    attack_surface_set,
    http_route_path_template,
    http_route_scope_url,
    surface_observation,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolResult
from pajin.policy.engine import PolicyDecision
from pajin.policy.scope import (
    InvalidScopeURL,
    normalize_scope_pattern,
    normalize_target_url,
    scope_matches,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    AuditEvent,
    RunIntegrityVerification,
    SealedArtifact,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)
from pajin.runtime.worker import WorkerResult
from pajin.tools.base import ToolRegistry, ToolSpec

_MAX_CAMPAIGN_BYTES = 1024 * 1024
_MAX_GATEWAY_EVIDENCE_BYTES = 16 * 1024 * 1024
_MAX_ADAPTER_SURFACES = 500
_PRODUCER_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_GATEWAY_EVIDENCE_FIELDS = frozenset(
    {
        "request",
        "policyDecision",
        "result",
        "networkLogTrusted",
        "workerJob",
        "workerResult",
        "secretLeases",
    }
)
_SURFACE_LOCATOR_ADAPTER: TypeAdapter[SurfaceLocator] = TypeAdapter(SurfaceLocator)
_ADMISSION_AUTHORITY = object()


class SurfaceAdmissionError(ValueError):
    """Raised when sealed discovery evidence cannot be admitted safely."""


@dataclass(frozen=True, slots=True)
class SurfaceCandidate:
    """One non-authoritative candidate returned by a trusted result adapter."""

    locator: SurfaceLocator
    confidence: float


class TrustedSurfaceAdapter(Protocol):
    """Code-owned interpreter for one registered Recon Tool result contract."""

    producer_id: str
    tool_id: str

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Sequence[SurfaceCandidate]:
        """Return bounded candidates derived only from the supplied Tool result."""


@dataclass(frozen=True, slots=True)
class TrustedSurfaceAdmission:
    """Process-local authority proving a Surface Set passed trusted admission."""

    producer_id: str
    source_tool_spec: ToolSpec
    source_run_path: Path
    source_verification: RunIntegrityVerification
    evidence_reference: str
    surface_set: AttackSurfaceSet
    authority_digest: str
    _authority: object
    adapter_reference: DiscoveryAdapterReference | None = None

    def require_valid_authority(self) -> None:
        """Reject serialized, copied, or post-admission-mutated authority objects."""

        if self._authority is not _ADMISSION_AUTHORITY:
            raise SurfaceAdmissionError("Surface projection requires trusted admission authority")
        expected = _trusted_admission_digest(
            producer_id=self.producer_id,
            source_tool_spec=self.source_tool_spec,
            source_run_path=self.source_run_path,
            source_verification=self.source_verification,
            evidence_reference=self.evidence_reference,
            surface_set=self.surface_set,
            adapter_reference=self.adapter_reference,
        )
        if self.authority_digest != expected:
            raise SurfaceAdmissionError("trusted Surface admission authority was mutated")


class TrustedSurfaceProducer:
    """Produce admitted Surface Sets only from verified Gateway evidence.

    Adapters are registered by application code at construction time. The public
    production path accepts no caller-supplied Surface or locator object.
    """

    def __init__(
        self,
        *,
        tools: ToolRegistry,
        adapters: Iterable[TrustedSurfaceAdapter],
    ) -> None:
        self._tools = tools
        self._adapters: dict[str, TrustedSurfaceAdapter] = {}
        self._tool_specs: dict[str, ToolSpec] = {}
        self._adapter_network_receipt_requirements: dict[str, bool] = {}
        self._adapter_registry: DiscoveryAdapterRegistry | None = None
        self._adapter_references: dict[str, DiscoveryAdapterReference] = {}
        for adapter in adapters:
            self._register_adapter(adapter)
        if not self._adapters:
            raise ValueError("Trusted Surface Producer requires at least one adapter")

    @classmethod
    def from_adapter_registry(
        cls,
        *,
        tools: ToolRegistry,
        registry: DiscoveryAdapterRegistry,
        adapter_references: Iterable[DiscoveryAdapterReference],
    ) -> TrustedSurfaceProducer:
        """Construct an exact-version producer from one shared authority registry."""

        registry.require_tool_registry(tools)
        selected = registry.select(adapter_references)
        producer = cls(
            tools=tools,
            adapters=(registered.adapter for registered in selected),
        )
        producer._adapter_registry = registry
        producer._adapter_references = {
            registered.definition.tool.tool_id: registered.definition.reference()
            for registered in selected
        }
        return producer

    def produce_from_run(
        self,
        run_path: Path,
        *,
        evidence_reference: str,
        expected_run_id: str | None = None,
        admitted_at: datetime | None = None,
    ) -> TrustedSurfaceAdmission:
        """Load one sealed Gateway record and admit its derived Surface candidates."""

        reference = _validated_gateway_evidence_reference(evidence_reference)
        try:
            snapshot = load_verified_run_artifacts(
                run_path,
                requests={
                    "campaign.json": _MAX_CAMPAIGN_BYTES,
                    reference: _MAX_GATEWAY_EVIDENCE_BYTES,
                },
                expected_run_id=expected_run_id,
            )
            campaign = _load_campaign(snapshot)
            (
                request,
                result,
                recorded_decision,
                network_log_trusted,
                worker_result,
            ) = _load_gateway_record(snapshot, reference)
            evidence_record = _sealed_artifact(snapshot, reference)
            self._validate_source_events(
                snapshot,
                campaign=campaign,
                request=request,
                result=result,
                decision=recorded_decision,
                evidence_reference=reference,
            )
            (
                adapter,
                tool_spec,
                adapter_reference,
                supported_surface_kinds,
                requires_trusted_network_receipt,
            ) = self._trusted_adapter(request.tool_id)
            evaluated_at = _normalize_admission_time(admitted_at)
            target_id = _admitted_target_id(campaign, request)
            _revalidate_source_authority(
                campaign,
                request=request,
                result=result,
                tool_spec=tool_spec,
                admitted_at=evaluated_at,
            )
            if requires_trusted_network_receipt:
                self._revalidate_trusted_network_execution(
                    request=request,
                    result=result,
                    worker_result=worker_result,
                    network_log_trusted=network_log_trusted,
                )
            candidates = _extract_candidates(
                adapter,
                request,
                result,
                supported_surface_kinds=supported_surface_kinds,
            )
            surface_set = _admit_candidates(
                campaign=campaign,
                snapshot=snapshot,
                request=request,
                result=result,
                target_id=target_id,
                evidence_record=evidence_record,
                evidence_reference=reference,
                candidates=candidates,
                admitted_at=evaluated_at,
            )
            return _trusted_admission(
                producer_id=adapter.producer_id,
                source_tool_spec=tool_spec,
                source_run_path=snapshot.run_path,
                source_verification=snapshot.verification,
                evidence_reference=reference,
                surface_set=surface_set,
                adapter_reference=adapter_reference,
            )
        except SurfaceAdmissionError:
            raise
        except Exception as exc:
            raise SurfaceAdmissionError(
                "sealed Recon evidence could not be admitted safely"
            ) from exc

    def _register_adapter(self, adapter: TrustedSurfaceAdapter) -> None:
        producer_id = getattr(adapter, "producer_id", None)
        tool_id = getattr(adapter, "tool_id", None)
        extractor = getattr(adapter, "extract_surfaces", None)
        requires_trusted_network_receipt = getattr(
            adapter,
            "requires_trusted_network_receipt",
            False,
        )
        if (
            not isinstance(producer_id, str)
            or fullmatch(_PRODUCER_ID_PATTERN, producer_id) is None
            or not isinstance(tool_id, str)
            or fullmatch(_PRODUCER_ID_PATTERN, tool_id) is None
            or not callable(extractor)
            or type(requires_trusted_network_receipt) is not bool
        ):
            raise ValueError("Trusted Surface adapter contract is invalid")
        if tool_id in self._adapters:
            raise ValueError(f"Trusted Surface adapter already registered for Tool: {tool_id}")
        try:
            tool_spec = self._tools.spec(tool_id)
        except (KeyError, ValueError) as exc:
            raise ValueError("Trusted Surface adapter requires a registered Tool") from exc
        self._adapters[tool_id] = adapter
        self._tool_specs[tool_id] = tool_spec
        self._adapter_network_receipt_requirements[tool_id] = (
            requires_trusted_network_receipt
        )

    def _trusted_adapter(
        self,
        tool_id: str,
    ) -> tuple[
        TrustedSurfaceAdapter,
        ToolSpec,
        DiscoveryAdapterReference | None,
        frozenset[str] | None,
        bool,
    ]:
        try:
            adapter = self._adapters[tool_id]
            expected_spec = self._tool_specs[tool_id]
            current_spec = self._tools.spec(tool_id)
            requires_trusted_network_receipt = (
                self._adapter_network_receipt_requirements[tool_id]
            )
        except (KeyError, ValueError) as exc:
            raise SurfaceAdmissionError(
                "Recon result Tool has no trusted Surface adapter"
            ) from exc
        if current_spec != expected_spec:
            raise SurfaceAdmissionError("trusted Recon Tool contract changed after registration")
        if (
            getattr(adapter, "requires_trusted_network_receipt", False)
            is not requires_trusted_network_receipt
        ):
            raise SurfaceAdmissionError(
                "trusted Recon adapter receipt requirement changed after registration"
            )
        reference = self._adapter_references.get(tool_id)
        supported_surface_kinds: frozenset[str] | None = None
        if self._adapter_registry is not None:
            if reference is None:
                raise SurfaceAdmissionError(
                    "Recon result Tool has no versioned discovery adapter authority"
                )
            try:
                registered = self._adapter_registry.resolve(reference)
            except DiscoveryAdapterError as exc:
                raise SurfaceAdmissionError(
                    "versioned discovery adapter authority is unavailable or has drifted"
                ) from exc
            if (
                registered.adapter is not adapter
                or registered.definition.tool.tool_id != tool_id
                or registered.definition.tool.tool_version != current_spec.version
            ):
                raise SurfaceAdmissionError(
                    "versioned discovery adapter differs from its trusted registration"
                )
            supported_surface_kinds = frozenset(registered.definition.supported_surface_kinds)
            if (
                registered.definition.requires_trusted_network_receipt
                is not requires_trusted_network_receipt
            ):
                raise SurfaceAdmissionError(
                    "versioned discovery adapter receipt requirement differs from registration"
                )
        return (
            adapter,
            current_spec,
            reference,
            supported_surface_kinds,
            requires_trusted_network_receipt,
        )

    def _revalidate_trusted_network_execution(
        self,
        *,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult | None,
        network_log_trusted: bool,
    ) -> None:
        if not network_log_trusted or worker_result is None:
            raise SurfaceAdmissionError(
                "discovery adapter requires a trusted network execution receipt"
            )
        try:
            tool = self._tools.tool(request.tool_id)
            tool.validate_trusted_execution(
                request.model_copy(deep=True),
                result.model_copy(deep=True),
                worker_result.model_copy(deep=True),
                network_log_trusted=True,
            )
        except Exception as exc:
            raise SurfaceAdmissionError(
                "trusted network execution receipt does not match the discovery result"
            ) from exc

    @staticmethod
    def _validate_source_events(
        snapshot: VerifiedRunSnapshot,
        *,
        campaign: CampaignManifest,
        request: ToolRequest,
        result: ToolResult,
        decision: PolicyDecision,
        evidence_reference: str,
    ) -> None:
        started = [
            event
            for event in snapshot.events
            if event.event_type == "campaign.started"
            and event.payload.get("campaign") == campaign.metadata.name
        ]
        if len(started) != 1:
            raise SurfaceAdmissionError("source Run lacks one exact Campaign start authority")

        policy_events = [
            event
            for event in snapshot.events
            if _event_matches_request(event, "tool.policy_evaluated", request)
        ]
        completed_events = [
            event
            for event in snapshot.events
            if _event_matches_request(event, "tool.completed", request)
            and event.payload.get("success") is True
            and event.payload.get("evidence") == evidence_reference
        ]
        if len(policy_events) != 1 or len(completed_events) != 1:
            raise SurfaceAdmissionError("source Run lacks one exact Tool admission lineage")
        policy_event = policy_events[0]
        completed_event = completed_events[0]
        if policy_event.sequence >= completed_event.sequence:
            raise SurfaceAdmissionError("source Tool policy event does not predate completion")
        if (
            policy_event.payload.get("allowed") is not True
            or policy_event.payload.get("policy") != decision.policy
            or policy_event.payload.get("reason") != decision.reason
            or decision.allowed is not True
            or result.success is not True
        ):
            raise SurfaceAdmissionError("source Tool policy or completion was not allowed")


def _validated_gateway_evidence_reference(value: str) -> str:
    try:
        reference = SurfaceEvidenceReference(
            reference=value,
            sha256="0" * 64,
            media_type="application/json",
        ).reference
    except ValueError as exc:
        raise SurfaceAdmissionError("Gateway evidence reference is not portable") from exc
    path = PurePosixPath(reference)
    if len(path.parts) != 2 or path.parts[0] != "evidence" or path.suffix != ".json":
        raise SurfaceAdmissionError("Gateway evidence must be one direct JSON evidence child")
    return reference


def _load_campaign(snapshot: VerifiedRunSnapshot) -> CampaignManifest:
    try:
        value = parse_strict_json_bytes(
            snapshot.artifact_bytes("campaign.json"),
            label="sealed discovery Campaign",
            max_bytes=_MAX_CAMPAIGN_BYTES,
        )
        campaign = CampaignManifest.model_validate(value)
    except (KeyError, TypeError, ValueError) as exc:
        raise SurfaceAdmissionError("sealed discovery Campaign is invalid") from exc
    return campaign


def _load_gateway_record(
    snapshot: VerifiedRunSnapshot,
    reference: str,
) -> tuple[ToolRequest, ToolResult, PolicyDecision, bool, WorkerResult | None]:
    try:
        value = parse_strict_json_bytes(
            snapshot.artifact_bytes(reference),
            label="sealed Gateway evidence",
            max_bytes=_MAX_GATEWAY_EVIDENCE_BYTES,
        )
        if not isinstance(value, dict) or not set(value) <= _GATEWAY_EVIDENCE_FIELDS:
            raise ValueError("Gateway evidence fields are invalid")
        if not {"request", "policyDecision", "result", "networkLogTrusted"} <= set(value):
            raise ValueError("Gateway evidence fields are incomplete")
        if type(value.get("networkLogTrusted")) is not bool:
            raise ValueError("Gateway evidence network trust flag is invalid")
        request = ToolRequest.model_validate(value.get("request"))
        result = ToolResult.model_validate(value.get("result"))
        decision = PolicyDecision.model_validate(value.get("policyDecision"))
        network_log_trusted = value["networkLogTrusted"]
        worker_result_value = value.get("workerResult")
        worker_result = (
            None
            if worker_result_value is None
            else WorkerResult.model_validate(worker_result_value)
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SurfaceAdmissionError("sealed Gateway evidence contract is invalid") from exc
    if result.request_id != request.request_id or result.tool_id != request.tool_id:
        raise SurfaceAdmissionError("sealed Tool result differs from its source request")
    return request, result, decision, network_log_trusted, worker_result


def _sealed_artifact(snapshot: VerifiedRunSnapshot, reference: str) -> SealedArtifact:
    records = [
        artifact
        for seal in snapshot.seals
        for artifact in seal.artifacts
        if artifact.path == reference
    ]
    if len(records) != 1:
        raise SurfaceAdmissionError("Gateway evidence is not sealed exactly once")
    record = records[0]
    if record.media_type != "application/json":
        raise SurfaceAdmissionError("Gateway evidence media type is not JSON")
    return record


def _event_matches_request(
    event: AuditEvent,
    event_type: str,
    request: ToolRequest,
) -> bool:
    return bool(
        event.event_type == event_type
        and event.payload.get("requestId") == request.request_id
        and event.payload.get("toolId") == request.tool_id
    )


def _normalize_admission_time(value: datetime | None) -> datetime:
    evaluated_at = value or datetime.now(UTC)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise SurfaceAdmissionError("Surface admission time requires an explicit UTC offset")
    return evaluated_at.astimezone(UTC)


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SurfaceAdmissionError(f"{label} requires an explicit UTC offset")
    return value.astimezone(UTC)


def _admitted_target_id(campaign: CampaignManifest, request: ToolRequest) -> str:
    try:
        request_target = normalize_target_url(request.target)
        matches = [
            target
            for target in campaign.spec.targets
            if normalize_target_url(target.endpoint) == request_target
        ]
    except (InvalidScopeURL, ValueError) as exc:
        raise SurfaceAdmissionError("source request target cannot be bound safely") from exc
    if len(matches) != 1:
        raise SurfaceAdmissionError("source request does not bind one declared Campaign target")
    return matches[0].id


def _revalidate_source_authority(
    campaign: CampaignManifest,
    *,
    request: ToolRequest,
    result: ToolResult,
    tool_spec: ToolSpec,
    admitted_at: datetime,
) -> None:
    started_at = _aware_utc(result.started_at, label="Tool result start time")
    finished_at = _aware_utc(result.finished_at, label="Tool result finish time")
    if started_at > finished_at or finished_at > admitted_at:
        raise SurfaceAdmissionError("Tool result chronology is invalid for admission")
    if result.error is not None or not result.success:
        raise SurfaceAdmissionError("failed Tool results cannot produce admitted Surfaces")
    if not (
        campaign.spec.authorization.is_active(started_at)
        and campaign.spec.authorization.is_active(finished_at)
    ):
        raise SurfaceAdmissionError("Campaign authorization was inactive during Recon")
    windows = campaign.spec.rules_of_engagement.testing_windows
    if windows and not all(
        any(window.is_active(at) for window in windows) for at in (started_at, finished_at)
    ):
        raise SurfaceAdmissionError("Recon occurred outside the approved testing window")
    rules = campaign.spec.rules_of_engagement
    if tool_spec.tool_id != request.tool_id:
        raise SurfaceAdmissionError("registered Recon Tool differs from the source request")
    if tool_spec.risk_tier > rules.max_tool_risk_tier:
        raise SurfaceAdmissionError("Recon Tool risk exceeds Campaign authority")
    if request.method not in rules.allowed_methods:
        raise SurfaceAdmissionError("Recon request method exceeds Campaign authority")
    if rules.allowed_tool_categories and not tool_spec.categories <= rules.allowed_tool_categories:
        raise SurfaceAdmissionError("Recon Tool category is not allowlisted")
    if tool_spec.categories & rules.prohibit:
        raise SurfaceAdmissionError("Recon Tool belongs to a prohibited category")
    _require_in_scope(campaign, request.target)


def _extract_candidates(
    adapter: TrustedSurfaceAdapter,
    request: ToolRequest,
    result: ToolResult,
    *,
    supported_surface_kinds: frozenset[str] | None,
) -> list[SurfaceCandidate]:
    try:
        extracted = adapter.extract_surfaces(
            request.model_copy(deep=True),
            result.model_copy(deep=True),
        )
        candidates = list(islice(iter(extracted), _MAX_ADAPTER_SURFACES + 1))
    except Exception as exc:
        raise SurfaceAdmissionError("trusted Surface adapter rejected the Tool result") from exc
    if len(candidates) > _MAX_ADAPTER_SURFACES:
        raise SurfaceAdmissionError("trusted Surface adapter exceeded the Surface limit")
    if any(not isinstance(candidate, SurfaceCandidate) for candidate in candidates):
        raise SurfaceAdmissionError("trusted Surface adapter returned an invalid candidate")
    if supported_surface_kinds is not None and any(
        candidate.locator.kind not in supported_surface_kinds for candidate in candidates
    ):
        raise SurfaceAdmissionError(
            "versioned discovery adapter returned an undeclared Surface kind"
        )
    return candidates


def _admit_candidates(
    *,
    campaign: CampaignManifest,
    snapshot: VerifiedRunSnapshot,
    request: ToolRequest,
    result: ToolResult,
    target_id: str,
    evidence_record: SealedArtifact,
    evidence_reference: str,
    candidates: list[SurfaceCandidate],
    admitted_at: datetime,
) -> AttackSurfaceSet:
    request_digest = _canonical_sha256(request.model_dump(mode="json"))
    result_digest = _canonical_sha256(result.model_dump(mode="json"))
    evidence: list[SurfaceEvidenceReference | Mapping[str, object]] = [
        SurfaceEvidenceReference(
            reference=evidence_reference,
            sha256=evidence_record.sha256,
            media_type=evidence_record.media_type,
        )
    ]
    by_locator: dict[bytes, tuple[SurfaceLocator, float]] = {}
    for candidate in candidates:
        locator = _SURFACE_LOCATOR_ADAPTER.validate_python(candidate.locator)
        confidence = candidate.confidence
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0 <= float(confidence) <= 1
        ):
            raise SurfaceAdmissionError("Surface confidence must be a finite probability")
        _revalidate_surface_scope(campaign, locator)
        key = canonical_json_bytes(locator.model_dump(mode="json"), label="Surface locator")
        previous = by_locator.get(key)
        if previous is None or float(confidence) > previous[1]:
            by_locator[key] = (locator, float(confidence))

    observations: list[SurfaceObservation] = []
    surfaces: list[AttackSurface] = []
    for key in sorted(by_locator):
        locator, confidence = by_locator[key]
        observation = surface_observation(
            campaign=campaign.metadata.name,
            run_id=snapshot.verification.run_id,
            source_root_digest=snapshot.verification.root_digest,
            target_id=target_id,
            request_id=request.request_id,
            request_target=normalize_target_url(request.target),
            tool_id=request.tool_id,
            source_request_digest=request_digest,
            source_result_digest=result_digest,
            locator=locator,
            evidence=evidence,
            observed_at=result.finished_at,
        )
        observations.append(observation)
        surfaces.append(
            attack_surface(
                campaign=campaign.metadata.name,
                target_id=target_id,
                locator=locator,
                observations=[observation],
                confidence=confidence,
            )
        )
    return attack_surface_set(
        campaign=campaign.metadata.name,
        run_id=snapshot.verification.run_id,
        source_root_digest=snapshot.verification.root_digest,
        observations=observations,
        surfaces=surfaces,
        generated_at=admitted_at,
    )


def _revalidate_surface_scope(campaign: CampaignManifest, locator: SurfaceLocator) -> None:
    if isinstance(locator, HTTPAuthenticationSurfaceLocator):
        if locator.route.method not in campaign.spec.rules_of_engagement.allowed_methods:
            raise SurfaceAdmissionError("discovered HTTP method exceeds Campaign authority")
        _require_route_in_scope(campaign, locator.route)
        return
    if isinstance(locator, HTTPSurfaceLocator | HTTPRouteSurfaceLocator):
        if locator.method not in campaign.spec.rules_of_engagement.allowed_methods:
            raise SurfaceAdmissionError("discovered HTTP method exceeds Campaign authority")
        if isinstance(locator, HTTPSurfaceLocator):
            _require_in_scope(campaign, locator.url)
        else:
            _require_route_in_scope(campaign, locator)


def _require_route_in_scope(
    campaign: CampaignManifest,
    locator: HTTPRouteSurfaceLocator,
) -> None:
    rendered = http_route_scope_url(locator)
    template = http_route_path_template(locator)
    if "{" not in template:
        _require_in_scope(campaign, rendered)
        return
    if not any(
        _scope_allow_covers_route(rule, locator)
        for rule in campaign.spec.scope.allow
    ):
        raise SurfaceAdmissionError(
            "HTTP route template is not fully covered by Campaign allow scope"
        )
    if any(
        _scope_deny_may_overlap_route(rule, locator)
        for rule in campaign.spec.scope.deny
    ):
        raise SurfaceAdmissionError(
            "HTTP route template may overlap an explicit Campaign deny rule"
        )


def _scope_allow_covers_route(
    rule: str,
    locator: HTTPRouteSurfaceLocator,
) -> bool:
    try:
        pattern = urlsplit(normalize_scope_pattern(rule))
        base = urlsplit(locator.base_url)
    except (InvalidScopeURL, ValueError):
        return False
    if not _scope_origin_matches(pattern, base) or pattern.query:
        return False
    route_template = http_route_path_template(locator)
    route_prefix = route_template.partition("{")[0]
    pattern_path = pattern.path or "/"
    glob_indexes = [
        pattern_path.index(character)
        for character in "*?["
        if character in pattern_path
    ]
    if not glob_indexes:
        return False
    pattern_prefix = pattern_path[: min(glob_indexes)]
    if not route_prefix.startswith(pattern_prefix):
        return False
    first = http_route_scope_url(locator)
    second_path = sub(r"\{[^{}]+\}", "pajin-route-alternative", route_template)
    second = normalize_target_url(
        f"{base.scheme}://{base.netloc}{second_path}"
    )
    return scope_matches(rule, first) and scope_matches(rule, second)


def _scope_deny_may_overlap_route(
    rule: str,
    locator: HTTPRouteSurfaceLocator,
) -> bool:
    try:
        pattern = urlsplit(normalize_scope_pattern(rule))
        base = urlsplit(locator.base_url)
    except (InvalidScopeURL, ValueError):
        return True
    if not _scope_origin_matches(pattern, base) or pattern.query:
        return False
    route_template = http_route_path_template(locator)
    pattern_path = pattern.path or "/"
    if not any(character in pattern_path for character in "*?["):
        return _concrete_path_matches_route_template(pattern_path, route_template)
    if scope_matches(rule, http_route_scope_url(locator)):
        return True
    route_prefix = route_template.partition("{")[0]
    pattern_prefix = pattern_path[
        : min(
            pattern_path.index(character)
            for character in "*?["
            if character in pattern_path
        )
    ]
    return route_prefix.startswith(pattern_prefix) or pattern_prefix.startswith(
        route_prefix
    )


def _scope_origin_matches(pattern: SplitResult, target: SplitResult) -> bool:
    if pattern.scheme != target.scheme:
        return False
    pattern_host = pattern.hostname
    target_host = target.hostname
    if pattern_host is None or target_host is None:
        return False
    if pattern_host.startswith("*."):
        if not fnmatchcase(target_host, pattern_host):
            return False
    elif pattern_host != target_host:
        return False
    pattern_port = pattern.port or (443 if pattern.scheme == "https" else 80)
    target_port = target.port or (443 if target.scheme == "https" else 80)
    return pattern_port == target_port


def _concrete_path_matches_route_template(
    concrete_path: str,
    route_template: str,
) -> bool:
    concrete_segments = concrete_path.split("/")
    route_segments = route_template.split("/")
    if len(concrete_segments) != len(route_segments):
        return False
    return all(
        route_segment == concrete_segment
        or (
            route_segment.startswith("{")
            and route_segment.endswith("}")
            and bool(concrete_segment)
        )
        for concrete_segment, route_segment in zip(
            concrete_segments,
            route_segments,
            strict=True,
        )
    )


def _require_in_scope(campaign: CampaignManifest, target: str) -> None:
    try:
        if any(scope_matches(rule, target) for rule in campaign.spec.scope.deny):
            raise SurfaceAdmissionError("Surface target matches an explicit deny rule")
        if not any(scope_matches(rule, target) for rule in campaign.spec.scope.allow):
            raise SurfaceAdmissionError("Surface target is outside the Campaign allow scope")
    except InvalidScopeURL as exc:
        raise SurfaceAdmissionError("Surface target scope cannot be evaluated safely") from exc


def _canonical_sha256(value: object) -> str:
    return sha256(canonical_json_bytes(value, label="sealed discovery source")).hexdigest()


def _trusted_admission(
    *,
    producer_id: str,
    source_tool_spec: ToolSpec,
    source_run_path: Path,
    source_verification: RunIntegrityVerification,
    evidence_reference: str,
    surface_set: AttackSurfaceSet,
    adapter_reference: DiscoveryAdapterReference | None = None,
) -> TrustedSurfaceAdmission:
    trusted_set = AttackSurfaceSet.model_validate(surface_set.model_dump(mode="python"))
    trusted_verification = RunIntegrityVerification.model_validate(
        source_verification.model_dump(mode="python")
    )
    trusted_spec = ToolSpec.model_validate(source_tool_spec.model_dump(mode="python"))
    trusted_adapter_reference = (
        DiscoveryAdapterReference.model_validate(
            adapter_reference.model_dump(mode="json", by_alias=True)
        )
        if adapter_reference is not None
        else None
    )
    resolved_path = source_run_path.resolve()
    authority_digest = _trusted_admission_digest(
        producer_id=producer_id,
        source_tool_spec=trusted_spec,
        source_run_path=resolved_path,
        source_verification=trusted_verification,
        evidence_reference=evidence_reference,
        surface_set=trusted_set,
        adapter_reference=trusted_adapter_reference,
    )
    return TrustedSurfaceAdmission(
        producer_id=producer_id,
        source_tool_spec=trusted_spec,
        source_run_path=resolved_path,
        source_verification=trusted_verification,
        evidence_reference=evidence_reference,
        surface_set=trusted_set,
        authority_digest=authority_digest,
        _authority=_ADMISSION_AUTHORITY,
        adapter_reference=trusted_adapter_reference,
    )


def _trusted_admission_digest(
    *,
    producer_id: str,
    source_tool_spec: ToolSpec,
    source_run_path: Path,
    source_verification: RunIntegrityVerification,
    evidence_reference: str,
    surface_set: AttackSurfaceSet,
    adapter_reference: DiscoveryAdapterReference | None = None,
) -> str:
    return discovery_digest(
        "pajin.discovery.trusted-surface-admission/v1",
        {
            "producerId": producer_id,
            "sourceToolSpec": {
                "toolId": source_tool_spec.tool_id,
                "version": source_tool_spec.version,
                "description": source_tool_spec.description,
                "riskTier": int(source_tool_spec.risk_tier),
                "categories": sorted(source_tool_spec.categories),
                "evidenceTypes": sorted(source_tool_spec.evidence_types),
                "networkAccess": source_tool_spec.network_access,
                "networkRequestCost": source_tool_spec.network_request_cost,
                "parallelSafe": source_tool_spec.parallel_safe,
            },
            "sourceRunPath": str(source_run_path),
            "sourceVerification": source_verification.model_dump(mode="json"),
            "evidenceReference": evidence_reference,
            "adapterReference": (
                adapter_reference.model_dump(mode="json", by_alias=True)
                if adapter_reference is not None
                else None
            ),
            "surfaceSet": surface_set.model_dump(mode="json", by_alias=True),
        },
    )
