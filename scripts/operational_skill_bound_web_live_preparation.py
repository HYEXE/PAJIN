"""Seal one proof-bound, zero-dispatch compact WEB-007 live preparation."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

if TYPE_CHECKING or __package__:
    from scripts import operational_web_analysis as _legacy
else:  # pragma: no cover - exercised by the standalone entrypoint
    import operational_web_analysis as _legacy

from pajin.runtime.pinned_workspace import PinnedOutputRoot
from pajin.web_assessment.analysis_capacity_v2 import (
    VerifiedWebAnalysisCapacityV2Run,
    load_verified_web_analysis_capacity_v2_run,
)
from pajin.web_assessment.analysis_skill_projection import (
    VerifiedWebAnalysisSkillProjectionRun,
    build_skill_bound_web_analysis_snapshot,
    load_verified_web_analysis_skill_projection,
)
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)

_SUMMARY_API_VERSION: Final = (
    "pajin.dev/operational-compact-web-live-preparation-conformance/v1alpha1"
)
_EXPECTED_STATUS: Final = "prepared-not-authorized-no-dispatch"


class OperationalSkillBoundWebLivePreparationError(ValueError):
    """Raised when the compact live-preparation boundary fails closed."""


@dataclass(frozen=True, slots=True)
class OperationalSkillBoundWebLivePreparationResult:
    """Secret-free terminal summary and process-success classification."""

    summary: dict[str, object]
    succeeded: bool


@dataclass(frozen=True, slots=True)
class OperationalSkillBoundWebLivePreparationInputs:
    """Caller-supplied immutable Runs and independently retained anchors."""

    source_run_path: Path
    source_run_id: str
    source_root_digest: str
    skill_run_path: Path
    skill_run_id: str
    skill_root_digest: str
    capacity_run_path: Path
    capacity_run_id: str
    capacity_root_digest: str
    capacity_pin_digest: str
    capacity_proof_digest: str
    capacity_model_materialization_attestation_digest: str
    expected_transport_pin_digest: str
    output_root: Path


@dataclass(frozen=True, slots=True)
class VerifiedOperationalSkillBoundWebLivePreparationInputs:
    """Strictly reloaded immutable inputs for one inert preparation Run."""

    source: VerifiedAuthenticatedDiscoveryRun
    skill_run: VerifiedWebAnalysisSkillProjectionRun
    capacity_run: VerifiedWebAnalysisCapacityV2Run
    output_root: Path
    values: OperationalSkillBoundWebLivePreparationInputs


@dataclass(frozen=True, slots=True)
class _PreparationView:
    run_path: Path
    run_id: str
    root_digest: str
    status: str
    live_request_digest: str
    preparation_digest: str
    index_digest: str
    skill_run_id: str
    skill_root_digest: str
    capacity_run_id: str
    capacity_root_digest: str
    capacity_pin_digest: str
    capacity_proof_digest: str
    model_materialization_attestation_digest: str
    transport_pin_digest: str
    execution_state: tuple[tuple[str, bool | int], ...]


class _ExecutionStateContract(Protocol):
    def model_dump(self, *, mode: str, by_alias: bool) -> dict[str, object]: ...


class _LiveRequestContract(Protocol):
    request_digest: str
    status: str
    skill_run_id: str
    skill_run_root_digest: str
    execution_state: _ExecutionStateContract


class _PreparationContract(Protocol):
    preparation_digest: str
    status: str
    live_request_digest: str
    skill_run_id: str
    skill_run_root_digest: str
    capacity_run_id: str
    capacity_run_root_digest: str
    capacity_pin_digest: str
    capacity_proof_digest: str
    model_materialization_attestation_digest: str
    transport_pin_digest: str
    execution_state: _ExecutionStateContract


class _IndexContract(Protocol):
    index_digest: str
    status: str
    request_digest: str
    preparation_digest: str
    capacity_run_id: str
    capacity_run_root_digest: str
    capacity_pin_digest: str
    capacity_proof_digest: str
    model_materialization_attestation_digest: str
    transport_pin_digest: str
    execution_state: _ExecutionStateContract


class _PreparationRunContract(Protocol):
    run_path: Path
    run_id: str
    root_digest: str
    live_request: _LiveRequestContract
    preparation: _PreparationContract
    index: _IndexContract


@dataclass(frozen=True, slots=True)
class _PreparationApi:
    plan: Callable[..., object]
    create_run: Callable[..., object]
    load_run: Callable[..., object]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-run-path", required=True, type=Path)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--source-root-digest", required=True)
    parser.add_argument("--skill-run-path", required=True, type=Path)
    parser.add_argument("--skill-run-id", required=True)
    parser.add_argument("--skill-root-digest", required=True)
    parser.add_argument("--capacity-run-path", required=True, type=Path)
    parser.add_argument("--capacity-run-id", required=True)
    parser.add_argument("--capacity-root-digest", required=True)
    parser.add_argument("--capacity-pin-digest", required=True)
    parser.add_argument("--capacity-proof-digest", required=True)
    parser.add_argument(
        "--capacity-model-materialization-attestation-digest",
        required=True,
    )
    parser.add_argument("--expected-transport-pin-digest", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser


def _arguments(
    argv: Sequence[str] | None = None,
) -> OperationalSkillBoundWebLivePreparationInputs:
    args = _parser().parse_args(argv)
    return OperationalSkillBoundWebLivePreparationInputs(
        source_run_path=args.source_run_path,
        source_run_id=args.source_run_id,
        source_root_digest=args.source_root_digest,
        skill_run_path=args.skill_run_path,
        skill_run_id=args.skill_run_id,
        skill_root_digest=args.skill_root_digest,
        capacity_run_path=args.capacity_run_path,
        capacity_run_id=args.capacity_run_id,
        capacity_root_digest=args.capacity_root_digest,
        capacity_pin_digest=args.capacity_pin_digest,
        capacity_proof_digest=args.capacity_proof_digest,
        capacity_model_materialization_attestation_digest=(
            args.capacity_model_materialization_attestation_digest
        ),
        expected_transport_pin_digest=args.expected_transport_pin_digest,
        output_root=args.output_root,
    )


def _verify_inputs(
    values: OperationalSkillBoundWebLivePreparationInputs,
) -> VerifiedOperationalSkillBoundWebLivePreparationInputs:
    """Strictly reload source, Skill, and Capacity v2 without runtime construction."""

    try:
        output_root = _legacy._fresh_output_root(
            values.output_root,
            label="compact live preparation output root",
        )
        source = load_verified_authenticated_discovery(
            values.source_run_path,
            expected_run_id=values.source_run_id,
            expected_root_digest=values.source_root_digest,
        )
        expected_snapshot = build_skill_bound_web_analysis_snapshot(
            source,
            expected_source_run_id=values.source_run_id,
            expected_source_root_digest=values.source_root_digest,
        )
        skill_run = load_verified_web_analysis_skill_projection(
            values.skill_run_path,
            source=source,
            expected_run_id=values.skill_run_id,
            expected_root_digest=values.skill_root_digest,
            expected_source_run_id=values.source_run_id,
            expected_source_root_digest=values.source_root_digest,
            expected_registry_ref=expected_snapshot.selection_policy.registry,
            expected_policy_digest=expected_snapshot.selection_policy.policy_digest,
        )
        if skill_run.snapshot != expected_snapshot:
            raise ValueError("sealed SKILL-002 Run differs from code-owned projection")
        capacity_run = load_verified_web_analysis_capacity_v2_run(
            values.capacity_run_path,
            skill_run=skill_run,
            expected_run_id=values.capacity_run_id,
            expected_root_digest=values.capacity_root_digest,
            expected_pin_digest=values.capacity_pin_digest,
            expected_transport_pin_digest=values.expected_transport_pin_digest,
            expected_proof_digest=values.capacity_proof_digest,
            expected_model_materialization_attestation_digest=(
                values.capacity_model_materialization_attestation_digest
            ),
        )
        _require_output_outside_inputs(
            output_root,
            source_run_path=source.run_path,
            skill_run_path=skill_run.run_path,
            capacity_run_path=capacity_run.run_path,
        )
        return VerifiedOperationalSkillBoundWebLivePreparationInputs(
            source=source,
            skill_run=skill_run,
            capacity_run=capacity_run,
            output_root=output_root,
            values=values,
        )
    except OperationalSkillBoundWebLivePreparationError:
        raise
    except Exception as exc:
        raise OperationalSkillBoundWebLivePreparationError(
            "compact live-preparation inputs failed strict verification"
        ) from exc


def _require_output_outside_inputs(
    output_root: Path,
    *,
    source_run_path: Path,
    skill_run_path: Path,
    capacity_run_path: Path,
) -> None:
    inputs = tuple(
        Path(os.path.abspath(value))
        for value in (source_run_path, skill_run_path, capacity_run_path)
    )
    if any(
        output_root == value or value in output_root.parents or output_root in value.parents
        for value in inputs
    ):
        raise OperationalSkillBoundWebLivePreparationError(
            "preparation output root must be outside immutable inputs"
        )


def _reserve_fresh_output_root(path: Path) -> PinnedOutputRoot:
    try:
        return PinnedOutputRoot.create(path)
    except Exception as exc:
        raise OperationalSkillBoundWebLivePreparationError(
            "preparation output root could not be reserved"
        ) from exc


def _preparation_api() -> _PreparationApi:
    from pajin.web_assessment.analysis_skill_live_preparation import (
        _create_compact_skill_bound_web_analysis_preparation_run_in_workspace,
        _load_verified_compact_skill_bound_web_analysis_preparation_against_plan,
        plan_compact_skill_bound_web_analysis_call,
    )

    return _PreparationApi(
        plan=plan_compact_skill_bound_web_analysis_call,
        create_run=_create_compact_skill_bound_web_analysis_preparation_run_in_workspace,
        load_run=_load_verified_compact_skill_bound_web_analysis_preparation_against_plan,
    )


def _capacity_anchors(
    verified: VerifiedOperationalSkillBoundWebLivePreparationInputs,
) -> dict[str, object]:
    values = verified.values
    return {
        "skill_run": verified.skill_run,
        "capacity_run": verified.capacity_run,
        "expected_skill_run_id": values.skill_run_id,
        "expected_skill_root_digest": values.skill_root_digest,
        "expected_capacity_run_id": values.capacity_run_id,
        "expected_capacity_root_digest": values.capacity_root_digest,
        "expected_capacity_pin_digest": values.capacity_pin_digest,
        "expected_capacity_proof_digest": values.capacity_proof_digest,
        "expected_capacity_model_materialization_attestation_digest": (
            values.capacity_model_materialization_attestation_digest
        ),
        "expected_transport_pin_digest": values.expected_transport_pin_digest,
    }


def run_operational_skill_bound_web_live_preparation(
    values: OperationalSkillBoundWebLivePreparationInputs,
) -> OperationalSkillBoundWebLivePreparationResult:
    """Create and independently reload one inert, proof-bound preparation Run."""

    verified = _verify_inputs(values)
    try:
        api = _preparation_api()
        plan = api.plan(**_capacity_anchors(verified))
        pinned_output = _reserve_fresh_output_root(verified.output_root)
        with pinned_output, pinned_output.activate():
            created = api.create_run(Path("."), plan=plan)
            created_view = _preparation_view(created)
            loaded = api.load_run(
                created_view.run_path,
                expected_run_id=created_view.run_id,
                expected_root_digest=created_view.root_digest,
                expected_plan=plan,
            )
            view = _preparation_view(loaded)
            if view != created_view:
                raise OperationalSkillBoundWebLivePreparationError(
                    "strictly reloaded preparation differs from its created Run"
                )
            pinned_output.require_original_path_identity()
    except OperationalSkillBoundWebLivePreparationError:
        raise
    except Exception as exc:
        raise OperationalSkillBoundWebLivePreparationError(
            "compact live-preparation Run failed closed"
        ) from exc
    return OperationalSkillBoundWebLivePreparationResult(
        summary=_secret_free_summary(verified=verified, preparation=view),
        succeeded=True,
    )


def _state_view(state: _ExecutionStateContract) -> tuple[tuple[str, bool | int], ...]:
    raw = state.model_dump(mode="json", by_alias=True)
    values: list[tuple[str, bool | int]] = []
    for key, value in sorted(raw.items()):
        if type(value) is bool:
            if value is not False:
                raise OperationalSkillBoundWebLivePreparationError(
                    "preparation unexpectedly carries a true execution marker"
                )
        elif type(value) is int:
            if value != 0:
                raise OperationalSkillBoundWebLivePreparationError(
                    "preparation unexpectedly carries a nonzero execution count"
                )
        else:
            raise OperationalSkillBoundWebLivePreparationError(
                "preparation execution state is not literal zero/false"
            )
        values.append((key, value))
    if not values:
        raise OperationalSkillBoundWebLivePreparationError("preparation execution state is empty")
    return tuple(values)


def _preparation_view(run: object) -> _PreparationView:
    try:
        verified = cast(_PreparationRunContract, run)
        live_request = verified.live_request
        preparation = verified.preparation
        index = verified.index
        states = tuple(
            _state_view(state)
            for state in (
                live_request.execution_state,
                preparation.execution_state,
                index.execution_state,
            )
        )
        if (
            states[0] != states[1]
            or states[1] != states[2]
            or live_request.status != _EXPECTED_STATUS
            or preparation.status != _EXPECTED_STATUS
            or index.status != _EXPECTED_STATUS
            or preparation.live_request_digest != live_request.request_digest
            or index.request_digest != live_request.request_digest
            or index.preparation_digest != preparation.preparation_digest
            or preparation.skill_run_id != live_request.skill_run_id
            or preparation.skill_run_root_digest != live_request.skill_run_root_digest
            or index.capacity_run_id != preparation.capacity_run_id
            or index.capacity_run_root_digest != preparation.capacity_run_root_digest
            or index.capacity_pin_digest != preparation.capacity_pin_digest
            or index.capacity_proof_digest != preparation.capacity_proof_digest
            or index.model_materialization_attestation_digest
            != preparation.model_materialization_attestation_digest
            or index.transport_pin_digest != preparation.transport_pin_digest
        ):
            raise OperationalSkillBoundWebLivePreparationError(
                "preparation Run lineage or zero-dispatch state differs"
            )
        return _PreparationView(
            run_path=verified.run_path,
            run_id=verified.run_id,
            root_digest=verified.root_digest,
            status=preparation.status,
            live_request_digest=live_request.request_digest,
            preparation_digest=preparation.preparation_digest,
            index_digest=index.index_digest,
            skill_run_id=preparation.skill_run_id,
            skill_root_digest=preparation.skill_run_root_digest,
            capacity_run_id=preparation.capacity_run_id,
            capacity_root_digest=preparation.capacity_run_root_digest,
            capacity_pin_digest=preparation.capacity_pin_digest,
            capacity_proof_digest=preparation.capacity_proof_digest,
            model_materialization_attestation_digest=(
                preparation.model_materialization_attestation_digest
            ),
            transport_pin_digest=preparation.transport_pin_digest,
            execution_state=states[0],
        )
    except OperationalSkillBoundWebLivePreparationError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise OperationalSkillBoundWebLivePreparationError(
            "preparation Run does not expose the closed zero-dispatch contract"
        ) from exc


def _secret_free_summary(
    *,
    verified: VerifiedOperationalSkillBoundWebLivePreparationInputs,
    preparation: _PreparationView,
) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalCompactSkillBoundWebLivePreparationConformance",
        "status": preparation.status,
        "semantics": "proof-bound-zero-dispatch-live-preparation",
        "strictSourceReloaded": True,
        "strictSkillReloaded": True,
        "strictCapacityV2Reloaded": True,
        "strictPreparationReloaded": True,
        "sourceRunId": verified.values.source_run_id,
        "sourceRootDigest": verified.values.source_root_digest,
        "skillRunId": preparation.skill_run_id,
        "skillRootDigest": preparation.skill_root_digest,
        "capacityRunId": preparation.capacity_run_id,
        "capacityRootDigest": preparation.capacity_root_digest,
        "capacityPinDigest": preparation.capacity_pin_digest,
        "capacityProofDigest": preparation.capacity_proof_digest,
        "modelMaterializationAttestationDigest": (
            preparation.model_materialization_attestation_digest
        ),
        "transportPinDigest": preparation.transport_pin_digest,
        "liveRequestDigest": preparation.live_request_digest,
        "preparationDigest": preparation.preparation_digest,
        "preparationIndexDigest": preparation.index_digest,
        "preparationRunId": preparation.run_id,
        "preparationRootDigest": preparation.root_digest,
        "modelRuntimeStartCount": 0,
        "modelInvocationCount": 0,
        "providerDispatchCount": 0,
        "targetRequestCount": 0,
        "toolRequestCount": 0,
        "actionPermitCount": 0,
        "findingCount": 0,
        "graphAdmissionCount": 0,
        "reportCount": 0,
        "deliveryCount": 0,
        "futureLiveCallAuthorized": False,
        "executionAuthority": False,
        "externalDeliveryPerformed": False,
    }


def _error_summary(exc: BaseException) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalCompactSkillBoundWebLivePreparationConformance",
        "status": "operational-error",
        "errorType": type(exc).__name__,
        "complete": False,
        "modelRuntimeStartCount": 0,
        "modelInvocationCount": 0,
        "providerDispatchCount": 0,
        "targetRequestCount": 0,
        "externalDeliveryPerformed": False,
        "futureLiveCallAuthorized": False,
        "executionAuthority": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run_operational_skill_bound_web_live_preparation(_arguments(argv))
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps(_error_summary(exc), sort_keys=True))
        return 2
    print(json.dumps(result.summary, sort_keys=True))
    return 0 if result.succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
