"""Explicit trusted-host composition from admitted collaboration to a pinned CP stop."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from pajin.collaboration.snapshots import CollaborationSnapshot, SharedArtifactSource
from pajin.collaboration.terminal_result import (
    TerminalResultHandoff,
    TerminalResultHandoffAuthority,
)
from pajin.collaboration.urgent_observation import UrgentObservationFastGateAuthority
from pajin.control_plane.errors import AuthorizationDenied
from pajin.control_plane.urgent_stops import (
    UrgentStopApplication,
    UrgentStopBinding,
    UrgentStopService,
)
from pajin.domain.models import CampaignManifest, campaign_manifest_digest
from pajin.graph.models import GraphNodeRef
from pajin.graph.projection import GraphSnapshotStore
from pajin.runtime.host_gate import host_work
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import load_verified_run_artifacts


class UrgentStopRuntime:
    """One deployment-bound producer. Wire metadata cannot construct this authority."""

    def __init__(
        self,
        *,
        service: UrgentStopService,
        binding: UrgentStopBinding,
        fast_gate: UrgentObservationFastGateAuthority,
        terminal_result_authority: TerminalResultHandoffAuthority,
        terminal_result: TerminalResultHandoff,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_sources: Iterable[SharedArtifactSource],
    ) -> None:
        self._service = service
        self._binding = UrgentStopBinding.model_validate(binding.model_dump(mode="python"))
        self._fast_gate = fast_gate
        self._terminal_authority = terminal_result_authority
        self._terminal = terminal_result.model_copy(deep=True)
        self._snapshot = collaboration_snapshot.model_copy(deep=True)
        self._graph_store = graph_snapshot_store
        self._sources = tuple(
            SharedArtifactSource(
                reference=source.reference.model_copy(deep=True),
                evidence=source.evidence.model_copy(deep=True),
                source_run_path=source.source_run_path,
            )
            for source in shared_artifact_sources
        )

    def admit(self, *, observation: GraphNodeRef, decided_at: datetime) -> UrgentStopApplication:
        """Validate the full admission, then commit cancellation and its human alert together."""

        with host_work():
            return self._admit(observation=observation, decided_at=decided_at)

    def _admit(self, *, observation: GraphNodeRef, decided_at: datetime) -> UrgentStopApplication:

        binding = self._binding
        result = self._terminal_authority.resolve(self._terminal)
        if (
            result.result_handoff_id != binding.terminal_handoff_id
            or result.result_handoff_digest != binding.terminal_handoff_digest
            or result.result_artifact.shared_artifact_id != binding.result_artifact_id
            or result.result_artifact.shared_artifact_digest != binding.result_artifact_digest
            or result.result_artifact.source_run_id != binding.source_run_id
            or result.result_artifact.source_root_digest != binding.source_root_digest
        ):
            raise AuthorizationDenied("Urgent stop source differs from deployment binding")
        sources = [source for source in self._sources if source.reference == result.result_artifact]
        if len(sources) != 1:
            raise AuthorizationDenied("Urgent stop requires one exact source artifact")
        sealed = load_verified_run_artifacts(
            sources[0].source_run_path,
            requests={"campaign.json": 1024 * 1024},
            expected_run_id=binding.source_run_id,
        )
        manifest = CampaignManifest.model_validate(
            parse_strict_json_bytes(
                sealed.artifact_bytes("campaign.json"),
                label="Urgent stop source Campaign",
            )
        )
        if (
            sealed.verification.root_digest != binding.source_root_digest
            or campaign_manifest_digest(manifest) != binding.campaign_digest
        ):
            raise AuthorizationDenied("Urgent stop source Campaign differs from deployment binding")
        from pajin.runtime.recovery_bindings import require_registered_producer

        require_registered_producer(
            graph_store=self._graph_store,
            sources=tuple(
                (source.source_run_path, source.reference.source_run_id,
                 source.reference.source_root_digest)
                for source in self._sources
            ),
        )
        # A fresh process reconstructs the same original decision time. It still
        # revalidates live authorities and all source inputs before reusing history.
        previous = self._service.previous(binding)
        decision = self._fast_gate.admit(
            terminal_result_authority=self._terminal_authority,
            terminal_result=self._terminal,
            collaboration_snapshot=self._snapshot,
            graph_snapshot_store=self._graph_store,
            shared_artifact_sources=self._sources,
            observation=observation,
            decided_at=previous.decision.decided_at if previous is not None else decided_at,
        )
        verified = self._fast_gate.verify(
            decision,
            terminal_result_authority=self._terminal_authority,
            terminal_result=self._terminal,
            collaboration_snapshot=self._snapshot,
            graph_snapshot_store=self._graph_store,
            shared_artifact_sources=self._sources,
            observation=observation,
        )
        if (verified.authority_id, verified.authority_digest) != (
            binding.authority_id,
            binding.authority_digest,
        ):
            raise AuthorizationDenied("Urgent stop fast gate differs from deployment binding")
        return self._service._apply_verified(binding, verified)
