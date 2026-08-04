"""Sealed-Run adapter for non-executable Campaign Fact admission."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError

from pajin.domain.models import CampaignManifest
from pajin.graph.admission import GraphAdmissionAuthority, GraphAdmissionResult
from pajin.graph.models import CampaignFactProposal, parse_graph_proposal
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityError, VerifiedRunSnapshot, load_verified_run_artifacts

_MAX_CAMPAIGN_BYTES = 1024 * 1024
_MAX_FACT_EVIDENCE_BYTES = 1024 * 1024
_MAX_FACT_EVIDENCE_COUNT = 64


class SealedCampaignFactAdmissionError(ValueError):
    """Raised when a Campaign Fact source cannot be verified without ambiguity."""


class SealedRunCampaignFactAdapter:
    """Submit one existing CampaignFactProposal from an exact sealed Run.

    This adapter authenticates only the sealed source boundary. Producer and full
    request/Capability lineage remain independently governed by the configured
    ``GraphAdmissionAuthority``. Neither this adapter nor its result is an
    execution Capability.
    """

    def __init__(self, authority: GraphAdmissionAuthority) -> None:
        if not isinstance(authority, GraphAdmissionAuthority):
            raise TypeError("sealed Campaign Fact adapter requires GraphAdmissionAuthority")
        self._authority = authority

    def submit(
        self,
        proposal: CampaignFactProposal,
        *,
        source_run_path: Path,
    ) -> GraphAdmissionResult:
        """Verify current sealed source material, then invoke existing admission."""

        try:
            canonical = parse_graph_proposal(
                proposal.model_dump(mode="json", by_alias=True)
            )
            if not isinstance(canonical, CampaignFactProposal):
                raise ValueError("sealed Campaign Fact adapter accepts only Fact proposals")
            if len(canonical.lineage.evidence) > _MAX_FACT_EVIDENCE_COUNT:
                raise ValueError("Campaign Fact evidence count exceeds the adapter limit")

            requests = {"campaign.json": _MAX_CAMPAIGN_BYTES}
            for binding in canonical.lineage.evidence:
                if binding.reference == "campaign.json":
                    raise ValueError("Campaign authority artifact cannot be Fact evidence")
                requests[binding.reference] = _MAX_FACT_EVIDENCE_BYTES
            snapshot = load_verified_run_artifacts(
                source_run_path,
                requests=requests,
                expected_run_id=canonical.lineage.run_id,
            )
            _require_exact_campaign(snapshot, canonical.lineage.campaign_id)
            if snapshot.verification.root_digest != canonical.lineage.source_root_digest:
                raise ValueError("Campaign Fact source root is stale or substituted")
            for binding in canonical.lineage.evidence:
                observed = sha256(snapshot.artifact_bytes(binding.reference)).hexdigest()
                if observed != binding.sha256:
                    raise ValueError("Campaign Fact evidence digest differs from sealed source")
        except SealedCampaignFactAdmissionError:
            raise
        except (
            KeyError,
            OSError,
            RunIntegrityError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise SealedCampaignFactAdmissionError(
                "sealed Campaign Fact source could not be verified"
            ) from exc

        return self._authority.submit(canonical)


def _require_exact_campaign(snapshot: VerifiedRunSnapshot, campaign_id: str) -> None:
    raw = parse_strict_json_bytes(
        snapshot.artifact_bytes("campaign.json"),
        label="sealed Campaign Fact Campaign",
        max_bytes=_MAX_CAMPAIGN_BYTES,
    )
    campaign = CampaignManifest.model_validate(raw)
    if campaign.metadata.name != campaign_id:
        raise ValueError("Campaign Fact source Campaign differs from proposal")
    started = [event for event in snapshot.events if event.event_type == "campaign.started"]
    if len(started) != 1 or started[0].payload.get("campaign") != campaign_id:
        raise ValueError("Campaign Fact source lacks one exact Campaign start event")
