"""Capability issuance, attenuation, revocation, and lineage accounting."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    ToolRiskTier,
)


class CapabilityError(ValueError):
    """Raised when a grant would increase or use unauthorized authority."""


class CapabilityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant: CapabilityGrant
    remaining_calls: int = Field(ge=0)
    revoked: bool = False
    revoke_reason: str | None = None


class CapabilityLedger:
    """Track grant lineage so a child invocation consumes every ancestor budget."""

    def __init__(self, *, max_depth: int) -> None:
        self._max_depth = max_depth
        self._records: dict[str, CapabilityRecord] = {}

    def issue_root(
        self,
        campaign: CampaignManifest,
        *,
        subject: str,
        tools: set[str],
        targets: set[str],
    ) -> CapabilityGrant:
        if self._records:
            raise CapabilityError("root capability has already been issued")
        grant = CapabilityGrant(
            subject=subject,
            campaign=campaign.metadata.name,
            tools=tools,
            targets=targets,
            max_risk_tier=campaign.spec.rules_of_engagement.max_tool_risk_tier,
            max_calls=campaign.spec.budgets.max_tool_calls,
            expires_at=campaign.spec.authorization.expires_at,
            delegable=True,
            depth=0,
        )
        self._records[grant.grant_id] = CapabilityRecord(
            grant=grant,
            remaining_calls=grant.max_calls,
        )
        return grant

    def delegate(
        self,
        parent_grant_id: str,
        *,
        subject: str,
        tools: set[str],
        targets: set[str],
        max_risk_tier: ToolRiskTier,
        max_calls: int,
        expires_at: datetime | None = None,
        delegable: bool = False,
    ) -> CapabilityGrant:
        parent_record = self.record(parent_grant_id)
        parent = parent_record.grant
        if parent_record.revoked:
            raise CapabilityError("revoked capability cannot delegate")
        child_depth = parent.depth + 1
        if child_depth > self._max_depth:
            raise CapabilityError("maximum capability delegation depth exceeded")
        if max_calls > parent_record.remaining_calls:
            raise CapabilityError("child call budget exceeds parent remaining budget")
        child = CapabilityGrant(
            parent_grant_id=parent.grant_id,
            subject=subject,
            campaign=parent.campaign,
            tools=tools,
            targets=targets,
            max_risk_tier=max_risk_tier,
            max_calls=max_calls,
            expires_at=expires_at or parent.expires_at,
            delegable=delegable,
            depth=child_depth,
        )
        if not child.attenuates(parent):
            raise CapabilityError("child capability does not attenuate parent authority")
        self._records[child.grant_id] = CapabilityRecord(
            grant=child,
            remaining_calls=child.max_calls,
        )
        return child

    def can_consume(self, grant_id: str) -> bool:
        return all(
            not record.revoked and record.remaining_calls > 0 for record in self._lineage(grant_id)
        )

    def consume(self, grant_id: str) -> None:
        lineage = self._lineage(grant_id)
        if not all(not item.revoked and item.remaining_calls > 0 for item in lineage):
            raise CapabilityError("capability lineage has no remaining authorized call")
        for item in lineage:
            item.remaining_calls -= 1

    def revoke(self, grant_id: str, reason: str, *, cascade: bool = True) -> list[str]:
        self.record(grant_id)
        revoked: list[str] = []
        for current_id, record in self._records.items():
            if current_id == grant_id or (cascade and self._descends_from(current_id, grant_id)):
                record.revoked = True
                record.revoke_reason = reason
                revoked.append(current_id)
        return revoked

    def record(self, grant_id: str) -> CapabilityRecord:
        try:
            return self._records[grant_id]
        except KeyError as exc:
            raise CapabilityError(f"unknown capability grant: {grant_id}") from exc

    def snapshot(self) -> list[dict[str, object]]:
        return [record.model_dump(mode="json") for record in self._records.values()]

    def _lineage(self, grant_id: str) -> list[CapabilityRecord]:
        lineage: list[CapabilityRecord] = []
        current = self.record(grant_id)
        while True:
            lineage.append(current)
            parent_id = current.grant.parent_grant_id
            if parent_id is None:
                return lineage
            current = self.record(parent_id)

    def _descends_from(self, grant_id: str, ancestor_id: str) -> bool:
        current = self.record(grant_id)
        while current.grant.parent_grant_id is not None:
            if current.grant.parent_grant_id == ancestor_id:
                return True
            current = self.record(current.grant.parent_grant_id)
        return False
