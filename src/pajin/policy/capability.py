"""Capability issuance, attenuation, revocation, and lineage accounting."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from threading import RLock

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

    def __init__(
        self,
        *,
        max_depth: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            isinstance(max_depth, bool)
            or not isinstance(max_depth, int)
            or not 0 <= max_depth <= 100
        ):
            raise ValueError("maximum capability depth must be an integer from 0 through 100")
        self._max_depth = max_depth
        self._clock = clock or (lambda: datetime.now(UTC))
        self._records: dict[str, CapabilityRecord] = {}
        self._lock = RLock()

    def issue_root(
        self,
        campaign: CampaignManifest,
        *,
        subject: str,
        tools: set[str],
        targets: set[str],
    ) -> CapabilityGrant:
        with self._lock:
            campaign_max_calls = campaign.spec.budgets.max_tool_calls
            if isinstance(campaign_max_calls, bool) or not isinstance(campaign_max_calls, int):
                raise CapabilityError("campaign tool-call authority is invalid")
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
                issued_at=self._issued_at(),
                depth=0,
            )
            self._store_grant(grant)
            return self._copy_grant(grant)

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
        with self._lock:
            if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 0:
                raise CapabilityError("child call budget must be a non-negative integer")
            parent_record = self._record(parent_grant_id)
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
                issued_at=self._issued_at(),
                depth=child_depth,
            )
            if not child.attenuates(parent):
                raise CapabilityError("child capability does not attenuate parent authority")
            self._store_grant(child)
            return self._copy_grant(child)

    def can_consume(self, grant_id: str) -> bool:
        with self._lock:
            return all(
                not record.revoked and record.remaining_calls > 0
                for record in self._lineage(grant_id)
            )

    def consume(self, grant_id: str) -> None:
        with self._lock:
            lineage = self._lineage(grant_id)
            if not all(not item.revoked and item.remaining_calls > 0 for item in lineage):
                raise CapabilityError("capability lineage has no remaining authorized call")
            for item in lineage:
                item.remaining_calls -= 1

    def revoke(self, grant_id: str, reason: str, *, cascade: bool = True) -> list[str]:
        with self._lock:
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
                raise CapabilityError(
                    "capability revocation reason must contain 1 to 500 characters"
                )
            self._record(grant_id)
            revoked: list[str] = []
            for current_id, record in self._records.items():
                selected = current_id == grant_id or (
                    cascade and self._descends_from(current_id, grant_id)
                )
                if selected and not record.revoked:
                    record.revoked = True
                    record.revoke_reason = reason
                    revoked.append(current_id)
            return revoked

    def record(self, grant_id: str) -> CapabilityRecord:
        """Return a detached observation; only the ledger may mutate live authority."""

        with self._lock:
            return self._record(grant_id).model_copy(deep=True)

    def _record(self, grant_id: str) -> CapabilityRecord:
        try:
            return self._records[grant_id]
        except KeyError as exc:
            raise CapabilityError(f"unknown capability grant: {grant_id}") from exc

    def snapshot(self) -> list[dict[str, object]]:
        with self._lock:
            return [record.model_dump(mode="json") for record in self._records.values()]

    def _lineage(self, grant_id: str) -> list[CapabilityRecord]:
        lineage: list[CapabilityRecord] = []
        current = self._record(grant_id)
        while True:
            lineage.append(current)
            parent_id = current.grant.parent_grant_id
            if parent_id is None:
                return lineage
            current = self._record(parent_id)

    def _descends_from(self, grant_id: str, ancestor_id: str) -> bool:
        current = self._record(grant_id)
        while current.grant.parent_grant_id is not None:
            if current.grant.parent_grant_id == ancestor_id:
                return True
            current = self._record(current.grant.parent_grant_id)
        return False

    def _store_grant(self, grant: CapabilityGrant) -> None:
        owned_grant = self._copy_grant(grant)
        self._records[owned_grant.grant_id] = CapabilityRecord(
            grant=owned_grant,
            remaining_calls=owned_grant.max_calls,
        )

    def _issued_at(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise CapabilityError("capability issuance clock failed") from exc
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise CapabilityError("capability issuance clock requires a UTC offset or Z")
        return value.astimezone(UTC)

    @staticmethod
    def _copy_grant(grant: CapabilityGrant) -> CapabilityGrant:
        return CapabilityGrant.model_validate(grant.model_dump(mode="python"))
