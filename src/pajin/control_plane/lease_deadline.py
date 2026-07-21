"""Conservative local monotonic deadlines for server-issued Worker leases."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

from pajin.control_plane.client import (
    ControlPlaneLocalLeaseDeadlineExceeded,
    ControlPlaneProtocolError,
)


@dataclass(slots=True)
class MonotonicLeaseDeadline:
    """Map a trusted server lease window onto one local event-loop clock."""

    expires_at: float

    @classmethod
    def from_server_timestamps(
        cls,
        *,
        lease_expires_at: datetime | None,
        lease_reference_at: datetime | None,
        requested_lease_seconds: int,
        observed_at: float,
    ) -> MonotonicLeaseDeadline:
        return cls(
            expires_at=observed_at
            + _bounded_server_lease_seconds(
                lease_expires_at=lease_expires_at,
                lease_reference_at=lease_reference_at,
                requested_lease_seconds=requested_lease_seconds,
            )
        )

    def renew_from_server_timestamps(
        self,
        *,
        lease_expires_at: datetime | None,
        lease_reference_at: datetime | None,
        requested_lease_seconds: int,
        request_started_at: float,
    ) -> None:
        # Anchor at request start, not response receipt.  The entire heartbeat
        # round trip therefore consumes the newly issued server lease window.
        self.expires_at = request_started_at + _bounded_server_lease_seconds(
            lease_expires_at=lease_expires_at,
            lease_reference_at=lease_reference_at,
            requested_lease_seconds=requested_lease_seconds,
        )

    def remaining(self) -> float:
        return self.expires_at - asyncio.get_running_loop().time()

    def require_active(self) -> None:
        if self.remaining() <= 0:
            raise ControlPlaneLocalLeaseDeadlineExceeded(
                "local lease deadline elapsed before authority was renewed"
            )

    async def wait_for_renewal_interval(self, heartbeat_seconds: float) -> None:
        remaining = self.remaining()
        if remaining <= 0:
            self.require_active()
        await asyncio.sleep(min(heartbeat_seconds, remaining))
        self.require_active()


def _bounded_server_lease_seconds(
    *,
    lease_expires_at: datetime | None,
    lease_reference_at: datetime | None,
    requested_lease_seconds: int,
) -> float:
    if lease_expires_at is None or lease_reference_at is None:
        raise ControlPlaneProtocolError(
            "Control Plane lease response omitted its server timestamps"
        )
    for timestamp in (lease_expires_at, lease_reference_at):
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ControlPlaneProtocolError(
                "Control Plane lease response used a timezone-naive timestamp"
            )
    server_window = (lease_expires_at - lease_reference_at).total_seconds()
    if server_window <= 0:
        raise ControlPlaneLocalLeaseDeadlineExceeded(
            "local lease deadline elapsed before authority was received"
        )
    return min(server_window, float(requested_lease_seconds))
