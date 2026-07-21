"""Secret-free Control Plane failure classifications shared by Worker roles."""

from __future__ import annotations

from pajin.control_plane.client import (
    ControlPlaneAuthenticationError,
    ControlPlaneLeaseLost,
    ControlPlaneLocalLeaseDeadlineExceeded,
    ControlPlaneProtocolError,
    ControlPlaneRunCancelled,
    ControlPlaneTransientError,
)
from pajin.runtime.error_safety import audit_safe_exception_diagnostic


def control_plane_cancellation_reason(error: BaseException) -> str:
    """Map a remote/transport failure to a stable secret-free cancellation reason."""

    if isinstance(error, ControlPlaneRunCancelled):
        return "run has been cancelled"
    if isinstance(error, ControlPlaneLocalLeaseDeadlineExceeded):
        return "local Control Plane lease deadline elapsed"
    if isinstance(error, ControlPlaneLeaseLost):
        return "Control Plane lease was lost"
    if isinstance(error, ControlPlaneAuthenticationError):
        return "Control Plane authentication failed"
    if isinstance(error, ControlPlaneProtocolError):
        return "Control Plane protocol validation failed"
    if isinstance(error, ControlPlaneTransientError):
        return "Control Plane transport is unavailable"
    return "Control Plane heartbeat is unavailable"


def control_plane_status_diagnostic(error: BaseException, *, stage: str) -> str:
    """Describe a daemon failure without copying a peer-controlled response detail."""

    return audit_safe_exception_diagnostic(error, stage=stage)
