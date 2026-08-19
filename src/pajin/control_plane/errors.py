"""Stable application errors shared by Control Plane collaborators."""

from __future__ import annotations


class ControlPlaneError(RuntimeError):
    """Base class for expected Control Plane errors."""


class AuthorizationDenied(ControlPlaneError):
    """Authenticated principal was denied by deployment authorization policy."""


class ResourceNotFound(ControlPlaneError):
    pass


class StateConflict(ControlPlaneError):
    pass


class ReplayExecutorRejected(StateConflict):
    """Authenticated principal is not authorized for the selected Replay executor."""


class RunCancelled(StateConflict):
    """Signal that an active Worker must stop because its Run was cancelled."""


class LeaseRejected(ControlPlaneError):
    pass
