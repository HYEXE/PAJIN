"""Evidence-bound attack-surface discovery contracts."""

from pajin.discovery.models import (
    DISCOVERY_API_VERSION,
    AttackSurface,
    AttackSurfaceSet,
    HTTPSurfaceLocator,
    SurfaceEvidenceReference,
    SurfaceLocator,
    SurfaceObservation,
    ToolInterfaceSurfaceLocator,
    attack_surface,
    attack_surface_set,
    http_surface_locator,
    surface_observation,
    tool_interface_surface_locator,
)

__all__ = [
    "DISCOVERY_API_VERSION",
    "AttackSurface",
    "AttackSurfaceSet",
    "HTTPSurfaceLocator",
    "SurfaceEvidenceReference",
    "SurfaceLocator",
    "SurfaceObservation",
    "ToolInterfaceSurfaceLocator",
    "attack_surface",
    "attack_surface_set",
    "http_surface_locator",
    "surface_observation",
    "tool_interface_surface_locator",
]
