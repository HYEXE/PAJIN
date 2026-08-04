"""Shadow Supervisor contracts and authorities."""

from pajin.supervision.model_binding import (
    SUPERVISOR_MODEL_BINDING_API_VERSION,
    SUPERVISOR_SHADOW_PROPOSAL_DRAFT_API_VERSION,
    SupervisorModelBinding,
    SupervisorModelBindingError,
    SupervisorModelConfiguration,
    SupervisorModelSchemaBinding,
    SupervisorModelSchemaKind,
    SupervisorProviderModelIdentity,
    SupervisorShadowProposalDraft,
    SupervisorShadowProposalKind,
    bind_supervisor_model,
    verify_supervisor_model_binding,
)

__all__ = [
    "SUPERVISOR_MODEL_BINDING_API_VERSION",
    "SUPERVISOR_SHADOW_PROPOSAL_DRAFT_API_VERSION",
    "SupervisorModelBinding",
    "SupervisorModelBindingError",
    "SupervisorModelConfiguration",
    "SupervisorModelSchemaBinding",
    "SupervisorModelSchemaKind",
    "SupervisorProviderModelIdentity",
    "SupervisorShadowProposalDraft",
    "SupervisorShadowProposalKind",
    "bind_supervisor_model",
    "verify_supervisor_model_binding",
]
