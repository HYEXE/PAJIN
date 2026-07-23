"""Code-registered materializers for information-only validation Controls."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from pydantic import JsonValue, model_validator

from pajin.domain.models import CampaignMode, StrictModel
from pajin.domain.validation_controls import ValidationControlKind


class MaterializedValidationControl(StrictModel):
    """One bounded argument variant produced without execution authority."""

    control_kind: ValidationControlKind
    arguments: dict[str, JsonValue]
    session_id: str
    expected_observed: bool

    @model_validator(mode="after")
    def require_expected_contrast(self) -> MaterializedValidationControl:
        expected = self.control_kind is ValidationControlKind.BASELINE
        if self.expected_observed is not expected:
            raise ValueError("materialized Control expectation differs from its kind")
        return self


class ValidationControlMaterializer(Protocol):
    """Mode-owned transformation from one trusted request to three Controls."""

    @property
    def materializer_id(self) -> str: ...

    @property
    def materializer_version(self) -> str: ...

    @property
    def mode(self) -> CampaignMode: ...

    @property
    def scenario_id(self) -> str: ...

    @property
    def tool_id(self) -> str: ...

    @property
    def scenario_digest(self) -> str: ...

    def materialize(
        self,
        original_arguments: Mapping[str, JsonValue],
        *,
        nonce: str,
    ) -> Sequence[MaterializedValidationControl]:
        """Return bounded inputs without creating a Tool request or Capability."""


@dataclass(frozen=True, slots=True)
class _RegisteredValidationControlMaterializer:
    """Immutable identity snapshot around one Mode-owned adapter."""

    adapter: ValidationControlMaterializer
    materializer_id: str
    materializer_version: str
    mode: CampaignMode
    scenario_id: str
    tool_id: str
    scenario_digest: str

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return _materializer_key(
            self.materializer_id,
            self.materializer_version,
            self.mode,
            self.scenario_id,
            self.tool_id,
        )

    def validate_adapter_identity(self) -> None:
        try:
            current = _materializer_key(
                self.adapter.materializer_id,
                self.adapter.materializer_version,
                self.adapter.mode,
                self.adapter.scenario_id,
                self.adapter.tool_id,
            )
            current_digest = self.adapter.scenario_digest
        except (AttributeError, TypeError, ValueError) as exc:
            raise KeyError("registered Control materializer identity changed") from exc
        if current != self.key or current_digest != self.scenario_digest:
            raise KeyError("registered Control materializer identity changed")

    def materialize(
        self,
        original_arguments: Mapping[str, JsonValue],
        *,
        nonce: str,
    ) -> tuple[MaterializedValidationControl, ...]:
        self.validate_adapter_identity()
        try:
            controls = tuple(
                MaterializedValidationControl.model_validate(item)
                for item in self.adapter.materialize(
                    original_arguments,
                    nonce=nonce,
                )
            )
        finally:
            self.validate_adapter_identity()
        if (
            len(controls) != len(ValidationControlKind)
            or {item.control_kind for item in controls} != set(ValidationControlKind)
        ):
            raise ValueError("Control materializer must return each Control kind exactly once")
        if len({item.session_id for item in controls}) != len(controls):
            raise ValueError("Control materializer must return unique fresh sessions")
        return controls


class ValidationControlMaterializerRegistry:
    """Frozen allowlist keyed by materializer and trusted execution identity."""

    def __init__(self) -> None:
        self._materializers: dict[
            tuple[str, str, str, str, str],
            _RegisteredValidationControlMaterializer,
        ] = {}
        self._frozen = False

    def register(self, materializer: ValidationControlMaterializer) -> None:
        if self._frozen:
            raise RuntimeError("Control materializer registry is frozen")
        registered = _RegisteredValidationControlMaterializer(
            adapter=materializer,
            materializer_id=materializer.materializer_id,
            materializer_version=materializer.materializer_version,
            mode=materializer.mode,
            scenario_id=materializer.scenario_id,
            tool_id=materializer.tool_id,
            scenario_digest=materializer.scenario_digest,
        )
        if len(registered.scenario_digest) != 64 or any(
            character not in "0123456789abcdef"
            for character in registered.scenario_digest
        ):
            raise ValueError("Control materializer scenario_digest must be a lowercase SHA-256")
        if registered.key in self._materializers:
            raise ValueError(
                "Control materializer is already registered: "
                f"{registered.materializer_id}@{registered.materializer_version}"
            )
        registered.validate_adapter_identity()
        self._materializers[registered.key] = registered

    def resolve(
        self,
        *,
        materializer_id: str,
        materializer_version: str,
        mode: CampaignMode,
        scenario_id: str,
        tool_id: str,
        scenario_digest: str,
    ) -> _RegisteredValidationControlMaterializer:
        self._frozen = True
        key = _materializer_key(
            materializer_id,
            materializer_version,
            mode,
            scenario_id,
            tool_id,
        )
        try:
            registered = self._materializers[key]
        except KeyError as exc:
            raise KeyError(
                "unknown Control materializer: "
                f"{materializer_id}@{materializer_version}"
            ) from exc
        registered.validate_adapter_identity()
        if registered.scenario_digest != scenario_digest:
            raise KeyError("Control materializer scenario digest differs from trusted input")
        return registered


def _materializer_key(
    materializer_id: str,
    version: str,
    mode: CampaignMode,
    scenario_id: str,
    tool_id: str,
) -> tuple[str, str, str, str, str]:
    values = (
        materializer_id.strip(),
        version.strip(),
        mode.value,
        scenario_id.strip(),
        tool_id.strip(),
    )
    if any(not value or len(value) > 200 for value in values):
        raise ValueError("Control materializer identity fields must contain 1-200 characters")
    return values
