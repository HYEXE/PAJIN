"""Trusted argument materializers for session-bearing restricted replay."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from pydantic import JsonValue

from pajin.domain.models import CampaignMode
from pajin.domain.replay import CompiledReplaySpec, ReplaySessionPolicy


class ReplaySessionMaterializer(Protocol):
    """Mode-owned transformation limited by runtime-enforced ephemeral fields."""

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
    def session_policy(self) -> ReplaySessionPolicy: ...

    @property
    def scenario_digest(self) -> str: ...

    def materialize(
        self,
        spec: CompiledReplaySpec,
        attempt_number: int,
    ) -> Mapping[str, JsonValue]:
        """Return one attempt's arguments without creating authority or a Tool request."""


@dataclass(frozen=True, slots=True)
class _RegisteredReplayMaterializer:
    """Immutable identity snapshot around one mutable Mode-owned adapter."""

    adapter: ReplaySessionMaterializer
    materializer_id: str
    materializer_version: str
    mode: CampaignMode
    scenario_id: str
    tool_id: str
    session_policy: ReplaySessionPolicy
    scenario_digest: str

    def validate_adapter_identity(self) -> None:
        try:
            current = _materializer_key(
                self.adapter.materializer_id,
                self.adapter.materializer_version,
                self.adapter.mode,
                self.adapter.scenario_id,
                self.adapter.tool_id,
                self.adapter.session_policy,
            )
            current_digest = self.adapter.scenario_digest
        except (AttributeError, TypeError, ValueError) as exc:
            raise KeyError("registered replay materializer identity changed") from exc
        if current != self.key or current_digest != self.scenario_digest:
            raise KeyError("registered replay materializer identity changed")

    @property
    def key(self) -> tuple[str, str, str, str, str, str]:
        return _materializer_key(
            self.materializer_id,
            self.materializer_version,
            self.mode,
            self.scenario_id,
            self.tool_id,
            self.session_policy,
        )

    def materialize(
        self,
        spec: CompiledReplaySpec,
        attempt_number: int,
    ) -> Mapping[str, JsonValue]:
        self.validate_adapter_identity()
        try:
            return self.adapter.materialize(spec, attempt_number)
        finally:
            self.validate_adapter_identity()


class ReplayMaterializerRegistry:
    """Frozen allowlist keyed by the compiled materializer and Mode identity."""

    def __init__(self) -> None:
        self._materializers: dict[
            tuple[str, str, str, str, str, str], _RegisteredReplayMaterializer
        ] = {}
        self._frozen = False

    def register(self, materializer: ReplaySessionMaterializer) -> None:
        if self._frozen:
            raise RuntimeError("replay materializer registry is frozen")
        registered = _RegisteredReplayMaterializer(
            adapter=materializer,
            materializer_id=materializer.materializer_id,
            materializer_version=materializer.materializer_version,
            mode=materializer.mode,
            scenario_id=materializer.scenario_id,
            tool_id=materializer.tool_id,
            session_policy=materializer.session_policy,
            scenario_digest=materializer.scenario_digest,
        )
        key = registered.key
        if len(registered.scenario_digest) != 64 or any(
            character not in "0123456789abcdef" for character in registered.scenario_digest
        ):
            raise ValueError("replay materializer scenario_digest must be a lowercase SHA-256")
        if key in self._materializers:
            raise ValueError(
                "replay materializer is already registered: "
                f"{registered.materializer_id}@{registered.materializer_version}"
            )
        registered.validate_adapter_identity()
        self._materializers[key] = registered

    def resolve(self, spec: CompiledReplaySpec) -> ReplaySessionMaterializer:
        self._frozen = True
        if spec.materializer_id is None or spec.materializer_version is None:
            raise KeyError("compiled replay does not declare a materializer")
        key = _materializer_key(
            spec.materializer_id,
            spec.materializer_version,
            spec.binding.mode,
            spec.binding.scenario_id,
            spec.binding.tool_id,
            spec.session_policy,
        )
        try:
            registered = self._materializers[key]
        except KeyError as exc:
            raise KeyError(
                f"unknown replay materializer: {spec.materializer_id}@{spec.materializer_version}"
            ) from exc
        registered.validate_adapter_identity()
        return registered

    @staticmethod
    def _key(
        materializer_id: str,
        version: str,
        mode: CampaignMode,
        scenario_id: str,
        tool_id: str,
        session_policy: ReplaySessionPolicy,
    ) -> tuple[str, str, str, str, str, str]:
        return _materializer_key(
            materializer_id,
            version,
            mode,
            scenario_id,
            tool_id,
            session_policy,
        )


def _materializer_key(
    materializer_id: str,
    version: str,
    mode: CampaignMode,
    scenario_id: str,
    tool_id: str,
    session_policy: ReplaySessionPolicy,
) -> tuple[str, str, str, str, str, str]:
    values = (
        materializer_id.strip(),
        version.strip(),
        mode.value,
        scenario_id.strip(),
        tool_id.strip(),
        session_policy.value,
    )
    if any(not value or len(value) > 200 for value in values):
        raise ValueError("replay materializer identity fields must contain 1-200 characters")
    return values
