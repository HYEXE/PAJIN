"""Trusted argument materializers for session-bearing restricted replay."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from pydantic import JsonValue

from pajin.domain.models import CampaignMode
from pajin.domain.replay import CompiledReplaySpec, ReplaySessionPolicy


class ReplaySessionMaterializer(Protocol):
    """Mode-owned transformation limited by runtime-enforced ephemeral fields."""

    materializer_id: str
    materializer_version: str
    mode: CampaignMode
    scenario_id: str
    tool_id: str
    session_policy: ReplaySessionPolicy
    scenario_digest: str

    def materialize(
        self,
        spec: CompiledReplaySpec,
        attempt_number: int,
    ) -> Mapping[str, JsonValue]:
        """Return one attempt's arguments without creating authority or a Tool request."""


class ReplayMaterializerRegistry:
    """Frozen allowlist keyed by the compiled materializer and Mode identity."""

    def __init__(self) -> None:
        self._materializers: dict[
            tuple[str, str, str, str, str, str], ReplaySessionMaterializer
        ] = {}
        self._frozen = False

    def register(self, materializer: ReplaySessionMaterializer) -> None:
        if self._frozen:
            raise RuntimeError("replay materializer registry is frozen")
        key = self._key(
            materializer.materializer_id,
            materializer.materializer_version,
            materializer.mode,
            materializer.scenario_id,
            materializer.tool_id,
            materializer.session_policy,
        )
        if len(materializer.scenario_digest) != 64 or any(
            character not in "0123456789abcdef" for character in materializer.scenario_digest
        ):
            raise ValueError("replay materializer scenario_digest must be a lowercase SHA-256")
        if key in self._materializers:
            raise ValueError(
                "replay materializer is already registered: "
                f"{materializer.materializer_id}@{materializer.materializer_version}"
            )
        self._materializers[key] = materializer

    def resolve(self, spec: CompiledReplaySpec) -> ReplaySessionMaterializer:
        self._frozen = True
        if spec.materializer_id is None or spec.materializer_version is None:
            raise KeyError("compiled replay does not declare a materializer")
        key = self._key(
            spec.materializer_id,
            spec.materializer_version,
            spec.binding.mode,
            spec.binding.scenario_id,
            spec.binding.tool_id,
            spec.session_policy,
        )
        try:
            materializer = self._materializers[key]
        except KeyError as exc:
            raise KeyError(
                f"unknown replay materializer: {spec.materializer_id}@{spec.materializer_version}"
            ) from exc
        if (
            self._key(
                materializer.materializer_id,
                materializer.materializer_version,
                materializer.mode,
                materializer.scenario_id,
                materializer.tool_id,
                materializer.session_policy,
            )
            != key
        ):
            raise KeyError("registered replay materializer identity changed after registration")
        return materializer

    @staticmethod
    def _key(
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
