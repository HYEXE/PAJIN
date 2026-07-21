"""Trusted replay Oracle protocol and immutable registry boundary."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from pydantic import JsonValue

from pajin.domain.models import CampaignMode, ToolRequest
from pajin.domain.replay import (
    CompiledReplaySpec,
    ReplayAttempt,
    ReplayAttemptStatus,
    ReplayMaterialization,
    ReplayOracleResult,
)
from pajin.tools.gateway import GatewayOutcome


class ReplayModeOracle(Protocol):
    """Trusted cooperative-async adapter; CPU work needs a separately bounded executor."""

    @property
    def oracle_id(self) -> str: ...

    @property
    def oracle_version(self) -> str: ...

    @property
    def observation_schema(self) -> str: ...

    @property
    def mode(self) -> CampaignMode: ...

    @property
    def scenario_id(self) -> str: ...

    @property
    def tool_id(self) -> str: ...

    @property
    def scenario_digest(self) -> str: ...

    def observation(
        self,
        spec: CompiledReplaySpec,
        request: ToolRequest,
        materialization: ReplayMaterialization | None,
        outcome: GatewayOutcome,
    ) -> Mapping[str, JsonValue]:
        """Normalize a successful Tool result into the declared observation schema."""

    def classify_failure(self, outcome: GatewayOutcome) -> ReplayAttemptStatus:
        """Classify a failed dispatch without turning attacker text into policy."""

    async def evaluate(
        self,
        spec: CompiledReplaySpec,
        attempts: Sequence[ReplayAttempt],
        *,
        evaluated_at: datetime,
    ) -> ReplayOracleResult:
        """Evaluate successful fresh observations against the Mode-owned contract."""


@dataclass(frozen=True, slots=True)
class _RegisteredReplayOracle:
    """Immutable identity snapshot around one mutable Mode-owned adapter."""

    adapter: ReplayModeOracle
    oracle_id: str
    oracle_version: str
    observation_schema: str
    mode: CampaignMode
    scenario_id: str
    tool_id: str
    scenario_digest: str

    @property
    def key(self) -> tuple[str, str, str, str, str, str]:
        return _oracle_key(
            self.oracle_id,
            self.oracle_version,
            self.observation_schema,
            self.mode,
            self.scenario_id,
            self.tool_id,
        )

    def validate_adapter_identity(self) -> None:
        try:
            current = _oracle_key(
                self.adapter.oracle_id,
                self.adapter.oracle_version,
                self.adapter.observation_schema,
                self.adapter.mode,
                self.adapter.scenario_id,
                self.adapter.tool_id,
            )
            current_digest = self.adapter.scenario_digest
        except (AttributeError, TypeError, ValueError) as exc:
            raise KeyError("registered replay Oracle identity changed") from exc
        if current != self.key or current_digest != self.scenario_digest:
            raise KeyError("registered replay Oracle identity changed")

    def observation(
        self,
        spec: CompiledReplaySpec,
        request: ToolRequest,
        materialization: ReplayMaterialization | None,
        outcome: GatewayOutcome,
    ) -> Mapping[str, JsonValue]:
        self.validate_adapter_identity()
        try:
            return self.adapter.observation(spec, request, materialization, outcome)
        finally:
            self.validate_adapter_identity()

    def classify_failure(self, outcome: GatewayOutcome) -> ReplayAttemptStatus:
        self.validate_adapter_identity()
        try:
            return self.adapter.classify_failure(outcome)
        finally:
            self.validate_adapter_identity()

    async def evaluate(
        self,
        spec: CompiledReplaySpec,
        attempts: Sequence[ReplayAttempt],
        *,
        evaluated_at: datetime,
    ) -> ReplayOracleResult:
        self.validate_adapter_identity()
        try:
            return await self.adapter.evaluate(
                spec,
                attempts,
                evaluated_at=evaluated_at,
            )
        finally:
            self.validate_adapter_identity()


class ReplayOracleRegistry:
    """Explicit allowlist of trusted Mode Oracles keyed by immutable identity."""

    def __init__(self) -> None:
        self._oracles: dict[tuple[str, str, str, str, str, str], _RegisteredReplayOracle] = {}
        self._frozen = False

    def register(self, oracle: ReplayModeOracle) -> None:
        if self._frozen:
            raise RuntimeError("replay Oracle registry is frozen")
        registered = _RegisteredReplayOracle(
            adapter=oracle,
            oracle_id=oracle.oracle_id,
            oracle_version=oracle.oracle_version,
            observation_schema=oracle.observation_schema,
            mode=oracle.mode,
            scenario_id=oracle.scenario_id,
            tool_id=oracle.tool_id,
            scenario_digest=oracle.scenario_digest,
        )
        key = registered.key
        if len(registered.scenario_digest) != 64 or any(
            character not in "0123456789abcdef" for character in registered.scenario_digest
        ):
            raise ValueError("replay Oracle scenario_digest must be a lowercase SHA-256")
        if key in self._oracles:
            raise ValueError(
                "replay Oracle is already registered: "
                f"{registered.oracle_id}@{registered.oracle_version}/"
                f"{registered.observation_schema}"
            )
        registered.validate_adapter_identity()
        self._oracles[key] = registered

    def resolve(self, spec: CompiledReplaySpec) -> ReplayModeOracle:
        self._frozen = True
        key = _oracle_key(
            spec.oracle_id,
            spec.oracle_version,
            spec.observation_schema,
            spec.binding.mode,
            spec.binding.scenario_id,
            spec.binding.tool_id,
        )
        try:
            registered = self._oracles[key]
        except KeyError as exc:
            raise KeyError(
                "unknown replay Oracle: "
                f"{spec.oracle_id}@{spec.oracle_version}/{spec.observation_schema}"
            ) from exc
        registered.validate_adapter_identity()
        return registered

    @staticmethod
    def _key(
        oracle_id: str,
        version: str,
        observation_schema: str,
        mode: CampaignMode,
        scenario_id: str,
        tool_id: str,
    ) -> tuple[str, str, str, str, str, str]:
        return _oracle_key(
            oracle_id,
            version,
            observation_schema,
            mode,
            scenario_id,
            tool_id,
        )


def _oracle_key(
    oracle_id: str,
    version: str,
    observation_schema: str,
    mode: CampaignMode,
    scenario_id: str,
    tool_id: str,
) -> tuple[str, str, str, str, str, str]:
    values = (
        oracle_id.strip(),
        version.strip(),
        observation_schema.strip(),
        mode.value,
        scenario_id.strip(),
        tool_id.strip(),
    )
    if any(not value or len(value) > 200 for value in values):
        raise ValueError("replay Oracle identity fields must contain 1-200 characters")
    return values
