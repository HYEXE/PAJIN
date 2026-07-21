"""Single-use authorities for compiler-issued replay execution."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Protocol, cast
from uuid import uuid4

from pajin.domain.replay import ReplayCompilation

_REPLAY_COMPILATION_SET_PATHS = (
    ("contract", "ephemeral_argument_fields"),
    ("contract", "allowed_argument_fields"),
    ("spec", "ephemeral_argument_fields"),
    ("grant", "tools"),
    ("grant", "targets"),
)


@dataclass(frozen=True, slots=True)
class ReplayExecutionTicket:
    """Opaque handle to one admitted compiler output; the ledger retains authority."""

    ticket_id: str


@dataclass(frozen=True, slots=True)
class ReplayTicketContext:
    """Trusted fingerprints captured beside compiler output, never model-authored."""

    candidate_source_root_digest: str
    campaign_digest: str
    tool_spec_digest: str
    scenario_digest: str

    def __post_init__(self) -> None:
        for name, value in (
            ("candidate_source_root_digest", self.candidate_source_root_digest),
            ("campaign_digest", self.campaign_digest),
            ("tool_spec_digest", self.tool_spec_digest),
            ("scenario_digest", self.scenario_digest),
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")


class ReplayTicketState(StrEnum):
    ISSUED = "issued"
    CLAIMED = "claimed"
    FINALIZED = "finalized"


@dataclass(frozen=True, slots=True)
class ClaimedReplayExecution:
    """Canonical compiler output released exactly once to the runtime."""

    ticket: ReplayExecutionTicket
    compilation: ReplayCompilation
    compilation_digest: str
    context: ReplayTicketContext


@dataclass(slots=True)
class _ReplayTicketEntry:
    canonical_compilation: bytes
    compilation_digest: str
    context: ReplayTicketContext
    replay_run_id: str
    expires_at: datetime
    state: ReplayTicketState = ReplayTicketState.ISSUED
    claimed_at: datetime | None = None
    finalized_at: datetime | None = None
    final_seal_root_digest: str | None = None
    artifact_set_digest: str | None = None


class _ReplayTicketIssueBackend(Protocol):
    """Internal capability consumed only by the compiler-side facade."""

    def _issue(
        self,
        token: object,
        compilation: ReplayCompilation,
        *,
        context: ReplayTicketContext,
    ) -> ReplayExecutionTicket: ...


class _ReplayTicketClaimBackend(Protocol):
    """Internal capability consumed only by the restricted runtime facade."""

    def _claim(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        expected_replay_run_id: str,
        expected_candidate_source_root_digest: str,
        expected_campaign_digest: str,
        claimed_at: datetime,
    ) -> ClaimedReplayExecution: ...

    def _finalize(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        finalized_at: datetime,
    ) -> None: ...

    def _recover_finalization(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        context: ReplayTicketContext,
        replay_run_id: str,
        finalized_at: datetime,
    ) -> None: ...

    def _verify_finalized(
        self,
        token: object,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None: ...


class _ReplayTicketVerifyBackend(Protocol):
    """Internal capability consumed only by a read-only verifier facade."""

    def _verify_finalized(
        self,
        token: object,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None: ...


class ReplayTicketIssuer:
    """Compiler-side facade; do not expose it to model or external request handlers."""

    def __init__(self, authority: _ReplayTicketIssueBackend, token: object) -> None:
        self.__authority = authority
        self.__token = token

    def issue_from_compiler(
        self,
        compilation: ReplayCompilation,
        *,
        context: ReplayTicketContext,
    ) -> ReplayExecutionTicket:
        return self.__authority._issue(self.__token, compilation, context=context)


class ReplayTicketClaimer:
    """Runtime-side facade that can claim and finalize, but never issue, tickets."""

    def __init__(self, authority: _ReplayTicketClaimBackend, token: object) -> None:
        self.__authority = authority
        self.__token = token

    def claim(
        self,
        ticket: ReplayExecutionTicket,
        *,
        expected_replay_run_id: str,
        expected_candidate_source_root_digest: str,
        expected_campaign_digest: str,
        claimed_at: datetime,
    ) -> ClaimedReplayExecution:
        return self.__authority._claim(
            self.__token,
            ticket,
            expected_replay_run_id=expected_replay_run_id,
            expected_candidate_source_root_digest=expected_candidate_source_root_digest,
            expected_campaign_digest=expected_campaign_digest,
            claimed_at=claimed_at,
        )

    def finalize(
        self,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        finalized_at: datetime,
    ) -> None:
        self.__authority._finalize(
            self.__token,
            ticket,
            final_seal_root_digest=final_seal_root_digest,
            artifact_set_digest=artifact_set_digest,
            finalized_at=finalized_at,
        )

    def recover_finalization(
        self,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        context: ReplayTicketContext,
        replay_run_id: str,
        finalized_at: datetime,
    ) -> None:
        """Finalize only a claimed ticket matching a fully reverified sealed receipt."""

        self.__authority._recover_finalization(
            self.__token,
            ticket,
            final_seal_root_digest=final_seal_root_digest,
            artifact_set_digest=artifact_set_digest,
            compilation_digest=compilation_digest,
            context=context,
            replay_run_id=replay_run_id,
            finalized_at=finalized_at,
        )

    def verify_finalized(
        self,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        self.__authority._verify_finalized(
            self.__token,
            ticket_id,
            final_seal_root_digest=final_seal_root_digest,
            artifact_set_digest=artifact_set_digest,
            compilation_digest=compilation_digest,
            candidate_source_root_digest=candidate_source_root_digest,
            replay_run_id=replay_run_id,
        )


class ReplayTicketFinalizationVerifier(Protocol):
    """Read-only contract used when consuming a sealed replay receipt."""

    def verify_finalized(
        self,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        """Reject unless final seals and issued compiler lineage all match exactly."""


class ReplayTicketVerifier:
    """Read-only ticket-ledger facade for future confirmation gates."""

    def __init__(self, authority: _ReplayTicketVerifyBackend, token: object) -> None:
        self.__authority = authority
        self.__token = token

    def verify_finalized(
        self,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        self.__authority._verify_finalized(
            self.__token,
            ticket_id,
            final_seal_root_digest=final_seal_root_digest,
            artifact_set_digest=artifact_set_digest,
            compilation_digest=compilation_digest,
            candidate_source_root_digest=candidate_source_root_digest,
            replay_run_id=replay_run_id,
        )


class ReplayTicketAuthority(Protocol):
    """Role-separated issuer, runtime, and verifier factory used by coordinators."""

    def issuer(self) -> ReplayTicketIssuer:
        """Return a compiler-only ticket issuer."""

    def claimer(self) -> ReplayTicketClaimer:
        """Return a runtime-only claim/finalization facade."""

    def verifier(self) -> ReplayTicketFinalizationVerifier:
        """Return a read-only finalized-ticket verifier."""


class ReplayExecutionAuthority:
    """Process-local replay ledger with atomic issue, claim, and finalize transitions."""

    def __init__(self) -> None:
        self.__issuer_token = object()
        self.__claimer_token = object()
        self.__verifier_token = object()
        self.__entries: dict[str, _ReplayTicketEntry] = {}
        self.__tickets_by_replay_run_id: dict[str, str] = {}
        self.__lock = Lock()

    def issuer(self) -> ReplayTicketIssuer:
        return ReplayTicketIssuer(self, self.__issuer_token)

    def claimer(self) -> ReplayTicketClaimer:
        return ReplayTicketClaimer(self, self.__claimer_token)

    def verifier(self) -> ReplayTicketVerifier:
        return ReplayTicketVerifier(self, self.__verifier_token)

    def _issue(
        self,
        token: object,
        compilation: ReplayCompilation,
        *,
        context: ReplayTicketContext,
    ) -> ReplayExecutionTicket:
        if token is not self.__issuer_token:
            raise PermissionError("invalid replay ticket issuer authority")
        canonical = canonical_replay_compilation_bytes(compilation)
        trusted = ReplayCompilation.model_validate_json(canonical)
        digest = sha256(canonical).hexdigest()
        ticket = ReplayExecutionTicket(ticket_id=f"replay-ticket_{uuid4().hex}")
        entry = _ReplayTicketEntry(
            canonical_compilation=canonical,
            compilation_digest=digest,
            context=context,
            replay_run_id=trusted.spec.binding.replay_run_id,
            expires_at=_utc(trusted.spec.expires_at),
        )
        with self.__lock:
            if entry.replay_run_id in self.__tickets_by_replay_run_id:
                raise PermissionError("a replay execution ticket already exists for this Run")
            self.__entries[ticket.ticket_id] = entry
            self.__tickets_by_replay_run_id[entry.replay_run_id] = ticket.ticket_id
        return ticket

    def _claim(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        expected_replay_run_id: str,
        expected_candidate_source_root_digest: str,
        expected_campaign_digest: str,
        claimed_at: datetime,
    ) -> ClaimedReplayExecution:
        if token is not self.__claimer_token:
            raise PermissionError("invalid replay ticket claimer authority")
        now = _utc(claimed_at)
        with self.__lock:
            entry = self.__entries.get(ticket.ticket_id)
            if entry is None:
                raise KeyError("unknown replay execution ticket")
            if entry.state is not ReplayTicketState.ISSUED:
                raise PermissionError(f"replay execution ticket is already {entry.state.value}")
            if entry.replay_run_id != expected_replay_run_id:
                raise PermissionError("replay execution ticket belongs to another Run")
            if (
                entry.context.candidate_source_root_digest != expected_candidate_source_root_digest
                or entry.context.campaign_digest != expected_campaign_digest
            ):
                raise PermissionError("trusted replay execution context changed after compilation")
            if now >= entry.expires_at:
                raise PermissionError("replay execution ticket authority expired")
            entry.state = ReplayTicketState.CLAIMED
            entry.claimed_at = now
            canonical = bytes(entry.canonical_compilation)
            digest = entry.compilation_digest
            context = entry.context
        return ClaimedReplayExecution(
            ticket=ticket,
            compilation=ReplayCompilation.model_validate_json(canonical),
            compilation_digest=digest,
            context=context,
        )

    def _finalize(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        finalized_at: datetime,
    ) -> None:
        if token is not self.__claimer_token:
            raise PermissionError("invalid replay ticket finalizer authority")
        for name, value in (
            ("final_seal_root_digest", final_seal_root_digest),
            ("artifact_set_digest", artifact_set_digest),
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        with self.__lock:
            entry = self.__entries.get(ticket.ticket_id)
            if entry is None:
                raise KeyError("unknown replay execution ticket")
            if entry.state is not ReplayTicketState.CLAIMED:
                raise PermissionError("only a claimed replay ticket can be finalized")
            entry.state = ReplayTicketState.FINALIZED
            entry.finalized_at = _utc(finalized_at)
            entry.final_seal_root_digest = final_seal_root_digest
            entry.artifact_set_digest = artifact_set_digest

    def _recover_finalization(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        context: ReplayTicketContext,
        replay_run_id: str,
        finalized_at: datetime,
    ) -> None:
        if token is not self.__claimer_token:
            raise PermissionError("invalid replay ticket recovery authority")
        for name, value in (
            ("final_seal_root_digest", final_seal_root_digest),
            ("artifact_set_digest", artifact_set_digest),
            ("compilation_digest", compilation_digest),
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        recovered_at = _utc(finalized_at)
        with self.__lock:
            entry = self.__entries.get(ticket.ticket_id)
            if entry is None:
                raise KeyError("unknown replay execution ticket")
            if (
                entry.compilation_digest != compilation_digest
                or entry.context != context
                or entry.replay_run_id != replay_run_id
            ):
                raise PermissionError("replay ticket recovery context does not match issuance")
            if entry.state is ReplayTicketState.FINALIZED:
                if (
                    entry.final_seal_root_digest == final_seal_root_digest
                    and entry.artifact_set_digest == artifact_set_digest
                ):
                    return
                raise PermissionError(
                    "replay ticket was already finalized with different sealed artifacts"
                )
            if entry.state is not ReplayTicketState.CLAIMED:
                raise PermissionError("only a claimed replay ticket can be recovered")
            if entry.claimed_at is None or recovered_at < entry.claimed_at:
                raise PermissionError("replay ticket recovery cannot predate its claim")
            entry.state = ReplayTicketState.FINALIZED
            entry.finalized_at = recovered_at
            entry.final_seal_root_digest = final_seal_root_digest
            entry.artifact_set_digest = artifact_set_digest

    def _verify_finalized(
        self,
        token: object,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        if token is not self.__claimer_token and token is not self.__verifier_token:
            raise PermissionError("invalid replay ticket verification authority")
        with self.__lock:
            entry = self.__entries.get(ticket_id)
            if entry is None:
                raise KeyError("unknown replay execution ticket")
            if entry.state is not ReplayTicketState.FINALIZED:
                raise PermissionError("replay execution ticket is not finalized")
            if (
                entry.final_seal_root_digest != final_seal_root_digest
                or entry.artifact_set_digest != artifact_set_digest
                or entry.compilation_digest != compilation_digest
                or entry.context.candidate_source_root_digest != candidate_source_root_digest
                or entry.replay_run_id != replay_run_id
            ):
                raise PermissionError(
                    "replay ticket finalization does not match the sealed receipt"
                )


def replay_context_digest(value: object) -> str:
    """Hash trusted JSON-like context using the same deterministic representation."""

    payload = json.dumps(
        _canonical_context(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()
    return sha256(payload).hexdigest()


def canonical_replay_compilation_payload(
    compilation: ReplayCompilation,
) -> dict[str, object]:
    """Return the deterministic JSON object issued and sealed for one compilation.

    The Python-mode dump deliberately preserves sets until ``_canonical_context``
    sorts them. Converting to JSON mode first would turn sets into order-sensitive
    lists and could make the ticket digest differ from the later sealed wire object.
    """

    trusted = ReplayCompilation.model_validate(compilation.model_dump(mode="python", by_alias=True))
    payload = _canonical_context(trusted)
    if not isinstance(payload, dict):  # pragma: no cover - ReplayCompilation is a mapping model
        raise TypeError("canonical replay compilation must be a JSON object")
    return cast(dict[str, object], payload)


def canonicalize_replay_compilation_wire_sets(
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Sort only v1 compilation fields whose typed contract is a set.

    This is a narrow compatibility transform for already-sealed v1 artifacts whose
    receipt and ``compilation.json`` serialized the same set in different orders.
    It starts from the decoded wire object, so fields absent from that historical
    wire stay absent. Ordered lists such as evidence and comparison goals are never
    reordered.
    """

    normalized = _canonical_context(payload)
    if not isinstance(normalized, dict):  # pragma: no cover - the input is a mapping
        raise TypeError("replay compilation wire must be a JSON object")
    for parent_name, field_name in _REPLAY_COMPILATION_SET_PATHS:
        parent = normalized.get(parent_name)
        if not isinstance(parent, dict) or field_name not in parent:
            continue
        value = parent[field_name]
        if not isinstance(value, list):
            raise TypeError(
                f"replay compilation set field {parent_name}.{field_name} must be a list"
            )
        parent[field_name] = sorted(value, key=_canonical_json)
    return cast(dict[str, object], normalized)


def _canonical_context(value: object) -> object:
    """Normalize trusted context without relying on process-specific set ordering."""

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _canonical_context(model_dump(mode="python", by_alias=True))
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_context(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (set, frozenset)):
        items = [_canonical_context(item) for item in value]
        return sorted(items, key=_canonical_json)
    if isinstance(value, (list, tuple)):
        return [_canonical_context(item) for item in value]
    if isinstance(value, Enum):
        return _canonical_context(value.value)
    if isinstance(value, datetime):
        normalized = (
            value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
        )
        return normalized.isoformat()
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported replay context type: {type(value).__name__}")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def canonical_replay_compilation_bytes(compilation: ReplayCompilation) -> bytes:
    """Serialize a typed compilation exactly as ticket authorities persist it."""

    return json.dumps(
        canonical_replay_compilation_payload(compilation),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
