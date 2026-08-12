from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest

import pajin.reporting.delivery as delivery
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import Finding, FindingSeverity
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    ReplayConfirmationLineage,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
)
from pajin.reporting.sarif import VerifiedSarifExport, load_verified_sarif_export
from pajin.runtime.secrets import SecretBroker, SecretLease, SecretMaterial
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    write_validation_artifacts,
)

NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
SECRET_REF = "external-delivery-test-key"
SECRET_VALUE = "test-external-delivery-secret-value"


def _finding() -> Finding:
    return Finding(
        finding_id="finding_delivery_1",
        title="Confirmed access control weakness",
        severity=FindingSeverity.HIGH,
        threat_class="M03",
        target="https://operator:secret@target.example/v1/chat?token=secret-target-token",
        summary="An independently replayed request crossed the expected access boundary.",
        impact="A scoped test identity reached another test tenant.",
        affected_component="tenant retrieval endpoint",
        root_cause="secret-root-cause-detail",
        reproduction=["secret-reproduction-step"],
        evidence=["evidence/secret-evidence-path.json"],
        remediation=["Bind retrieval to the authenticated tenant identity."],
        confidence=0.95,
        validated=False,
    )


def _sealed_validation_run(tmp_path: Path) -> RunStore:
    store = RunStore.create(tmp_path, "external-delivery-test")
    candidate = CandidateFinding(
        candidate_id="candidate_delivery_1",
        claim=_finding(),
        source="trusted-core:candidate-producer",
        source_agent_id="trusted-core:test-producer",
        source_request_ids=["request_source_1"],
        created_at=NOW,
    )
    source_decision = ValidationDecision(
        decision_id="decision_source_1",
        candidate_id=candidate.candidate_id,
        validator_id="agent:semantic-validator:1",
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=FindingDisposition.NEEDS_REVIEW,
        reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING],
        decision_summary="Independent reproduction has not run.",
        supporting_evidence=[],
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=[],
        decided_at=NOW,
    )
    store.append_event("test.source-validation.created", {})
    write_validation_artifacts(
        store,
        FindingValidationSet(
            candidates=[candidate],
            decisions=[source_decision],
            confirmed_findings=[],
        ),
    )
    store.write_json("findings.json", [])
    source_seal = store.seal()
    lineage = ReplayConfirmationLineage(
        replay_run_id="run_replay_delivery_1",
        replay_outcome_id="replay-outcome_delivery_1",
        replay_request_ids=["request_replay_1"],
        replay_evidence=["evidence/request_replay_1.json"],
        oracle_result_id="oracle-result_delivery_1",
        ticket_id="ticket_delivery_1",
        candidate_source_root_digest=source_seal.root_digest,
        artifact_set_digest="a" * 64,
        artifact_seal_root_digest="b" * 64,
        receipt_seal_root_digest="c" * 64,
        verified_at=NOW,
    )
    confirmed_decision = ValidationDecision(
        decision_id="decision_replay_1",
        supersedes_decision_id=source_decision.decision_id,
        candidate_id=candidate.candidate_id,
        validator_id="trusted-core:confirmed-gate",
        method=ValidationMethod.RESTRICTED_REPLAY_GATE,
        disposition=FindingDisposition.CONFIRMED,
        confirmation_basis=ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY,
        reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED],
        decision_summary="A verified independent replay supported the exact claim.",
        supporting_evidence=[],
        contradicting_evidence=[],
        replay_request_ids=lineage.replay_request_ids,
        replay_outcome_ids=[lineage.replay_outcome_id],
        replay_lineage=[lineage],
        checks=[],
        decided_at=NOW,
    )
    confirmed_finding = candidate.claim.model_copy(update={"validated": True})
    store.write_json(
        VERSIONED_VALIDATION_DECISIONS_PATH,
        VersionedValidationDecisionSet(
            sourceRunId=store.run_id,
            decisions=[confirmed_decision],
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        VERSIONED_VALIDATION_FINDINGS_PATH,
        VersionedConfirmedFindingSet(
            sourceRunId=store.run_id,
            confirmationSemantics="verified-independent-replay",
            findings=[confirmed_finding],
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_text(VERSIONED_VALIDATION_REPORT_PATH, "# Independently replayed findings\n")
    store.write_json(
        VERSIONED_VALIDATION_INDEX_PATH,
        VersionedValidationIndex(
            sourceRunId=store.run_id,
            candidateSourceRootDigest=source_seal.root_digest,
            confirmationSemantics="verified-independent-replay",
            dispositions={
                FindingDisposition.CONFIRMED: [candidate.candidate_id],
                FindingDisposition.NEEDS_REVIEW: [],
                FindingDisposition.INCONCLUSIVE: [],
                FindingDisposition.REJECTED_OBJECTIVE: [],
            },
            confirmedCandidateIds=[candidate.candidate_id],
            generatedAt=NOW,
        ).model_dump(mode="json", by_alias=True),
    )
    store.append_event("test.versioned-validation.created", {})
    store.seal()
    return store


def _export(store: RunStore) -> VerifiedSarifExport:
    authority = verify_run_integrity(store.path)
    return load_verified_sarif_export(
        store.path,
        expected_run_id=store.run_id,
        expected_root_digest=authority.root_digest,
    )


def _sink(*, endpoint_host: str = "sink.example") -> delivery.ExternalDeliverySink:
    return delivery.ExternalDeliverySink(
        sinkType="issue-tracker",
        deliveryEndpoint=f"https://{endpoint_host}/v1/findings",
        reconciliationEndpoint=f"https://{endpoint_host}/v1/findings/status",
        secretRefFingerprint=SecretBroker.fingerprint(SECRET_REF),
    )


def _authorization(
    intent: delivery.ExternalDeliveryIntent,
) -> delivery.ExternalDeliveryAuthorization:
    return delivery.ExternalDeliveryAuthorization(
        intentId=intent.intent_id,
        intentDigest=intent.intent_digest,
        sinkId=intent.sink_id,
        sinkDigest=intent.sink_digest,
        payloadDigest=intent.payload_digest,
        idempotencyKey=intent.idempotency_key,
        authorizedAt=NOW - timedelta(seconds=1),
        expiresAt=NOW + timedelta(minutes=5),
    )


def _signed_http_response(
    *,
    intent: delivery.ExternalDeliveryIntent,
    sink: delivery.ExternalDeliverySink,
    secret: SecretMaterial,
    attempt_ordinal: int,
    outcome: Literal["accepted", "not-received"],
    status_code: int,
    signing_secret: str | None = None,
) -> delivery.ExternalDeliveryHTTPResponse:
    response = delivery.ExternalDeliverySinkResponse(
        intentId=intent.intent_id,
        sinkId=sink.sink_id,
        idempotencyKey=intent.idempotency_key,
        payloadDigest=intent.payload_digest,
        attemptOrdinal=attempt_ordinal,
        outcome=outcome,
        externalReceiptId=(f"remote-receipt-{attempt_ordinal}" if outcome == "accepted" else None),
        acceptedAt=NOW if outcome == "accepted" else None,
    )
    signed = delivery.sign_external_delivery_sink_response(
        response,
        secret_value=signing_secret or secret.value,
    )
    body = canonical_json_bytes(
        signed.model_dump(mode="json", by_alias=True),
        label="test delivery response",
    )
    return delivery.ExternalDeliveryHTTPResponse(
        status_code=status_code,
        content_type="application/json; charset=utf-8",
        body=body,
    )


class FakeTransport:
    def __init__(
        self,
        *,
        dispatch_outcomes: list[Literal["accepted", "not-received"] | BaseException],
        reconcile_outcomes: list[Literal["accepted", "not-received"] | BaseException] | None = None,
        signing_secret: str | None = None,
    ) -> None:
        self.dispatch_outcomes = list(dispatch_outcomes)
        self.reconcile_outcomes = list(reconcile_outcomes or [])
        self.signing_secret = signing_secret
        self.dispatches: list[tuple[str, int, bytes]] = []
        self.reconciliations: list[tuple[str, int]] = []

    def dispatch(
        self,
        sink: delivery.ExternalDeliverySink,
        intent: delivery.ExternalDeliveryIntent,
        payload: bytes,
        secret: SecretMaterial,
        *,
        attempt_ordinal: int,
    ) -> delivery.ExternalDeliveryHTTPResponse:
        self.dispatches.append((intent.idempotency_key, attempt_ordinal, payload))
        outcome = self.dispatch_outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return _signed_http_response(
            intent=intent,
            sink=sink,
            secret=secret,
            attempt_ordinal=attempt_ordinal,
            outcome=outcome,
            status_code=202,
            signing_secret=self.signing_secret,
        )

    def reconcile(
        self,
        sink: delivery.ExternalDeliverySink,
        intent: delivery.ExternalDeliveryIntent,
        secret: SecretMaterial,
        *,
        attempt_ordinal: int,
    ) -> delivery.ExternalDeliveryHTTPResponse:
        self.reconciliations.append((intent.idempotency_key, attempt_ordinal))
        outcome = self.reconcile_outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return _signed_http_response(
            intent=intent,
            sink=sink,
            secret=secret,
            attempt_ordinal=attempt_ordinal,
            outcome=outcome,
            status_code=200,
            signing_secret=self.signing_secret,
        )


def _context(
    tmp_path: Path,
    *,
    transport: FakeTransport,
) -> tuple[
    RunStore,
    VerifiedSarifExport,
    delivery.ExternalDeliverySink,
    delivery.ExternalDeliveryIntent,
    delivery.ExternalDeliveryAuthorization,
    SecretBroker,
    delivery.SQLiteExternalDeliveryJournal,
    delivery.ExternalDeliveryCoordinator,
    delivery.ExternalDeliveryRecord,
]:
    store = _sealed_validation_run(tmp_path / "runs")
    exported = _export(store)
    sink = _sink()
    intent = delivery.build_external_delivery_intent(exported, sink)
    authorization = _authorization(intent)
    broker = SecretBroker(clock=lambda: NOW)
    broker.register(SECRET_REF, SECRET_VALUE)
    journal = delivery.SQLiteExternalDeliveryJournal(
        tmp_path / "delivery" / "journal.sqlite3",
        clock=lambda: NOW,
    )
    coordinator = delivery.ExternalDeliveryCoordinator(
        sinks=delivery.ExternalDeliverySinkRegistry((sink,)),
        authorizations=delivery.ExternalDeliveryAuthorizationRegistry((authorization,)),
        secrets=broker,
        journal=journal,
        transport=transport,
        clock=lambda: NOW,
    )
    record = coordinator.register(exported, intent, authorization)
    return (
        store,
        exported,
        sink,
        intent,
        authorization,
        broker,
        journal,
        coordinator,
        record,
    )


def _lease(
    broker: SecretBroker,
    sink: delivery.ExternalDeliverySink,
    intent: delivery.ExternalDeliveryIntent,
    *,
    operation: Literal["dispatch", "reconcile"],
    attempt_ordinal: int,
) -> SecretLease:
    return broker.issue(
        SECRET_REF,
        audience=sink.sink_id,
        binding=delivery.external_delivery_secret_binding(
            intent,
            operation=operation,
            attempt_ordinal=attempt_ordinal,
        ),
        scope=intent.source_run_id,
        ttl_seconds=30,
        max_uses=1,
    )


def test_external_delivery_acceptance_is_exact_durable_and_secret_free(tmp_path: Path) -> None:
    transport = FakeTransport(dispatch_outcomes=["accepted"])
    (
        _store,
        exported,
        sink,
        intent,
        _authorization_value,
        broker,
        journal,
        coordinator,
        record,
    ) = _context(tmp_path, transport=transport)

    delivered = coordinator.dispatch_once(
        record,
        exported,
        _lease(
            broker,
            sink,
            intent,
            operation="dispatch",
            attempt_ordinal=1,
        ),
    )

    assert delivered.state is delivery.ExternalDeliveryState.DELIVERED
    assert delivered.attempt_count == 1
    assert delivered.receipt is not None
    assert delivered.receipt.external_delivery_performed is True
    assert delivered.receipt.delivery_receipt_authority is True
    assert delivered.receipt.downstream_action_attested is False
    assert transport.dispatches == [(intent.idempotency_key, 1, exported.content.encode("utf-8"))]
    assert (
        delivery.SQLiteExternalDeliveryJournal(
            journal.path,
            clock=lambda: NOW,
        ).inspect(intent.intent_id)
        == delivered
    )
    assert SECRET_VALUE.encode("utf-8") not in journal.path.read_bytes()

    with pytest.raises(delivery.ExternalDeliveryError, match="dispatch is not available"):
        coordinator.dispatch_once(
            delivered,
            exported,
            _lease(
                broker,
                sink,
                intent,
                operation="dispatch",
                attempt_ordinal=2,
            ),
        )
    assert len(transport.dispatches) == 1


def test_unknown_dispatch_requires_authenticated_reconciliation_without_redispatch(
    tmp_path: Path,
) -> None:
    transport = FakeTransport(
        dispatch_outcomes=[OSError("connection closed")],
        reconcile_outcomes=["accepted"],
    )
    (
        _store,
        exported,
        sink,
        intent,
        _authorization_value,
        broker,
        journal,
        coordinator,
        record,
    ) = _context(tmp_path, transport=transport)

    with pytest.raises(delivery.ExternalDeliveryOutcomeUnknownError, match="outcome is unknown"):
        coordinator.dispatch_once(
            record,
            exported,
            _lease(
                broker,
                sink,
                intent,
                operation="dispatch",
                attempt_ordinal=1,
            ),
        )
    unknown = journal.inspect(intent.intent_id)
    assert unknown.state is delivery.ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    assert unknown.manual_review_required is True
    assert unknown.automatic_retry_authorized is False

    with pytest.raises(delivery.ExternalDeliveryError, match="dispatch is not available"):
        coordinator.dispatch_once(
            unknown,
            exported,
            _lease(
                broker,
                sink,
                intent,
                operation="dispatch",
                attempt_ordinal=2,
            ),
        )
    reconciled = coordinator.reconcile(
        unknown,
        exported,
        _lease(
            broker,
            sink,
            intent,
            operation="reconcile",
            attempt_ordinal=1,
        ),
    )
    assert reconciled.state is delivery.ExternalDeliveryState.DELIVERED
    assert reconciled.receipt is not None
    assert len(transport.dispatches) == 1
    assert transport.reconciliations == [(intent.idempotency_key, 1)]


def test_authenticated_not_received_allows_one_explicit_retry_with_same_key(
    tmp_path: Path,
) -> None:
    transport = FakeTransport(
        dispatch_outcomes=[OSError("unknown"), "accepted"],
        reconcile_outcomes=["not-received"],
    )
    (
        _store,
        exported,
        sink,
        intent,
        _authorization_value,
        broker,
        journal,
        coordinator,
        record,
    ) = _context(tmp_path, transport=transport)
    with pytest.raises(delivery.ExternalDeliveryOutcomeUnknownError):
        coordinator.dispatch_once(
            record,
            exported,
            _lease(
                broker,
                sink,
                intent,
                operation="dispatch",
                attempt_ordinal=1,
            ),
        )
    unknown = journal.inspect(intent.intent_id)
    retry_ready = coordinator.reconcile(
        unknown,
        exported,
        _lease(
            broker,
            sink,
            intent,
            operation="reconcile",
            attempt_ordinal=1,
        ),
    )
    assert retry_ready.state is delivery.ExternalDeliveryState.READY_RETRY
    assert retry_ready.retry_authorized is True
    assert retry_ready.automatic_retry_authorized is False

    delivered = coordinator.dispatch_once(
        retry_ready,
        exported,
        _lease(
            broker,
            sink,
            intent,
            operation="dispatch",
            attempt_ordinal=2,
        ),
    )
    assert delivered.state is delivery.ExternalDeliveryState.DELIVERED
    assert delivered.receipt is not None
    assert delivered.receipt.attempt_ordinal == 2
    assert [item[:2] for item in transport.dispatches] == [
        (intent.idempotency_key, 1),
        (intent.idempotency_key, 2),
    ]


def test_second_not_received_is_terminal_and_never_grants_third_attempt(tmp_path: Path) -> None:
    transport = FakeTransport(
        dispatch_outcomes=[OSError("unknown-1"), OSError("unknown-2")],
        reconcile_outcomes=["not-received", "not-received"],
    )
    (
        _store,
        exported,
        sink,
        intent,
        _authorization_value,
        broker,
        journal,
        coordinator,
        record,
    ) = _context(tmp_path, transport=transport)
    with pytest.raises(delivery.ExternalDeliveryOutcomeUnknownError):
        coordinator.dispatch_once(
            record,
            exported,
            _lease(broker, sink, intent, operation="dispatch", attempt_ordinal=1),
        )
    retry_ready = coordinator.reconcile(
        journal.inspect(intent.intent_id),
        exported,
        _lease(broker, sink, intent, operation="reconcile", attempt_ordinal=1),
    )
    with pytest.raises(delivery.ExternalDeliveryOutcomeUnknownError):
        coordinator.dispatch_once(
            retry_ready,
            exported,
            _lease(broker, sink, intent, operation="dispatch", attempt_ordinal=2),
        )
    terminal = coordinator.reconcile(
        journal.inspect(intent.intent_id),
        exported,
        _lease(broker, sink, intent, operation="reconcile", attempt_ordinal=2),
    )
    assert terminal.state is delivery.ExternalDeliveryState.TERMINAL_NOT_DELIVERED
    assert terminal.retry_authorized is False
    assert terminal.manual_review_required is False
    assert terminal.receipt is None
    with pytest.raises(delivery.ExternalDeliveryError, match="dispatch is not available"):
        coordinator.dispatch_once(
            terminal,
            exported,
            _lease(broker, sink, intent, operation="dispatch", attempt_ordinal=2),
        )


def test_forged_response_signature_remains_outcome_unknown(tmp_path: Path) -> None:
    transport = FakeTransport(
        dispatch_outcomes=["accepted"],
        signing_secret="forged-response-key",
    )
    (
        _store,
        exported,
        sink,
        intent,
        _authorization_value,
        broker,
        journal,
        coordinator,
        record,
    ) = _context(tmp_path, transport=transport)

    with pytest.raises(delivery.ExternalDeliveryOutcomeUnknownError):
        coordinator.dispatch_once(
            record,
            exported,
            _lease(broker, sink, intent, operation="dispatch", attempt_ordinal=1),
        )
    assert (
        journal.inspect(intent.intent_id).state
        is delivery.ExternalDeliveryState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    )


def test_wrong_secret_lease_fails_before_dispatch_claim(tmp_path: Path) -> None:
    transport = FakeTransport(dispatch_outcomes=["accepted"])
    (
        _store,
        exported,
        sink,
        intent,
        _authorization_value,
        broker,
        journal,
        coordinator,
        record,
    ) = _context(tmp_path, transport=transport)
    wrong = broker.issue(
        SECRET_REF,
        audience=sink.sink_id,
        binding=delivery.external_delivery_secret_binding(
            intent,
            operation="reconcile",
            attempt_ordinal=1,
        ),
        scope=intent.source_run_id,
        ttl_seconds=30,
        max_uses=1,
    )

    with pytest.raises(delivery.ExternalDeliveryError, match="secret lease differs"):
        coordinator.dispatch_once(record, exported, wrong)
    assert journal.inspect(intent.intent_id).state is delivery.ExternalDeliveryState.READY_INITIAL
    assert transport.dispatches == []


def test_stale_source_and_cross_sink_substitution_fail_before_side_effect(tmp_path: Path) -> None:
    transport = FakeTransport(dispatch_outcomes=["accepted"])
    (
        store,
        exported,
        sink,
        intent,
        authorization,
        broker,
        journal,
        coordinator,
        record,
    ) = _context(tmp_path, transport=transport)
    other_sink = _sink(endpoint_host="other-sink.example")
    other_intent = delivery.ExternalDeliveryIntent(
        **intent.model_dump(
            mode="python",
            by_alias=True,
            exclude={
                "intent_id",
                "intent_digest",
                "idempotency_key",
                "sink_id",
                "sink_digest",
            },
        ),
        sinkId=other_sink.sink_id,
        sinkDigest=other_sink.sink_digest,
    )
    other_coordinator = delivery.ExternalDeliveryCoordinator(
        sinks=delivery.ExternalDeliverySinkRegistry((other_sink,)),
        authorizations=delivery.ExternalDeliveryAuthorizationRegistry((authorization,)),
        secrets=broker,
        journal=journal,
        transport=transport,
        clock=lambda: NOW,
    )
    with pytest.raises(delivery.ExternalDeliveryError, match="authorization differs"):
        other_coordinator.register(exported, other_intent, authorization)

    store.write_json("later-phase.json", {"phase": "later"})
    store.append_event("test.later-phase.created", {})
    store.seal()
    with pytest.raises((delivery.ExternalDeliveryError, ValueError), match="root digest differs"):
        coordinator.dispatch_once(
            record,
            exported,
            _lease(broker, sink, intent, operation="dispatch", attempt_ordinal=1),
        )
    assert journal.inspect(intent.intent_id).state is delivery.ExternalDeliveryState.READY_INITIAL
    assert transport.dispatches == []


@pytest.mark.parametrize(
    ("delivery_endpoint", "reconciliation_endpoint"),
    [
        ("http://sink.example/v1/findings", "https://sink.example/v1/status"),
        ("https://user:secret@sink.example/v1/findings", "https://sink.example/v1/status"),
        ("https://sink.example/v1/findings?tenant=x", "https://sink.example/v1/status"),
        ("https://sink.example/v1/findings", "https://other.example/v1/status"),
    ],
)
def test_sink_registry_rejects_unsafe_or_cross_origin_endpoints(
    delivery_endpoint: str,
    reconciliation_endpoint: str,
) -> None:
    with pytest.raises(ValueError):
        delivery.ExternalDeliverySink(
            sinkType="siem",
            deliveryEndpoint=delivery_endpoint,
            reconciliationEndpoint=reconciliation_endpoint,
            secretRefFingerprint=SecretBroker.fingerprint(SECRET_REF),
        )


def test_journal_rejects_tampering_and_exact_registration_is_idempotent(tmp_path: Path) -> None:
    transport = FakeTransport(dispatch_outcomes=["accepted"])
    (
        _store,
        exported,
        _sink_value,
        intent,
        authorization,
        _broker,
        journal,
        coordinator,
        record,
    ) = _context(tmp_path, transport=transport)
    assert coordinator.register(exported, intent, authorization) == record

    connection = sqlite3.connect(journal.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE external_delivery_events SET occurred_at = ? WHERE intent_id = ?",
                ("2026-08-11T00:00:00Z", intent.intent_id),
            )
    finally:
        connection.close()
    assert journal.inspect(intent.intent_id) == record


def test_authorization_registry_rejects_unregistered_exactly_bound_authorization(
    tmp_path: Path,
) -> None:
    store = _sealed_validation_run(tmp_path / "runs")
    exported = _export(store)
    sink = _sink()
    intent = delivery.build_external_delivery_intent(exported, sink)
    authorization = _authorization(intent)
    broker = SecretBroker(clock=lambda: NOW)
    broker.register(SECRET_REF, SECRET_VALUE)
    coordinator = delivery.ExternalDeliveryCoordinator(
        sinks=delivery.ExternalDeliverySinkRegistry((sink,)),
        authorizations=delivery.ExternalDeliveryAuthorizationRegistry(()),
        secrets=broker,
        journal=delivery.SQLiteExternalDeliveryJournal(
            tmp_path / "delivery.sqlite3",
            clock=lambda: NOW,
        ),
        transport=FakeTransport(dispatch_outcomes=[]),
        clock=lambda: NOW,
    )

    with pytest.raises(delivery.ExternalDeliveryError, match="authorization was rejected"):
        coordinator.register(exported, intent, authorization)
