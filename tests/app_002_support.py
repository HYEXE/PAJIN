"""Explicit disposable-fixture operator and signed release; never used by product dispatch."""

from __future__ import annotations

import os
import struct
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.application_elf.capability import elf_capability_bundle
from pajin.application_elf.models import TOOL_ID, ELFInput
from pajin.application_elf.runtime import (
    ELFActivation,
    ELFOperatorAuthority,
    SignedELFApproval,
    approval_for_review,
    approval_message,
    prepare_elf_action,
)
from pajin.application_elf.tool import ELFCustody, ELFHeaderTool
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import CapabilityMaturity
from pajin.domain.models import CampaignManifest
from pajin.graph import SQLiteGraphStore
from pajin.policy.capability import CapabilityLedger
from pajin.runtime.store import RunStore


def seeded_elf(*, machine: int = 62, kind: int = 2, entry: int = 0x401080) -> bytes:
    return (
        b"\x7fELF\x02\x01\x01"
        + bytes(9)
        + struct.pack("<HHIQQQIHHHHHH", kind, machine, 1, entry, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    )


def private_custody(directory: Path, content: bytes) -> tuple[ELFCustody, ELFInput]:
    directory.mkdir(mode=0o700, parents=True)
    directory.chmod(0o700)
    value = ELFInput(artifactSha256=sha256(content).hexdigest(), artifactBytes=len(content))
    destination = directory / (value.artifact_sha256 + ".elf")
    with destination.open("xb") as handle:
        destination.chmod(0o600)
        handle.write(content)
    return ELFCustody(directory.absolute(), (value,)), value


def local_fixture_activation(tool: ELFHeaderTool, now: datetime | None = None) -> ELFActivation:
    now = now or datetime.now(UTC)
    bundle = elf_capability_bundle(tool)
    policy = CapabilityLifecyclePolicy.reference_policy()
    signers = []
    for role in (CapabilityLifecycleKeyRole.PUBLISHER, CapabilityLifecycleKeyRole.REVIEWER):
        seed = os.urandom(32)
        key = CapabilityLifecycleTrustKey(
            keyId="app-002.fixture." + role.value,
            principalId="app-002.fixture." + role.value,
            role=role,
            publicKeyBase64url=capability_lifecycle_public_key(seed),
            state=CapabilityLifecycleKeyState.ACTIVE,
            notBefore=now - timedelta(hours=1),
            notAfter=now + timedelta(hours=1),
        )
        signers.append(CapabilityLifecycleSigner.from_private_key_bytes(key=key, private_key=seed))
    publisher, reviewer = signers
    review = reviewer.sign_review(
        CapabilityReviewStatement(
            capability=bundle.reference,
            targetMaturity=CapabilityMaturity.EXPERIMENTAL,
            sequence=1,
            previousReleaseDigest=None,
            policyDigest=policy.digest,
            reviewerPrincipalId=reviewer.key.principal_id,
            checklistDigest=sha256(
                b"APP-002 explicitly invoked disposable fixture only"
            ).hexdigest(),
            decision=CapabilityReviewDecision.APPROVED,
            issuedAt=now - timedelta(seconds=2),
            expiresAt=now + timedelta(minutes=45),
        )
    )
    release = publisher.sign_release(
        CapabilityReleaseStatement(
            capability=bundle.reference,
            maturity=CapabilityMaturity.EXPERIMENTAL,
            sequence=1,
            previousReleaseDigest=None,
            policyDigest=policy.digest,
            reviewDigests=(review.statement.review_digest,),
            publisherPrincipalId=publisher.key.principal_id,
            issuedAt=now - timedelta(seconds=1),
        )
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher.key, reviewer.key),
        releases=(CapabilityReleaseBundle(release=release, reviews=(review,)),),
        clock=lambda: now,
    )
    return ELFActivation(bundle, lifecycle, release.statement.reference())


def fixture_campaign(value: ELFInput) -> CampaignManifest:
    now = datetime.now(UTC)
    return CampaignManifest.model_validate(
        {
            "apiVersion": "pajin.dev/v1alpha1",
            "kind": "Campaign",
            "metadata": {"name": "app-002-run"},
            "spec": {
                "mode": "ctf",
                "autonomy": "supervised",
                "authorization": {
                    "approvedBy": "app-002-fixture-operator",
                    "approvedAt": now,
                    "expiresAt": now + timedelta(minutes=30),
                    "evidence": "explicit-offline-disposable-fixture-invocation",
                },
                "targets": [
                    {"type": "application-binary", "id": "app-002", "endpoint": value.target}
                ],
                "scope": {"allow": [value.target]},
                "objectives": ["Read one immutable ELF header"],
                "rulesOfEngagement": {"maxToolRiskTier": "T2", "allowedMethods": ["GET"]},
                "budgets": {
                    "durationSeconds": 1800,
                    "maxCostUsd": 0,
                    "maxAgents": 1,
                    "maxSpawnDepth": 0,
                    "maxToolCalls": 1,
                },
                "outputs": [],
            },
        }
    )


def fixture_action(
    root: Path,
    tool: ELFHeaderTool,
    value: ELFInput,
    activation: ELFActivation | None = None,
    operator: Ed25519PrivateKey | None = None,
):
    activation = activation or local_fixture_activation(tool)
    campaign = fixture_campaign(value)
    ledger = CapabilityLedger(max_depth=0)
    grant = ledger.issue_root(
        campaign, subject="app-002-planner", tools={TOOL_ID}, targets={value.target}
    )
    store = RunStore.create(root / "runs", campaign.metadata.name)
    graph = SQLiteGraphStore(
        root / store.run_id / "graph.sqlite3", campaign_id=campaign.metadata.name
    )
    action = prepare_elf_action(
        activation=activation,
        tool=tool,
        value=value,
        campaign=campaign,
        grant=grant,
        graph=graph,
        store=store,
    )
    operator = operator or Ed25519PrivateKey.generate()
    public = operator.public_key().public_bytes_raw()
    approval = approval_for_review(
        action, activation, public_key=public, approved_by="app-002-fixture-operator"
    )
    signed = SignedELFApproval(
        approval=approval, signature=operator.sign(approval_message(approval)).hex()
    )
    authority = ELFOperatorAuthority(
        activation=activation,
        public_key=public,
        operator_id="app-002-fixture-operator",
        signed=signed,
        campaign=campaign,
        grant=grant,
        request=action.request,
        tool=tool,
    )
    return action, authority, graph, store
