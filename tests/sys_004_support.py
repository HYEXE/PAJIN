"""Explicit disposable-fixture operator and signed release; never used by product dispatch."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
from pajin.system_aslr.capability import aslr_capability_bundle
from pajin.system_aslr.models import TOOL_ID, AslrInput
from pajin.system_aslr.runtime import (
    AslrActivation,
    AslrOperatorAuthority,
    SignedAslrApproval,
    approval_for_review,
    approval_message,
    prepare_aslr_action,
)
from pajin.system_aslr.tool import AslrReadTool


def local_fixture_activation(tool: AslrReadTool, now: datetime | None = None) -> AslrActivation:
    now = now or datetime.now(UTC)
    bundle = aslr_capability_bundle(tool)
    policy = CapabilityLifecyclePolicy.reference_policy()
    signers = []
    for role in (CapabilityLifecycleKeyRole.PUBLISHER, CapabilityLifecycleKeyRole.REVIEWER):
        seed = os.urandom(32)
        key = CapabilityLifecycleTrustKey(
            keyId="sys-004.fixture." + role.value,
            principalId="sys-004.fixture." + role.value,
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
                b"SYS-004 explicitly invoked authenticated agent fixture only"
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
    return AslrActivation(bundle, lifecycle, release.statement.reference())


def fixture_campaign(value: AslrInput) -> CampaignManifest:
    now = datetime.now(UTC)
    return CampaignManifest.model_validate(
        {
            "apiVersion": "pajin.dev/v1alpha1",
            "kind": "Campaign",
            "metadata": {"name": "sys-004-run"},
            "spec": {
                "mode": "ctf",
                "autonomy": "supervised",
                "authorization": {
                    "approvedBy": "sys-004-fixture-operator",
                    "approvedAt": now,
                    "expiresAt": now + timedelta(minutes=30),
                    "evidence": "explicit-authenticated-disposable-fixture-invocation",
                },
                "targets": [
                    {"type": "system-host-agent", "id": "sys-004", "endpoint": value.target}
                ],
                "scope": {"allow": [value.target, value.scope_authority]},
                "objectives": ["Read one authenticated Linux kernel ASLR setting"],
                "rulesOfEngagement": {
                    "maxToolRiskTier": "T2",
                    "allowedMethods": ["GET", "CONNECT"],
                    "allowPrivateNetworks": True,
                },
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
    tool: AslrReadTool,
    value: AslrInput,
    activation: AslrActivation | None = None,
    operator: Ed25519PrivateKey | None = None,
):
    activation = activation or local_fixture_activation(tool)
    campaign = fixture_campaign(value)
    ledger = CapabilityLedger(max_depth=0)
    grant = ledger.issue_root(
        campaign, subject="sys-004-planner", tools={TOOL_ID}, targets={value.target}
    )
    store = RunStore.create(root / "runs", campaign.metadata.name)
    graph = SQLiteGraphStore(
        root / store.run_id / "graph.sqlite3", campaign_id=campaign.metadata.name
    )
    action = prepare_aslr_action(
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
        action, activation, public_key=public, approved_by="sys-004-fixture-operator"
    )
    signed = SignedAslrApproval(
        approval=approval, signature=operator.sign(approval_message(approval)).hex()
    )
    authority = AslrOperatorAuthority(
        activation=activation,
        public_key=public,
        operator_id="sys-004-fixture-operator",
        signed=signed,
        campaign=campaign,
        grant=grant,
        request=action.request,
        tool=tool,
    )
    return action, authority, graph, store
