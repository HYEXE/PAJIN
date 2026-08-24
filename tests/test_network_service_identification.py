from __future__ import annotations

import importlib.util
import json
from base64 import b64encode
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import ValidationError

from pajin.capabilities.authorities import CapabilityAuthorityRole
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import CapabilityMaturity, CapabilitySideEffectClass
from pajin.capabilities.network_service import (
    NETWORK_SERVICE_CAPABILITY_ID,
    NetworkServiceCapabilityActivation,
    NetworkServiceIdentificationBinding,
    NetworkServiceIdentificationError,
    NetworkServiceIdentificationPreparation,
    NetworkServiceProtocolBudget,
    activate_network_service_capability,
    network_service_capability_bundle,
    prepare_network_service_identification,
    registered_network_service_capability_definition,
    registered_network_service_capability_domain_classification,
    registered_network_service_identification_binding,
    resolve_network_service_capability_domain_classification,
    resolve_network_service_identification_binding,
)
from pajin.discovery import (
    NetworkAddressFamily,
    NetworkHostServiceSurface,
    NetworkTransportProtocol,
    network_host_surface_locator,
    network_port_surface_locator,
    network_service_surface_locator,
    typed_network_host_service_surface,
)
from pajin.domain.models import CampaignManifest, ToolRequest, ToolRiskTier
from pajin.domain.security_domain import SecurityDomain
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import EGRESS_HTTPS_CONNECT_RECEIPT_VERSION, ToolRegistry
from pajin.tools.gateway import ToolGateway
from pajin.tools.network import (
    MAX_NETWORK_SERVICE_BANNER_BYTES,
    NETWORK_PASSIVE_BANNER_PROFILE,
    NetworkServiceIdentificationInput,
    NetworkServiceIdentificationTool,
    network_service_scope_allow_rule,
    network_service_scope_target,
)

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
HOST = "8.8.8.8"
PORT = 22

_BINDING_FALSE_MARKERS = (
    "nameResolutionAuthorized",
    "udpAuthorized",
    "applicationProtocolWriteAuthorized",
    "portEnumerationAuthorized",
    "rawSocketAuthorized",
    "ambientCredentialUseAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "workerSelectionAuthorized",
    "graphAdmissionAuthorized",
    "runtimeSupportAssertedByBinding",
    "executionAuthorized",
)
_PREPARATION_FALSE_MARKERS = (
    "workerJobMaterialized",
    "egressPolicyMaterialized",
    "nameResolutionPerformed",
    "networkConnectionOpened",
    "serviceObservationProduced",
    "evidenceSealed",
    "graphAdmitted",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "gatewayDispatchAuthorized",
    "workerSelectionAuthorized",
    "executionAuthorized",
)


def _seed(label: str) -> bytes:
    return sha256(f"network-service:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"network-service.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
        notAfter=NOW + timedelta(days=30),
    )


def _activation() -> tuple[NetworkServiceCapabilityActivation, CapabilityReleaseRef]:
    tools = ToolRegistry()
    tools.register(NetworkServiceIdentificationTool())
    bundle = network_service_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="network-service.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="network-service.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=_seed("publisher"),
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=_seed("reviewer"),
    )
    review = CapabilityReviewStatement(
        capability=bundle.capability(),
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"network-service-review").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(days=2),
        expiresAt=NOW + timedelta(days=5),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=bundle.capability(),
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(signed_review.statement.review_digest,),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=NOW - timedelta(days=1),
    )
    signed_bundle = CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(signed_bundle,),
        clock=lambda: NOW,
    )
    release_ref = signed_bundle.release.statement.reference()
    return (
        activate_network_service_capability(
            bundle=bundle,
            lifecycle=lifecycle,
            release=release_ref,
        ),
        release_ref,
    )


def _surface(
    *,
    family: NetworkAddressFamily = NetworkAddressFamily.IPV4,
    host: str = HOST,
    protocol: NetworkTransportProtocol = NetworkTransportProtocol.TCP,
    port: int = PORT,
) -> NetworkHostServiceSurface:
    locator = network_port_surface_locator(
        host=network_host_surface_locator(address_family=family, host=host),
        transport_protocol=protocol,
        port=port,
    )
    return typed_network_host_service_surface(locator=locator)


def _campaign(
    sample_campaign: CampaignManifest,
    *,
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    connect_allowed: bool = True,
    allow_private_networks: bool = False,
) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"] = {
        "allow": allow
        if allow is not None
        else [
            network_service_scope_allow_rule(
                address_family="ipv4",
                host=HOST,
                port=PORT,
            )
        ],
        "deny": deny or [],
    }
    methods = set(payload["spec"]["rulesOfEngagement"]["allowedMethods"])
    if connect_allowed:
        methods.add("CONNECT")
    else:
        methods.discard("CONNECT")
    payload["spec"]["rulesOfEngagement"]["allowedMethods"] = sorted(methods)
    payload["spec"]["rulesOfEngagement"]["allowPrivateNetworks"] = allow_private_networks
    return CampaignManifest.model_validate(payload)


def _prepare(sample_campaign: CampaignManifest) -> NetworkServiceIdentificationPreparation:
    activation, release = _activation()
    return prepare_network_service_identification(
        activation=activation,
        release=release,
        campaign=_campaign(sample_campaign),
        surface=_surface(),
        request_id="tool_network_service_prepare",
        agent_id="agent:network-service",
    )


def _tool_input() -> NetworkServiceIdentificationInput:
    return NetworkServiceIdentificationInput(
        addressFamily="ipv4",
        host=HOST,
        transportProtocol="tcp",
        port=PORT,
        protocolProfile=NETWORK_PASSIVE_BANNER_PROFILE,
        connectTimeoutMilliseconds=5000,
        readTimeoutMilliseconds=2000,
        maxBannerBytes=MAX_NETWORK_SERVICE_BANNER_BYTES,
    )


def _tool_request() -> ToolRequest:
    return ToolRequest(
        request_id="tool_network_service_contract",
        agent_id="agent:network-service",
        tool_id=NetworkServiceIdentificationTool.spec.tool_id,
        target=network_service_scope_target(
            address_family="ipv4",
            host=HOST,
            port=PORT,
        ),
        method="CONNECT",
        arguments=_tool_input().model_dump(mode="json", by_alias=True),
    )


def _worker_result(output: object, *, network_log: str = "") -> WorkerResult:
    return WorkerResult(
        execution_id="exec_network_service_contract",
        backend="docker" if network_log else "contract-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(output),
        network_log=network_log,
        started_at=NOW,
        finished_at=NOW,
    )


def _connected_output(banner: bytes = b"SSH-2.0-OpenSSH\r\n") -> dict[str, object]:
    return {
        "target": _tool_request().target,
        "addressFamily": "ipv4",
        "host": HOST,
        "transportProtocol": "tcp",
        "port": PORT,
        "protocolProfile": NETWORK_PASSIVE_BANNER_PROFILE,
        "connected": True,
        "bannerBytes": len(banner),
        "bannerBase64": b64encode(banner).decode("ascii"),
        "bannerSha256": sha256(banner).hexdigest(),
        "serviceName": "ssh",
    }


def test_capability_and_binding_pin_exact_network_authority() -> None:
    definition = registered_network_service_capability_definition()
    binding = registered_network_service_identification_binding()
    tools = ToolRegistry()
    tools.register(NetworkServiceIdentificationTool())
    bundle = network_service_capability_bundle(tools)

    assert definition.capability_id == NETWORK_SERVICE_CAPABILITY_ID
    assert definition.supported_surface_types == ("network-port",)
    assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.network_access is True
    assert definition.approval_required is True
    assert {item.role for item in bundle.authorities.capabilities()[0].authorities} == set(
        CapabilityAuthorityRole
    )
    assert binding.capability == bundle.capability()
    assert binding.capability_domain_classification.domain_classification.domain is (
        SecurityDomain.NETWORK
    )
    assert binding.worker_profile.domain_classification.domain is SecurityDomain.NETWORK
    assert binding.worker_profile.profile_id == "pajin.worker-boundary.network.minimum"
    assert binding.protocol_budget.application_write_bytes == 0
    assert all(
        binding.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _BINDING_FALSE_MARKERS
    )
    classification = registered_network_service_capability_domain_classification()
    assert (
        resolve_network_service_capability_domain_classification(classification.reference())
        == classification
    )
    assert resolve_network_service_identification_binding(binding.reference()) == binding


def test_preparation_binds_surface_current_scope_budget_and_signed_capability(
    sample_campaign: CampaignManifest,
) -> None:
    preparation = _prepare(sample_campaign)
    request = preparation.prepared_action.request

    assert preparation.state == "prepared-not-authorized"
    assert preparation.surface == _surface()
    assert preparation.campaign_scope.scope == _campaign(sample_campaign).spec.scope
    assert preparation.matched_allow_rule == network_service_scope_allow_rule(
        address_family="ipv4",
        host=HOST,
        port=PORT,
    )
    assert request.method == "CONNECT"
    assert request.target == network_service_scope_target(
        address_family="ipv4",
        host=HOST,
        port=PORT,
    )
    assert request.arguments == _tool_input().model_dump(mode="json", by_alias=True)
    assert preparation.protocol_budget == NetworkServiceProtocolBudget()
    assert all(
        preparation.model_dump(mode="json", by_alias=True)[alias] is False
        for alias in _PREPARATION_FALSE_MARKERS
    )


def test_preparation_preserves_exact_ipv6_authority(
    sample_campaign: CampaignManifest,
) -> None:
    host = "2001:4860:4860::8888"
    activation, release = _activation()
    preparation = prepare_network_service_identification(
        activation=activation,
        release=release,
        campaign=_campaign(
            sample_campaign,
            allow=[
                network_service_scope_allow_rule(
                    address_family="ipv6",
                    host=host,
                    port=PORT,
                )
            ],
        ),
        surface=_surface(family=NetworkAddressFamily.IPV6, host=host),
        request_id="tool_network_service_ipv6",
        agent_id="agent:network-service",
    )

    assert preparation.matched_allow_rule == f"https://[{host}]:{PORT}/**"
    assert preparation.prepared_action.request.target == f"https://[{host}]:{PORT}/"
    assert preparation.prepared_action.request.arguments["addressFamily"] == "ipv6"
    assert preparation.prepared_action.request.arguments["host"] == host
    assert (
        NetworkServiceIdentificationPreparation.model_validate(
            preparation.model_dump(mode="json", by_alias=True)
        )
        == preparation
    )


@pytest.mark.parametrize(
    ("surface", "match"),
    (
        (
            _surface(
                family=NetworkAddressFamily.DNS_NAME,
                host="service.example.test",
            ),
            "IP-literal TCP",
        ),
        (
            _surface(protocol=NetworkTransportProtocol.UDP),
            "IP-literal TCP",
        ),
    ),
)
def test_preparation_rejects_dns_resolution_and_udp_authority(
    sample_campaign: CampaignManifest,
    surface: NetworkHostServiceSurface,
    match: str,
) -> None:
    activation, release = _activation()
    with pytest.raises(NetworkServiceIdentificationError, match=match):
        prepare_network_service_identification(
            activation=activation,
            release=release,
            campaign=_campaign(sample_campaign),
            surface=surface,
            request_id="tool_network_service_rejected",
            agent_id="agent:network-service",
        )


def test_preparation_rejects_declared_service_as_if_it_were_an_unknown_port(
    sample_campaign: CampaignManifest,
) -> None:
    activation, release = _activation()
    locator = network_service_surface_locator(
        host=network_host_surface_locator(
            address_family=NetworkAddressFamily.IPV4,
            host=HOST,
        ),
        transport_protocol=NetworkTransportProtocol.TCP,
        port=PORT,
        service_name="ssh",
    )
    with pytest.raises(NetworkServiceIdentificationError, match="network-port"):
        prepare_network_service_identification(
            activation=activation,
            release=release,
            campaign=_campaign(sample_campaign),
            surface=typed_network_host_service_surface(locator=locator),
            request_id="tool_network_service_known",
            agent_id="agent:network-service",
        )


@pytest.mark.parametrize(
    ("campaign_kwargs", "match"),
    (
        ({"allow": ["https://8.8.8.8:22/"]}, "exact host-wide"),
        (
            {
                "deny": ["https://8.8.8.8:22/admin"],
            },
            "deny rule",
        ),
        ({"connect_allowed": False}, "CONNECT authority"),
    ),
)
def test_preparation_rejects_scope_and_protocol_privilege_drift(
    sample_campaign: CampaignManifest,
    campaign_kwargs: dict[str, object],
    match: str,
) -> None:
    activation, release = _activation()
    with pytest.raises((NetworkServiceIdentificationError, ValidationError), match=match):
        prepare_network_service_identification(
            activation=activation,
            release=release,
            campaign=_campaign(sample_campaign, **campaign_kwargs),
            surface=_surface(),
            request_id="tool_network_service_scope_rejected",
            agent_id="agent:network-service",
        )


def test_private_address_requires_explicit_campaign_private_network_authority(
    sample_campaign: CampaignManifest,
) -> None:
    host = "10.0.0.10"
    rule = network_service_scope_allow_rule(
        address_family="ipv4",
        host=host,
        port=PORT,
    )
    activation, release = _activation()

    with pytest.raises(NetworkServiceIdentificationError, match="private-network"):
        prepare_network_service_identification(
            activation=activation,
            release=release,
            campaign=_campaign(sample_campaign, allow=[rule]),
            surface=_surface(host=host),
            request_id="tool_network_service_private_rejected",
            agent_id="agent:network-service",
        )

    accepted = prepare_network_service_identification(
        activation=activation,
        release=release,
        campaign=_campaign(
            sample_campaign,
            allow=[rule],
            allow_private_networks=True,
        ),
        surface=_surface(host=host),
        request_id="tool_network_service_private_accepted",
        agent_id="agent:network-service",
    )
    assert accepted.campaign_scope.allow_private_networks is True


@pytest.mark.parametrize("alias", _BINDING_FALSE_MARKERS)
def test_binding_rejects_authority_marker_escalation(alias: str) -> None:
    payload = registered_network_service_identification_binding().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    payload["bindingDigest"] = ""
    with pytest.raises(ValidationError):
        NetworkServiceIdentificationBinding.model_validate(payload)


def test_preparation_rejects_surface_scope_budget_and_digest_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    original = _prepare(sample_campaign).model_dump(mode="json", by_alias=True)
    mutations = (
        ("protocolBudget", "maxBannerBytes", 2048),
        ("campaignScope", "campaignDigest", "0" * 64),
        ("preparedAction", "requestDigest", "0" * 64),
        (None, "matchedAllowRule", "https://8.8.8.8:23/**"),
        (None, "preparationDigest", "0" * 64),
    )
    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            NetworkServiceIdentificationPreparation.model_validate(payload)


def test_tool_prepares_network_none_job_and_validates_host_connect_receipt() -> None:
    request = _tool_request()
    tool = NetworkServiceIdentificationTool()
    job = tool.prepare(request)
    banner = b"SSH-2.0-OpenSSH\r\n"
    authority = f"{HOST}:{PORT}"
    network_log = "\n".join(
        (
            json.dumps({"event": "ready", "port": 8080}),
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": EGRESS_HTTPS_CONNECT_RECEIPT_VERSION,
                    "sequence": 1,
                    "method": "CONNECT",
                    "authority": authority,
                    "authoritySha256": sha256(authority.encode()).hexdigest(),
                    "address": HOST,
                    "applicationVisibility": "opaque",
                    "methodEnforcement": "trusted-worker-only",
                    "pathEnforcement": "authority-only",
                }
            ),
        )
    )
    worker_result = _worker_result(_connected_output(banner), network_log=network_log)
    result = tool.interpret(request, worker_result)

    assert job.command == ["network-service-identify"]
    assert job.network is NetworkMode.NONE
    assert job.egress_policy is None
    assert json.loads(job.stdin)["maxBannerBytes"] == MAX_NETWORK_SERVICE_BANNER_BYTES
    assert result.success is True
    assert result.data["serviceName"] == "ssh"
    tool.validate_trusted_execution(
        request,
        result,
        worker_result,
        network_log_trusted=True,
    )
    with pytest.raises(ValueError, match="host-observed"):
        tool.validate_trusted_execution(
            request,
            result,
            worker_result,
            network_log_trusted=False,
        )


def test_tool_and_gateway_reject_target_drift_and_narrow_connect_egress(
    sample_campaign: CampaignManifest,
) -> None:
    tool = NetworkServiceIdentificationTool()
    request = _tool_request()
    campaign = _campaign(sample_campaign)

    with pytest.raises(ValueError, match="exact coordinate"):
        tool.prepare(request.model_copy(update={"target": "https://8.8.8.8:23/"}))

    job = ToolGateway._grant_egress(
        campaign,
        WorkerJob(image="pajin-worker:dev", command=["network-service-identify"]),
        request=request,
        request_cost=1,
        response_byte_limit=MAX_NETWORK_SERVICE_BANNER_BYTES,
    )
    assert job.network is NetworkMode.EGRESS_PROXY
    assert job.egress_policy is not None
    assert job.egress_policy.allow == [
        network_service_scope_allow_rule(
            address_family="ipv4",
            host=HOST,
            port=PORT,
        )
    ]
    assert job.egress_policy.deny == []
    assert job.egress_policy.max_requests == 1
    assert job.egress_policy.max_response_bytes == MAX_NETWORK_SERVICE_BANNER_BYTES

    denied_campaign = _campaign(
        sample_campaign,
        deny=["https://8.8.8.8:22/admin"],
    )
    with pytest.raises(ValueError, match="deny rule"):
        ToolGateway._grant_egress(
            denied_campaign,
            WorkerJob(image="pajin-worker:dev", command=["network-service-identify"]),
            request=request,
            request_cost=1,
            response_byte_limit=MAX_NETWORK_SERVICE_BANNER_BYTES,
        )

    without_connect = _campaign(sample_campaign, connect_allowed=False)
    with pytest.raises(ValueError, match="reviewed Campaign authority"):
        ToolGateway._grant_egress(
            without_connect,
            WorkerJob(image="pajin-worker:dev", command=["network-service-identify"]),
            request=request,
            request_cost=1,
            response_byte_limit=MAX_NETWORK_SERVICE_BANNER_BYTES,
        )

    with pytest.raises(ValueError, match="exact HTTPS authority"):
        ToolGateway._grant_egress(
            campaign,
            WorkerJob(image="pajin-worker:dev", command=["network-service-identify"]),
            request=request.model_copy(update={"target": "https://8.8.8.8:22/path"}),
            request_cost=1,
            response_byte_limit=MAX_NETWORK_SERVICE_BANNER_BYTES,
        )


def test_tool_rejects_malformed_banner_identity() -> None:
    output = _connected_output()
    output["bannerSha256"] = "0" * 64
    result = NetworkServiceIdentificationTool().interpret(
        _tool_request(),
        _worker_result(output),
    )

    assert result.success is False
    assert result.error is not None
    assert "invalid Network service identification output" in result.error


def _worker_entry() -> ModuleType:
    path = Path("containers/worker/worker_entry.py")
    spec = importlib.util.spec_from_file_location("pajin_network_worker_entry", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_worker_uses_only_proxy_connect_and_reads_bounded_passive_banner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    sent: list[bytes] = []
    coordinates: list[tuple[str, int]] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.responses = [
                b"HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-test\r\n",
                b"",
            ]

        def __enter__(self) -> FakeSocket:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, value: bytes) -> None:
            sent.append(value)

        def recv(self, _size: int) -> bytes:
            return self.responses.pop(0)

    def connect(coordinate: tuple[str, int], *, timeout: float) -> FakeSocket:
        assert timeout == 5
        coordinates.append(coordinate)
        return FakeSocket()

    monkeypatch.setenv("HTTPS_PROXY", "http://egress-proxy:8080")
    monkeypatch.setattr(worker.socket, "create_connection", connect)
    payload = {
        "target": _tool_request().target,
        **_tool_input().model_dump(mode="json", by_alias=True),
    }

    output = worker.network_service_identify(payload)

    assert coordinates == [("egress-proxy", 8080)]
    assert sent == ["CONNECT 8.8.8.8:22 HTTP/1.1\r\nHost: 8.8.8.8:22\r\n\r\n".encode("ascii")]
    assert output["connected"] is True
    assert output["serviceName"] == "ssh"
    assert output["bannerBytes"] == len(b"SSH-2.0-test\r\n")


def test_worker_rejects_dns_and_budget_injection_before_opening_a_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    monkeypatch.setattr(
        worker.socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("socket must not open"),
    )
    payload = {
        "target": "https://service.example.test:22/",
        **_tool_input().model_dump(mode="json", by_alias=True),
    }
    payload["host"] = "service.example.test"
    with pytest.raises(ValueError, match="IP literal"):
        worker.network_service_identify(payload)

    payload = {
        "target": _tool_request().target,
        **_tool_input().model_dump(mode="json", by_alias=True),
    }
    payload["maxBannerBytes"] = MAX_NETWORK_SERVICE_BANNER_BYTES + 1
    with pytest.raises(ValueError, match="fixed passive profile"):
        worker.network_service_identify(payload)
