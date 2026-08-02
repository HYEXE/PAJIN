"""Concrete OWASP ZAP registration and bounded SARIF 2.1.0 normalization."""

from __future__ import annotations

from hashlib import sha256
from typing import Annotated, Literal, Self, cast
from urllib.parse import parse_qsl, urlsplit

from pydantic import ConfigDict, Field, model_validator

from pajin.benchmark.models import benchmark_digest, canonical_benchmark_json
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes

ZAP_SCANNER_REGISTRATION_API_VERSION: Literal[
    "pajin.dev/zap-scanner-registration/v1alpha1"
] = "pajin.dev/zap-scanner-registration/v1alpha1"
ZAP_SARIF_NORMALIZATION_API_VERSION: Literal[
    "pajin.dev/zap-sarif-normalization/v1alpha1"
] = "pajin.dev/zap-sarif-normalization/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageId = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_MAX_SARIF_BYTES = 16 * 1024 * 1024
_MAX_REGISTRATION_BYTES = 256 * 1024
_MAX_NORMALIZATION_BYTES = 4 * 1024 * 1024
_TARGET_PATH = "/v1/users/lookup"
_SQL_INJECTION_RULE_IDS = frozenset(
    {
        "40018",
        "40019",
        "40020",
        "40021",
        "40022",
        "90018",
        "90019",
        "90020",
        "90024",
        "90025",
        "90026",
        "90027",
        "90028",
        "90029",
        "90030",
        "90031",
        "90033",
        "90034",
        "90035",
    }
)

ZAP_AUTOMATION_PLAN = b"""env:
  contexts:
    - name: p0-e2b
      urls:
        - http://target:8080
jobs:
  - type: requestor
    requests:
      - url: http://target:8080/v1/users/lookup?id=1
        name: seed-p0-d1-lookup
        method: GET
        responseCode: 200
  - type: activeScan
    parameters:
      context: p0-e2b
      url: http://target:8080/v1/users/lookup?id=1
      policy: Default Policy
      maxScanDurationInMins: 2
  - type: report
    parameters:
      template: sarif-json
      reportDir: /zap/wrk
      reportFile: p0-e2b.sarif.json
      displayReport: false
"""


class ZAPScannerRegistration(StrictModel):
    """Code-owned product identity plus one immutable runtime image."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/zap-scanner-registration/v1alpha1"] = Field(
        default=ZAP_SCANNER_REGISTRATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ZAPScannerRegistration"] = "ZAPScannerRegistration"
    registration_id: str = Field(default="", alias="registrationId", max_length=110)
    registration_digest: str = Field(
        default="", alias="registrationDigest", max_length=64
    )
    scanner_id: Literal["scanner:owasp-zap"] = Field(
        default="scanner:owasp-zap", alias="scannerId"
    )
    scanner_version: Literal["2.17.0"] = Field(
        default="2.17.0", alias="scannerVersion"
    )
    scanner_image: Literal["ghcr.io/zaproxy/zaproxy:stable"] = Field(
        default="ghcr.io/zaproxy/zaproxy:stable", alias="scannerImage"
    )
    scanner_image_id: _ImageId = Field(alias="scannerImageId")
    executable_artifact_sha256: _Sha256 = Field(alias="executableArtifactSha256")
    configuration_digest: _Sha256 = Field(alias="configurationDigest")
    parser_contract_digest: _Sha256 = Field(alias="parserContractDigest")
    output_format: Literal["sarif-2.1.0"] = Field(
        default="sarif-2.1.0", alias="outputFormat"
    )
    target_url: Literal["http://target:8080/v1/users/lookup?id=1"] = Field(
        default="http://target:8080/v1/users/lookup?id=1", alias="targetUrl"
    )

    @model_validator(mode="after")
    def bind_registration(self) -> Self:
        if (
            self.executable_artifact_sha256 != self.scanner_image_id.removeprefix("sha256:")
            or self.configuration_digest != sha256(ZAP_AUTOMATION_PLAN).hexdigest()
        ):
            raise ValueError("ZAP Scanner artifact or configuration differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registration_id", "registration_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.zap-scanner-registration/v1",
            material,
            max_bytes=_MAX_REGISTRATION_BYTES,
        )
        registration_id = f"zap-scanner-registration:{digest}"
        if self.registration_digest and self.registration_digest != digest:
            raise ValueError("ZAP Scanner Registration Digest differs")
        if self.registration_id and self.registration_id != registration_id:
            raise ValueError("ZAP Scanner Registration ID differs")
        object.__setattr__(self, "registration_digest", digest)
        object.__setattr__(self, "registration_id", registration_id)
        return self


class ZAPSarifFinding(StrictModel):
    """The bounded SARIF fields used by benchmark normalization."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    rule_id: str = Field(alias="ruleId", min_length=1, max_length=100)
    level: Literal["none", "note", "warning", "error"]
    message_sha256: _Sha256 = Field(alias="messageSha256")
    location_uris: tuple[str, ...] = Field(
        alias="locationUris", min_length=1, max_length=100
    )
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    known_surface: bool = Field(alias="knownSurface")
    matches_known_finding: bool = Field(alias="matchesKnownFinding")


class ZAPSarifNormalization(StrictModel):
    """Content-addressed projection of one raw, still separately retained SARIF file."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/zap-sarif-normalization/v1alpha1"] = Field(
        default=ZAP_SARIF_NORMALIZATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ZAPSarifNormalization"] = "ZAPSarifNormalization"
    normalization_digest: str = Field(
        default="", alias="normalizationDigest", max_length=64
    )
    registration_digest: _Sha256 = Field(alias="registrationDigest")
    raw_sarif_sha256: _Sha256 = Field(alias="rawSarifSha256")
    raw_sarif_size_bytes: int = Field(alias="rawSarifSizeBytes", ge=1, le=_MAX_SARIF_BYTES)
    tool_name: Literal["ZAP"] = Field(default="ZAP", alias="toolName")
    tool_version: Literal["2.17.0"] = Field(default="2.17.0", alias="toolVersion")
    findings: tuple[ZAPSarifFinding, ...] = Field(max_length=10_000)
    known_surface_detected: bool = Field(alias="knownSurfaceDetected")
    known_finding_matched: bool = Field(alias="knownFindingMatched")

    @model_validator(mode="after")
    def bind_normalization(self) -> Self:
        if (
            self.known_surface_detected != any(item.known_surface for item in self.findings)
            or self.known_finding_matched
            != any(item.matches_known_finding for item in self.findings)
            or len({item.candidate_id for item in self.findings}) != len(self.findings)
        ):
            raise ValueError("ZAP SARIF normalized summary differs")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"normalization_digest"}
        )
        digest = benchmark_digest(
            "pajin.benchmark.zap-sarif-normalization/v1",
            material,
            max_bytes=_MAX_NORMALIZATION_BYTES,
        )
        if self.normalization_digest and self.normalization_digest != digest:
            raise ValueError("ZAP SARIF Normalization Digest differs")
        object.__setattr__(self, "normalization_digest", digest)
        return self


def registered_zap_scanner(
    scanner_image_id: str,
    *,
    parser_contract_digest: str,
) -> ZAPScannerRegistration:
    """Bind the reviewed P0-E2A parser contract to the pinned ZAP image."""

    return ZAPScannerRegistration(
        scannerImageId=scanner_image_id,
        executableArtifactSha256=scanner_image_id.removeprefix("sha256:"),
        configurationDigest=sha256(ZAP_AUTOMATION_PLAN).hexdigest(),
        parserContractDigest=parser_contract_digest,
    )


def parse_zap_sarif(
    raw: bytes,
    *,
    registration: ZAPScannerRegistration,
) -> ZAPSarifNormalization:
    """Strictly normalize only the reviewed ZAP 2.17.0 SARIF output shape."""

    if not 1 <= len(raw) <= _MAX_SARIF_BYTES:
        raise ValueError("ZAP SARIF is missing or exceeds its byte limit")
    value = parse_strict_json_bytes(raw, label="ZAP SARIF", max_bytes=_MAX_SARIF_BYTES)
    canonical_benchmark_json(value, label="ZAP SARIF", max_bytes=_MAX_SARIF_BYTES)
    root = _exact_object(value, {"$schema", "version", "runs"}, "root")
    if root["version"] != "2.1.0" or not isinstance(root["$schema"], str):
        raise ValueError("ZAP SARIF version or schema differs")
    runs = root["runs"]
    if not isinstance(runs, list) or len(runs) != 1:
        raise ValueError("ZAP SARIF must contain exactly one Run")
    run = _exact_object(runs[0], {"results", "taxonomies", "tool"}, "Run")
    tool = _exact_object(run["tool"], {"driver"}, "tool")
    driver = _exact_object(
        tool["driver"],
        {
            "guid",
            "informationUri",
            "name",
            "rules",
            "semanticVersion",
            "supportedTaxonomies",
            "version",
        },
        "driver",
    )
    if driver["name"] != "ZAP" or driver["version"] != registration.scanner_version:
        raise ValueError("ZAP SARIF tool identity differs")
    rules = driver["rules"]
    if not isinstance(rules, list) or len(rules) > 10_000:
        raise ValueError("ZAP SARIF rule catalog is invalid")
    rule_ids = set()
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise ValueError("ZAP SARIF rule identity is invalid")
        rule_ids.add(cast(str, rule["id"]))
    if len(rule_ids) != len(rules):
        raise ValueError("ZAP SARIF rule identities are not unique")
    results = run["results"]
    if not isinstance(results, list) or len(results) > 10_000:
        raise ValueError("ZAP SARIF results are invalid")
    findings = tuple(
        _parse_result(item, rule_ids=rule_ids, target_url=registration.target_url)
        for item in results
    )
    return ZAPSarifNormalization(
        registrationDigest=registration.registration_digest,
        rawSarifSha256=sha256(raw).hexdigest(),
        rawSarifSizeBytes=len(raw),
        findings=findings,
        knownSurfaceDetected=any(item.known_surface for item in findings),
        knownFindingMatched=any(item.matches_known_finding for item in findings),
    )


def _parse_result(
    value: object,
    *,
    rule_ids: set[str],
    target_url: str,
) -> ZAPSarifFinding:
    result = _exact_object(
        value,
        {"level", "locations", "message", "ruleId", "webRequest", "webResponse"},
        "result",
    )
    rule_id = result["ruleId"]
    level = result["level"]
    if not isinstance(rule_id, str) or rule_id not in rule_ids:
        raise ValueError("ZAP SARIF result rule is absent from the driver catalog")
    if level not in {"none", "note", "warning", "error"}:
        raise ValueError("ZAP SARIF result level is invalid")
    message = _exact_object(result["message"], {"text"}, "message").get("text")
    if not isinstance(message, str) or not 1 <= len(message) <= 64 * 1024:
        raise ValueError("ZAP SARIF result message is invalid")
    locations = result["locations"]
    if not isinstance(locations, list) or not 1 <= len(locations) <= 100:
        raise ValueError("ZAP SARIF result locations are invalid")
    uris = tuple(_location_uri(item) for item in locations)
    known_surface = any(_is_known_surface(uri, target_url=target_url) for uri in uris)
    message_digest = sha256(message.encode("utf-8")).hexdigest()
    candidate_digest = benchmark_digest(
        "pajin.benchmark.zap-candidate/v1",
        {"ruleId": rule_id, "messageSha256": message_digest, "locationUris": uris},
        max_bytes=256 * 1024,
    )
    return ZAPSarifFinding(
        ruleId=rule_id,
        level=cast(Literal["none", "note", "warning", "error"], level),
        messageSha256=message_digest,
        locationUris=uris,
        candidateId=f"zap-candidate:{candidate_digest}",
        knownSurface=known_surface,
        matchesKnownFinding=known_surface and rule_id in _SQL_INJECTION_RULE_IDS,
    )


def _location_uri(value: object) -> str:
    location = _exact_object(value, {"physicalLocation", "properties"}, "location")
    physical = _exact_object(
        location["physicalLocation"], {"artifactLocation", "region"}, "physical location"
    )
    artifact = _exact_object(
        physical["artifactLocation"], {"uri"}, "artifact location"
    )
    uri = artifact["uri"]
    if not isinstance(uri, str) or not 1 <= len(uri) <= 16 * 1024:
        raise ValueError("ZAP SARIF location URI is invalid")
    parsed = urlsplit(uri)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("ZAP SARIF location URI has an invalid port") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed_port is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("ZAP SARIF location URI is not an HTTP target")
    return uri


def _is_known_surface(uri: str, *, target_url: str) -> bool:
    parsed = urlsplit(uri)
    expected = urlsplit(target_url)
    return (
        parsed.scheme == expected.scheme
        and parsed.hostname == expected.hostname
        and parsed.port == expected.port
        and parsed.path == _TARGET_PATH
        and {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)} == {"id"}
    )


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"ZAP SARIF {label} properties differ")
    return cast(dict[str, object], value)
