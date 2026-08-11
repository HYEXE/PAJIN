"""Deterministic SARIF export from one exact verified validation authority."""

from __future__ import annotations

import json
import os
import re
import unicodedata
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from pajin import __version__
from pajin.domain.models import Finding, FindingSeverity
from pajin.runtime.safe_files import atomic_write_text_no_follow, read_bounded_regular_bytes
from pajin.runtime.store import load_verified_run_snapshot
from pajin.runtime.verified_snapshot import require_same_authority
from pajin.workflow.validation_artifacts import (
    ValidationSnapshotSemantics,
    load_validation_snapshot,
)

SARIF_EXPORT_API_VERSION = "pajin.dev/sarif-export/v1alpha1"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_MEDIA_TYPE = "application/sarif+json"

_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_MAX_FINDINGS = 1_000
_MAX_FINDING_SET_BYTES = 16 * 1024 * 1024
_MAX_SARIF_BYTES = 16 * 1024 * 1024
_MAX_TITLE_BYTES = 4 * 1024
_MAX_THREAT_CLASS_BYTES = 1_024
_MAX_SUMMARY_BYTES = 64 * 1024
_MAX_DETAIL_BYTES = 32 * 1024
_MAX_REMEDIATION_ITEMS = 100
_MAX_REMEDIATION_BYTES = 16 * 1024


def _canonical_json_bytes(value: object, *, label: str, max_bytes: int) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the canonical byte limit")
    return encoded


@dataclass(frozen=True, slots=True)
class VerifiedSarifExport:
    """One local SARIF document bound to an exact sealed validation Run."""

    source_run_path: Path
    source_run_id: str
    source_root_digest: str
    finding_set_digest: str
    sarif_digest: str
    finding_count: int
    content: str


def load_verified_sarif_export(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> VerifiedSarifExport:
    """Build a minimized SARIF document from independently replay-confirmed Findings only."""

    _require_identifier(expected_run_id, label="expected validation Run ID")
    if _HASH_PATTERN.fullmatch(expected_root_digest) is None:
        raise ValueError("expected validation Run root digest must be 64 lowercase hex characters")

    root = run_path.resolve(strict=True)
    authority = load_verified_run_snapshot(root, expected_run_id=expected_run_id)
    if authority.verification.root_digest != expected_root_digest:
        raise ValueError("sealed validation Run root digest differs from the expected Run")

    snapshot = load_validation_snapshot(root, verified_snapshot=authority)
    if snapshot.semantics is not ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY:
        raise ValueError("SARIF export requires verified independent replay validation artifacts")
    findings = snapshot.product_confirmed_findings
    if len(findings) > _MAX_FINDINGS:
        raise ValueError(f"SARIF export exceeds the {_MAX_FINDINGS}-Finding limit")

    exported = _build_sarif_export(
        source_run_path=root,
        source_run_id=authority.verification.run_id,
        source_root_digest=authority.verification.root_digest,
        findings=findings,
    )
    current = load_verified_run_snapshot(root, expected_run_id=expected_run_id)
    require_same_authority(
        authority,
        current,
        message="sealed validation Run changed while SARIF was exported",
    )
    return exported


def write_verified_sarif_export(export: VerifiedSarifExport, output_path: Path) -> Path:
    """Atomically write and read-back verify one standalone private SARIF artifact."""

    encoded = export.content.encode("utf-8", errors="strict")
    if len(encoded) > _MAX_SARIF_BYTES:
        raise ValueError("SARIF export exceeds the canonical byte limit")
    if sha256(encoded).hexdigest() != export.sarif_digest:
        raise ValueError("SARIF export content differs from its verified digest")

    output = Path(os.path.abspath(os.fspath(output_path.expanduser())))
    resolved_output = output.resolve(strict=False)
    source = export.source_run_path.resolve(strict=True)
    if resolved_output == source or source in resolved_output.parents:
        raise ValueError("SARIF output must be outside the immutable source Run")

    atomic_write_text_no_follow(output, export.content, label="SARIF export artifact")
    persisted = read_bounded_regular_bytes(
        output,
        max_bytes=_MAX_SARIF_BYTES,
        label="SARIF export artifact",
        require_single_link=True,
    )
    if persisted != encoded:
        raise ValueError("SARIF export artifact differs after write verification")
    if sha256(persisted).hexdigest() != export.sarif_digest:
        raise ValueError("SARIF export artifact digest differs after write verification")
    return output


def _build_sarif_export(
    *,
    source_run_path: Path,
    source_run_id: str,
    source_root_digest: str,
    findings: list[Finding],
) -> VerifiedSarifExport:
    _require_identifier(source_run_id, label="validation Run ID")
    if _HASH_PATTERN.fullmatch(source_root_digest) is None:
        raise ValueError("validation Run root digest must be 64 lowercase hex characters")
    if len(findings) > _MAX_FINDINGS:
        raise ValueError(f"SARIF export exceeds the {_MAX_FINDINGS}-Finding limit")

    finding_ids = [finding.finding_id for finding in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("SARIF export requires unique Finding IDs")
    for finding_id in finding_ids:
        _require_identifier(finding_id, label="Finding ID")

    finding_payload = [finding.model_dump(mode="json") for finding in findings]
    finding_set_bytes = _canonical_json_bytes(
        finding_payload,
        label="SARIF source Finding set",
        max_bytes=_MAX_FINDING_SET_BYTES,
    )
    finding_set_digest = sha256(finding_set_bytes).hexdigest()

    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in sorted(findings, key=lambda item: item.finding_id):
        if not finding.validated:
            raise ValueError("SARIF export cannot include an unvalidated Finding")
        threat_class = _safe_text(
            finding.threat_class,
            label=f"Finding {finding.finding_id} threat class",
            max_bytes=_MAX_THREAT_CLASS_BYTES,
            single_line=True,
        )
        rule_id = _rule_id(threat_class)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": threat_class,
                "shortDescription": {"text": f"PAJIN confirmed {threat_class} finding"},
                "properties": {
                    "pajinThreatClass": threat_class,
                    "pajinThreatClassDigest": sha256(threat_class.encode("utf-8")).hexdigest(),
                },
            },
        )
        results.append(_sarif_result(finding, rule_id=rule_id))

    document: dict[str, object] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "automationDetails": {
                    "id": (f"pajin/sarif-export/v1alpha1/{source_run_id}/{source_root_digest[:16]}")
                },
                "tool": {
                    "driver": {
                        "name": "PAJIN",
                        "semanticVersion": __version__,
                        "rules": [rules[rule_id] for rule_id in sorted(rules)],
                    }
                },
                "results": results,
                "properties": {
                    "pajin": {
                        "apiVersion": SARIF_EXPORT_API_VERSION,
                        "sourceRunId": source_run_id,
                        "sourceRootDigest": source_root_digest,
                        "sourceFindingSetDigest": finding_set_digest,
                        "confirmationSemantics": (
                            ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY.value
                        ),
                        "redactionProfile": "pajin-minimized-finding-v1",
                        "excludedFindingFields": [
                            "target",
                            "rootCause",
                            "reproduction",
                            "evidence",
                        ],
                        "externalDeliveryPerformed": False,
                        "deliveryReceiptAuthority": False,
                        "issueMutationAuthority": False,
                        "siemIngestAuthority": False,
                        "soarActionAuthority": False,
                    }
                },
            }
        ],
    }
    content = (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    )
    encoded = content.encode("utf-8")
    if len(encoded) > _MAX_SARIF_BYTES:
        raise ValueError("SARIF export exceeds the canonical byte limit")
    return VerifiedSarifExport(
        source_run_path=source_run_path,
        source_run_id=source_run_id,
        source_root_digest=source_root_digest,
        finding_set_digest=finding_set_digest,
        sarif_digest=sha256(encoded).hexdigest(),
        finding_count=len(findings),
        content=content,
    )


def _sarif_result(finding: Finding, *, rule_id: str) -> dict[str, object]:
    finding_payload = finding.model_dump(mode="json")
    finding_digest = sha256(
        _canonical_json_bytes(
            finding_payload,
            label=f"Finding {finding.finding_id} fingerprint",
            max_bytes=_MAX_FINDING_SET_BYTES,
        )
    ).hexdigest()
    title = _safe_text(
        finding.title,
        label=f"Finding {finding.finding_id} title",
        max_bytes=_MAX_TITLE_BYTES,
        single_line=True,
    )
    summary = _safe_text(
        finding.summary,
        label=f"Finding {finding.finding_id} summary",
        max_bytes=_MAX_SUMMARY_BYTES,
    )
    properties: dict[str, object] = {
        "pajinFindingId": finding.finding_id,
        "pajinFindingDigest": finding_digest,
        "title": title,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "validated": True,
        "targetDigest": sha256(finding.target.encode("utf-8", errors="strict")).hexdigest(),
    }
    if finding.impact is not None:
        properties["impact"] = _safe_text(
            finding.impact,
            label=f"Finding {finding.finding_id} impact",
            max_bytes=_MAX_DETAIL_BYTES,
        )
    if finding.affected_component is not None:
        properties["affectedComponent"] = _safe_text(
            finding.affected_component,
            label=f"Finding {finding.finding_id} affected component",
            max_bytes=_MAX_DETAIL_BYTES,
        )
    if len(finding.remediation) > _MAX_REMEDIATION_ITEMS:
        raise ValueError(f"Finding {finding.finding_id} exceeds the remediation item limit")
    if finding.remediation:
        properties["remediation"] = [
            _safe_text(
                item,
                label=f"Finding {finding.finding_id} remediation",
                max_bytes=_MAX_REMEDIATION_BYTES,
            )
            for item in finding.remediation
        ]
    return {
        "ruleId": rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": summary},
        "partialFingerprints": {"pajinFinding/v1": finding_digest},
        "properties": properties,
    }


def _safe_text(value: str, *, label: str, max_bytes: int, single_line: bool = False) -> str:
    normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    if not normalized:
        raise ValueError(f"{label} must not be empty")
    for character in normalized:
        category = unicodedata.category(character)
        if category in {"Cf", "Cs"} or (category == "Cc" and character not in {"\n", "\t"}):
            raise ValueError(f"{label} contains unsafe Unicode controls")
        if single_line and character in {"\n", "\t"}:
            raise ValueError(f"{label} must be a single line")
    try:
        encoded = normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 text") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the export byte limit")
    return normalized


def _require_identifier(value: str, *, label: str) -> None:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a portable identifier")


def _rule_id(threat_class: str) -> str:
    digest = sha256(b"pajin-sarif-rule-v1\x00" + threat_class.encode("utf-8")).hexdigest()
    return f"PAJIN-{digest}"


def _sarif_level(severity: FindingSeverity) -> str:
    if severity in {FindingSeverity.CRITICAL, FindingSeverity.HIGH}:
        return "error"
    if severity is FindingSeverity.MEDIUM:
        return "warning"
    return "note"
