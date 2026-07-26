from __future__ import annotations

import importlib.util
import inspect
import json
import sys
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import JsonValue, ValidationError
from typer.testing import CliRunner

import pajin.capabilities.scaffold as scaffold_module
from pajin.capabilities import (
    CapabilityAuthorityError,
    CapabilityAuthorityRole,
    CapabilityBenchmarkMapping,
    CapabilityDefinition,
    CapabilityMaturity,
    CapabilityScaffold,
    CapabilityScaffoldError,
    CapabilityScaffoldSpec,
    CapabilitySideEffectClass,
    CapabilityToolBinding,
    MaterializerTemplate,
    canonical_capability_parameter_schema,
    capability_authority_binding,
    capability_parameter_schema_digest,
    generate_capability_scaffold,
    write_capability_scaffold,
)
from pajin.cli import app
from pajin.domain.models import ToolRiskTier

TOOL_DIGEST = sha256(b"scaffold-tool").hexdigest()


def _parameter_schema() -> dict[str, JsonValue]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "headers": {
                "additionalProperties": {"type": "string"},
                "type": "object",
            },
            "path": {"maxLength": 2_000, "minLength": 1, "type": "string"},
        },
        "required": ["path"],
        "type": "object",
    }


def _definition(
    *,
    parameter_schema_digest: str | None = None,
) -> CapabilityDefinition:
    schema_digest = parameter_schema_digest or capability_parameter_schema_digest(
        _parameter_schema()
    )
    return CapabilityDefinition(
        capabilityId="pajin.discovery.scaffold-test",
        capabilityVersion="1.0.0",
        domain="web",
        maturity=CapabilityMaturity.EXPERIMENTAL,
        supportedSurfaceTypes=("http-endpoint",),
        threatClasses=("surface-discovery",),
        preconditions=("campaign-scope-approved",),
        parameterSchemaDigest=schema_digest,
        tool=CapabilityToolBinding(
            toolId="test.scaffold-tool",
            toolVersion="1.0.0",
            toolDigest=TOOL_DIGEST,
        ),
        riskTier=ToolRiskTier.T1,
        sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
        evidenceTypes=("json",),
        networkAccess=False,
        approvalRequired=False,
        requestUnitCost=1,
        cleanupRequired=False,
        parallelSafe=True,
    )


def _spec() -> CapabilityScaffoldSpec:
    definition = _definition()
    return CapabilityScaffoldSpec(
        packageName="scaffold_test_capability",
        classPrefix="ScaffoldTest",
        authorityVersion="0.1.0",
        definition=definition,
        parameterSchema=_parameter_schema(),
        benchmarkMapping=CapabilityBenchmarkMapping(
            capability=definition.reference(),
            benchmarkIds=("benchmark.discovery.http",),
            expectedObservables=("HTTP response metadata is captured.",),
        ),
    )


def _load_generated_module(path: Path) -> ModuleType:
    module_spec = importlib.util.spec_from_file_location(
        "generated_scaffold_test_authorities",
        path,
    )
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = module
    try:
        module_spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_spec.name, None)
    return module


def test_generator_is_deterministic_complete_and_inert(tmp_path: Path) -> None:
    spec = _spec()
    scaffold = generate_capability_scaffold(spec)

    assert scaffold == generate_capability_scaffold(spec)
    assert scaffold.capability == spec.definition.reference()
    assert [item.path for item in scaffold.files] == [
        "scaffold_test_capability/README.md",
        "scaffold_test_capability/__init__.py",
        "scaffold_test_capability/authorities.py",
        "scaffold_test_capability/benchmark-mapping.json",
        "scaffold_test_capability/capability-definition.schema.json",
        "scaffold_test_capability/metadata.json",
        "scaffold_test_capability/parameter-schema.json",
        "scaffold_test_capability/py.typed",
        "tests/test_scaffold_test_capability_authorities.py",
    ]
    for item in scaffold.files:
        if item.path.endswith(".py"):
            compile(item.content, item.path, "exec")

    output = write_capability_scaffold(scaffold, tmp_path / "generated")
    manifest = json.loads(
        (output / "scaffold-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["scaffoldId"] == scaffold.scaffold_id
    assert manifest["scaffoldDigest"] == scaffold.scaffold_digest
    assert manifest["specDigest"] == spec.spec_digest
    for item in manifest["files"]:
        content = (output / item["path"]).read_bytes()
        assert sha256(content).hexdigest() == item["sha256"]

    generated = _load_generated_module(
        output / "scaffold_test_capability" / "authorities.py"
    )
    authority_types = [
        value
        for name, value in vars(generated).items()
        if name.startswith("ScaffoldTest") and inspect.isclass(value)
    ]
    assert len(authority_types) == len(CapabilityAuthorityRole)
    assert all(inspect.isabstract(value) for value in authority_types)
    for authority_type in authority_types:
        with pytest.raises(TypeError):
            authority_type()


def test_scaffold_spec_rejects_unsafe_or_drifted_metadata() -> None:
    schema = _parameter_schema()
    schema["additionalProperties"] = True
    with pytest.raises(
        CapabilityScaffoldError,
        match="forbid additional properties",
    ):
        canonical_capability_parameter_schema(schema)

    schema = _parameter_schema()
    schema["properties"]["path"] = {
        "$ref": "https://attacker.invalid/schema.json",
    }
    with pytest.raises(CapabilityScaffoldError, match=r"local \$defs"):
        capability_parameter_schema_digest(schema)

    schema = _parameter_schema()
    schema["properties"]["path"] = {"$ref": "#/$defs/Missing"}
    with pytest.raises(CapabilityScaffoldError, match="unresolved"):
        capability_parameter_schema_digest(schema)

    schema = _parameter_schema()
    schema["patternProperties"] = {"^x-": {"type": "string"}}
    with pytest.raises(CapabilityScaffoldError, match="authority-expanding"):
        capability_parameter_schema_digest(schema)

    schema = _parameter_schema()
    schema["properties"]["path"] = {
        "$dynamicRef": "https://attacker.invalid/schema.json",
    }
    with pytest.raises(CapabilityScaffoldError, match="reference scope"):
        capability_parameter_schema_digest(schema)

    schema = _parameter_schema()
    schema["required"] = ["path", "headers"]
    with pytest.raises(CapabilityScaffoldError, match="sorted, unique"):
        capability_parameter_schema_digest(schema)

    definition = _definition(parameter_schema_digest=sha256(b"wrong").hexdigest())
    with pytest.raises(ValidationError, match="parameter-schema digest differs"):
        CapabilityScaffoldSpec(
            packageName="scaffold_test_capability",
            classPrefix="ScaffoldTest",
            authorityVersion="0.1.0",
            definition=definition,
            parameterSchema=_parameter_schema(),
            benchmarkMapping=CapabilityBenchmarkMapping(
                capability=definition.reference(),
                benchmarkIds=("benchmark.discovery.http",),
                expectedObservables=("HTTP response metadata is captured.",),
            ),
        )


def test_scaffold_and_writer_reject_tampering_and_overwrite(tmp_path: Path) -> None:
    scaffold = generate_capability_scaffold(_spec())
    raw = scaffold.model_dump(mode="json", by_alias=True)
    raw["files"][0]["content"] += "tampered"
    with pytest.raises(ValidationError, match="file digest differs"):
        CapabilityScaffold.model_validate(raw)

    destination = tmp_path / "generated"
    write_capability_scaffold(scaffold, destination)
    manifest_before = (destination / "scaffold-manifest.json").read_bytes()
    with pytest.raises(CapabilityScaffoldError, match="already exists"):
        write_capability_scaffold(scaffold, destination)
    assert (destination / "scaffold-manifest.json").read_bytes() == manifest_before


def test_writer_leaves_partial_failure_without_completion_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scaffold = generate_capability_scaffold(_spec())
    destination = tmp_path / "partial"
    writes = 0
    real_write = scaffold_module.atomic_write_text_no_follow

    def fail_second_write(path: Path, content: str, *, label: str) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("injected write failure")
        real_write(path, content, label=label)

    monkeypatch.setattr(
        scaffold_module,
        "atomic_write_text_no_follow",
        fail_second_write,
    )

    with pytest.raises(CapabilityScaffoldError, match="without a manifest"):
        write_capability_scaffold(scaffold, destination)

    assert destination.is_dir()
    assert not (destination / "scaffold-manifest.json").exists()


def test_authority_template_is_concrete_only_after_method_implementation() -> None:
    definition = _definition()

    class ConcreteMaterializer(MaterializerTemplate):
        AUTHORITY_ID = "test.scaffold.materializer"
        AUTHORITY_VERSION = "1.0.0"
        CAPABILITY_REFERENCE = definition.reference()
        IMPLEMENTATION_VERSION = "1.0.0"

        def stable_execution_context(self) -> dict[str, object]:
            return dict(super().stable_execution_context())

        def materialize(
            self,
            parameters: Mapping[str, JsonValue],
        ) -> dict[str, JsonValue]:
            return dict(parameters)

    first = ConcreteMaterializer(configuration={"mode": "strict", "retries": 0})
    second = ConcreteMaterializer(configuration={"retries": 0, "mode": "strict"})
    assert first.materialize({"path": "/health"}) == {"path": "/health"}
    assert capability_authority_binding(first) == capability_authority_binding(second)
    assert capability_authority_binding(first).role is CapabilityAuthorityRole.MATERIALIZER

    secret = ConcreteMaterializer(configuration={"apiToken": "not-allowed"})
    with pytest.raises(CapabilityAuthorityError, match="stable context is invalid"):
        capability_authority_binding(secret)


def test_capability_scaffold_cli_writes_once_without_traceback(tmp_path: Path) -> None:
    spec_path = tmp_path / "scaffold-spec.json"
    spec_path.write_text(
        json.dumps(_spec().model_dump(mode="json", by_alias=True)),
        encoding="utf-8",
    )
    output = tmp_path / "generated"

    result = CliRunner().invoke(
        app,
        ["capability-scaffold", str(spec_path), "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert "capability-scaffold_" in result.output
    assert (output / "scaffold-manifest.json").is_file()

    repeated = CliRunner().invoke(
        app,
        ["capability-scaffold", str(spec_path), "--output", str(output)],
    )
    assert repeated.exit_code == 2
    assert "Capability scaffold generation failed" in repeated.output
    assert "Traceback" not in repeated.output
