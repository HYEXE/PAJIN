"""Deterministic, fail-closed authoring SDK and scaffold generator for Capabilities."""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Self, cast

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)

from pajin.capabilities.authorities import (
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
)
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    canonical_capability_json,
    capability_definition_digest,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.runtime.safe_files import (
    atomic_write_text_no_follow,
    load_bounded_strict_json,
)
from pajin.runtime.worker import WorkerJob, WorkerResult

CAPABILITY_SCAFFOLD_API_VERSION: Literal[
    "pajin.dev/capability-scaffold/v1alpha1"
] = "pajin.dev/capability-scaffold/v1alpha1"
CAPABILITY_BENCHMARK_MAPPING_API_VERSION: Literal[
    "pajin.dev/capability-benchmark-mapping/v1alpha1"
] = "pajin.dev/capability-benchmark-mapping/v1alpha1"
CAPABILITY_AUTHORITY_TEMPLATE_API_VERSION: Literal[
    "pajin.dev/capability-authority-template/v1alpha1"
] = "pajin.dev/capability-authority-template/v1alpha1"
CAPABILITY_SCAFFOLD_MANIFEST_API_VERSION: Literal[
    "pajin.dev/capability-scaffold-manifest/v1alpha1"
] = "pajin.dev/capability-scaffold-manifest/v1alpha1"

_MAX_SCAFFOLD_SPEC_BYTES = 1024 * 1024
_MAX_SCAFFOLD_FILE_BYTES = 512 * 1024
_MAX_SCAFFOLD_TOTAL_BYTES = 4 * 1024 * 1024
_JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Observable = Annotated[str, Field(min_length=1, max_length=2_000)]
_PACKAGE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CLASS_PREFIX_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9]{0,63}$")
_LOCAL_SCHEMA_REFERENCE_PATTERN = re.compile(r"^#/\$defs/[A-Za-z0-9._-]{1,200}$")
_FORBIDDEN_ROOT_SCHEMA_EXPANSION_KEYS = frozenset(
    {
        "allOf",
        "anyOf",
        "dependentSchemas",
        "else",
        "if",
        "not",
        "oneOf",
        "patternProperties",
        "then",
    }
)
_FORBIDDEN_SCHEMA_REFERENCE_KEYS = frozenset(
    {
        "$anchor",
        "$dynamicAnchor",
        "$dynamicRef",
        "$id",
        "$recursiveAnchor",
        "$recursiveRef",
    }
)


class CapabilityScaffoldError(ValueError):
    """Raised when a Capability scaffold cannot be generated or written safely."""


def capability_parameter_schema_digest(
    schema: Mapping[str, JsonValue],
) -> str:
    """Return the canonical CAP-003 digest for a strict parameter schema."""

    canonical = canonical_capability_parameter_schema(schema)
    return capability_definition_digest(
        "pajin.capability.parameter-schema/v1",
        canonical,
    )


def canonical_capability_parameter_schema(
    schema: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    """Validate and detach one standalone strict JSON object parameter schema."""

    if not isinstance(schema, Mapping) or any(
        not isinstance(key, str) for key in schema
    ):
        raise CapabilityScaffoldError(
            "Capability parameter schema must be a string-keyed JSON object"
        )
    try:
        encoded = canonical_capability_json(
            dict(schema),
            label="Capability parameter schema",
        )
        canonical = json.loads(encoded)
    except (
        CapabilityDefinitionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise CapabilityScaffoldError(
            "Capability parameter schema is not bounded canonical JSON"
        ) from exc
    if not isinstance(canonical, dict):
        raise CapabilityScaffoldError("Capability parameter schema must be a JSON object")
    if canonical.get("$schema", _JSON_SCHEMA_DIALECT) != _JSON_SCHEMA_DIALECT:
        raise CapabilityScaffoldError(
            "Capability parameter schema must use JSON Schema draft 2020-12"
        )
    if canonical.get("type") != "object":
        raise CapabilityScaffoldError(
            "Capability parameter schema root type must be object"
        )
    if canonical.get("additionalProperties") is not False:
        raise CapabilityScaffoldError(
            "Capability parameter schema must forbid additional properties"
        )
    forbidden_root = _FORBIDDEN_ROOT_SCHEMA_EXPANSION_KEYS & canonical.keys()
    if forbidden_root:
        raise CapabilityScaffoldError(
            "Capability parameter schema root cannot use authority-expanding composition"
        )
    if canonical.get("unevaluatedProperties", False) is not False:
        raise CapabilityScaffoldError(
            "Capability parameter schema must forbid unevaluated properties"
        )
    properties = canonical.get("properties")
    if not isinstance(properties, dict) or any(
        not isinstance(key, str) or not _is_identifier(key) for key in properties
    ):
        raise CapabilityScaffoldError(
            "Capability parameter schema properties must use bounded identifiers"
        )
    required = canonical.get("required", [])
    if (
        not isinstance(required, list)
        or any(not isinstance(item, str) for item in required)
        or required != sorted(set(required))
        or any(item not in properties for item in required)
    ):
        raise CapabilityScaffoldError(
            "Capability parameter schema required properties must be sorted, unique, and declared"
        )
    definitions = canonical.get("$defs", {})
    if not isinstance(definitions, dict) or any(
        not isinstance(key, str) or not _is_identifier(key)
        for key in definitions
    ):
        raise CapabilityScaffoldError(
            "Capability parameter schema $defs must use bounded identifiers"
        )
    references: set[str] = set()
    _validate_local_schema_references(canonical, references=references)
    if any(reference.removeprefix("#/$defs/") not in definitions for reference in references):
        raise CapabilityScaffoldError(
            "Capability parameter schema contains an unresolved local $defs reference"
        )
    return cast(dict[str, JsonValue], canonical)


class CapabilityAuthorityTemplate(ABC):
    """Common inert base for generated CAP-002 authority implementations."""

    ROLE: ClassVar[CapabilityAuthorityRole]
    AUTHORITY_ID: ClassVar[str]
    AUTHORITY_VERSION: ClassVar[str]
    CAPABILITY_REFERENCE: ClassVar[CapabilityDefinitionRef]
    IMPLEMENTATION_VERSION: ClassVar[str]

    def __init__(
        self,
        *,
        configuration: Mapping[str, JsonValue] | None = None,
    ) -> None:
        _require_identifier(self.AUTHORITY_ID, label="Capability authority ID")
        _require_identifier(self.AUTHORITY_VERSION, label="Capability authority version")
        _require_identifier(
            self.IMPLEMENTATION_VERSION,
            label="Capability implementation version",
        )
        try:
            self._capability_reference = CapabilityDefinitionRef.model_validate(
                self.CAPABILITY_REFERENCE.model_dump(mode="json", by_alias=True)
            )
            self._configuration = _canonical_json_mapping(
                configuration or {},
                label="Capability authority template configuration",
            )
        except (AttributeError, ValidationError) as exc:
            raise CapabilityScaffoldError(
                "Capability authority template identity is invalid"
            ) from exc

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return CapabilityAuthorityRole(self.ROLE)

    @property
    def authority_id(self) -> str:
        return self.AUTHORITY_ID

    @property
    def authority_version(self) -> str:
        return self.AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._capability_reference.model_copy(deep=True)

    def stable_execution_context(self) -> Mapping[str, object]:
        """Expose only explicit, canonical, non-secret behavior configuration."""

        return {
            "sdkApiVersion": CAPABILITY_AUTHORITY_TEMPLATE_API_VERSION,
            "implementationVersion": self.IMPLEMENTATION_VERSION,
            "configuration": json.loads(
                canonical_capability_json(
                    self._configuration,
                    label="Capability authority template configuration",
                )
            ),
        }


class MaterializerTemplate(CapabilityAuthorityTemplate, ABC):
    """Abstract CAP-002 Materializer template."""

    ROLE = CapabilityAuthorityRole.MATERIALIZER

    @abstractmethod
    def materialize(
        self,
        parameters: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]:
        """Normalize bounded proposal parameters."""


class ActionCompilerTemplate(CapabilityAuthorityTemplate, ABC):
    """Abstract CAP-002 deterministic Action Compiler template."""

    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    @abstractmethod
    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        """Compile materialized parameters without expanding request authority."""


class ExecutorAdapterTemplate(CapabilityAuthorityTemplate, ABC):
    """Abstract CAP-002 isolated Executor Adapter template."""

    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    @abstractmethod
    def prepare(self, request: ToolRequest) -> WorkerJob:
        """Prepare a Worker job for an already-authorized request."""


class ResultNormalizerTemplate(CapabilityAuthorityTemplate, ABC):
    """Abstract CAP-002 Result Normalizer template."""

    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    @abstractmethod
    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        """Normalize one Worker result into the Tool contract."""


class SuccessOracleTemplate(CapabilityAuthorityTemplate, ABC):
    """Abstract CAP-002 semantic Success Oracle template."""

    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    @abstractmethod
    def evaluate(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> CapabilityOracleDecision:
        """Classify the normalized result without creating Finding authority."""


class ReplayStrategyTemplate(CapabilityAuthorityTemplate, ABC):
    """Abstract CAP-002 non-executable Replay Strategy template."""

    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY

    @abstractmethod
    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        """Return a bounded plan that must be authorized separately."""


class CleanupHandlerTemplate(CapabilityAuthorityTemplate, ABC):
    """Abstract CAP-002 non-executable Cleanup Handler template."""

    ROLE = CapabilityAuthorityRole.CLEANUP_HANDLER

    @abstractmethod
    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        """Return a bounded cleanup plan that must receive a new Permit."""


class CapabilityBenchmarkMapping(StrictModel):
    """Exact benchmark coverage declaration generated beside a Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/capability-benchmark-mapping/v1alpha1"
    ] = Field(
        default=CAPABILITY_BENCHMARK_MAPPING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityBenchmarkMapping"] = "CapabilityBenchmarkMapping"
    mapping_digest: str = Field(default="", alias="mappingDigest", max_length=64)
    capability: CapabilityDefinitionRef
    benchmark_ids: tuple[_Identifier, ...] = Field(
        alias="benchmarkIds",
        min_length=1,
        max_length=100,
    )
    expected_observables: tuple[_Observable, ...] = Field(
        alias="expectedObservables",
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def bind_mapping_digest(self) -> Self:
        if self.benchmark_ids != tuple(sorted(set(self.benchmark_ids))):
            raise ValueError("Capability benchmark IDs must be unique and sorted")
        if self.expected_observables != tuple(sorted(set(self.expected_observables))):
            raise ValueError(
                "Capability expected observables must be unique and sorted"
            )
        if any(
            value != value.strip()
            or not value.isprintable()
            or "\r" in value
            or "\n" in value
            for value in self.expected_observables
        ):
            raise ValueError(
                "Capability expected observables must be bounded single-line text"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"mapping_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.benchmark-mapping/v1",
            material,
        )
        if self.mapping_digest and self.mapping_digest != digest:
            raise ValueError(
                "Capability benchmark mapping digest differs from canonical identity"
            )
        object.__setattr__(self, "mapping_digest", digest)
        return self


class CapabilityScaffoldSpec(StrictModel):
    """Strict, code-free authoring input for a deterministic Capability scaffold."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-scaffold/v1alpha1"] = Field(
        default=CAPABILITY_SCAFFOLD_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityScaffoldSpec"] = "CapabilityScaffoldSpec"
    spec_digest: str = Field(default="", alias="specDigest", max_length=64)
    package_name: str = Field(alias="packageName", min_length=1, max_length=64)
    class_prefix: str = Field(alias="classPrefix", min_length=1, max_length=64)
    authority_version: _Identifier = Field(alias="authorityVersion")
    definition: CapabilityDefinition
    parameter_schema: dict[str, JsonValue] = Field(alias="parameterSchema")
    benchmark_mapping: CapabilityBenchmarkMapping = Field(alias="benchmarkMapping")

    @field_validator("package_name")
    @classmethod
    def require_safe_package_name(cls, value: str) -> str:
        if _PACKAGE_NAME_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "Capability scaffold packageName must be a lowercase Python identifier"
            )
        return value

    @field_validator("class_prefix")
    @classmethod
    def require_safe_class_prefix(cls, value: str) -> str:
        if _CLASS_PREFIX_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "Capability scaffold classPrefix must be a bounded PascalCase identifier"
            )
        return value

    @model_validator(mode="after")
    def bind_spec_digest(self) -> Self:
        schema = canonical_capability_parameter_schema(self.parameter_schema)
        object.__setattr__(self, "parameter_schema", schema)
        if (
            self.definition.parameter_schema_digest
            != capability_parameter_schema_digest(schema)
        ):
            raise ValueError(
                "Capability definition parameter-schema digest differs from scaffold schema"
            )
        if self.benchmark_mapping.capability != self.definition.reference():
            raise ValueError(
                "Capability benchmark mapping differs from the exact definition"
            )
        for role in CapabilityAuthorityRole:
            generated_id = _generated_authority_id(self.definition, role)
            _require_identifier(generated_id, label="generated Capability authority ID")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"spec_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.scaffold-spec/v1",
            material,
        )
        if self.spec_digest and self.spec_digest != digest:
            raise ValueError("Capability scaffold spec digest differs from canonical identity")
        object.__setattr__(self, "spec_digest", digest)
        return self


class CapabilityScaffoldFile(StrictModel):
    """One deterministic generated scaffold file and its exact digest."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    path: str = Field(min_length=1, max_length=240)
    media_type: str = Field(alias="mediaType", min_length=1, max_length=100)
    content: str
    sha256: str = Field(default="", max_length=64)

    @field_validator("path")
    @classmethod
    def require_safe_relative_path(cls, value: str) -> str:
        if "\\" in value:
            raise ValueError("Capability scaffold paths must use forward slashes")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != value
        ):
            raise ValueError(
                "Capability scaffold path must be a normalized relative path"
            )
        return value

    @model_validator(mode="after")
    def bind_file_digest(self) -> Self:
        if "\r" in self.content:
            raise ValueError("Capability scaffold files must use LF line endings")
        try:
            encoded = self.content.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError("Capability scaffold file is not UTF-8 text") from exc
        if len(encoded) > _MAX_SCAFFOLD_FILE_BYTES:
            raise ValueError("Capability scaffold file exceeds the byte limit")
        digest = sha256(encoded).hexdigest()
        if self.sha256 and self.sha256 != digest:
            raise ValueError("Capability scaffold file digest differs from content")
        object.__setattr__(self, "sha256", digest)
        return self


class CapabilityScaffold(StrictModel):
    """Immutable generated file set and audit identity."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-scaffold-manifest/v1alpha1"] = Field(
        default=CAPABILITY_SCAFFOLD_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityScaffold"] = "CapabilityScaffold"
    scaffold_id: str = Field(default="", alias="scaffoldId", max_length=87)
    scaffold_digest: str = Field(default="", alias="scaffoldDigest", max_length=64)
    spec_digest: _Sha256 = Field(alias="specDigest")
    capability: CapabilityDefinitionRef
    package_name: str = Field(alias="packageName")
    benchmark_mapping_digest: _Sha256 = Field(alias="benchmarkMappingDigest")
    files: tuple[CapabilityScaffoldFile, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def bind_scaffold_identity(self) -> Self:
        paths = [item.path for item in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("Capability scaffold files must have unique, sorted paths")
        total_bytes = sum(len(item.content.encode("utf-8")) for item in self.files)
        if total_bytes > _MAX_SCAFFOLD_TOTAL_BYTES:
            raise ValueError("Capability scaffold exceeds the total byte limit")
        material = {
            "specDigest": self.spec_digest,
            "capability": self.capability.model_dump(mode="json", by_alias=True),
            "packageName": self.package_name,
            "benchmarkMappingDigest": self.benchmark_mapping_digest,
            "files": [
                {
                    "path": item.path,
                    "mediaType": item.media_type,
                    "sha256": item.sha256,
                }
                for item in self.files
            ],
        }
        digest = capability_definition_digest(
            "pajin.capability.scaffold/v1",
            material,
        )
        scaffold_id = f"capability-scaffold_{digest}"
        if self.scaffold_digest and self.scaffold_digest != digest:
            raise ValueError("Capability scaffold digest differs from generated files")
        if self.scaffold_id and self.scaffold_id != scaffold_id:
            raise ValueError("Capability scaffold ID differs from generated files")
        object.__setattr__(self, "scaffold_digest", digest)
        object.__setattr__(self, "scaffold_id", scaffold_id)
        return self

    def manifest_json(self) -> str:
        """Return the content written last to mark a complete scaffold."""

        manifest = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"files"},
        )
        manifest["files"] = [
            {
                "path": item.path,
                "mediaType": item.media_type,
                "sha256": item.sha256,
            }
            for item in self.files
        ]
        return _pretty_json(manifest)


def load_capability_scaffold_spec(path: Path) -> CapabilityScaffoldSpec:
    """Load one bounded strict-JSON authoring spec without YAML execution semantics."""

    try:
        decoded = load_bounded_strict_json(
            path,
            max_bytes=_MAX_SCAFFOLD_SPEC_BYTES,
            label="Capability scaffold spec",
            max_depth=64,
            max_nodes=50_000,
        )
        return CapabilityScaffoldSpec.model_validate(decoded)
    except (
        CapabilityScaffoldError,
        OSError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CapabilityScaffoldError("Capability scaffold spec is invalid") from exc


def generate_capability_scaffold(
    spec: CapabilityScaffoldSpec,
) -> CapabilityScaffold:
    """Generate deterministic inert templates and exact supporting artifacts."""

    try:
        canonical_spec = CapabilityScaffoldSpec.model_validate(
            spec.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise CapabilityScaffoldError(
            "Capability scaffold generator requires a canonical spec"
        ) from exc

    package = canonical_spec.package_name
    files = (
        CapabilityScaffoldFile(
            path=f"{package}/README.md",
            mediaType="text/markdown",
            content=_render_readme(canonical_spec),
        ),
        CapabilityScaffoldFile(
            path=f"{package}/__init__.py",
            mediaType="text/x-python",
            content=_render_package_init(canonical_spec),
        ),
        CapabilityScaffoldFile(
            path=f"{package}/authorities.py",
            mediaType="text/x-python",
            content=_render_authorities(canonical_spec),
        ),
        CapabilityScaffoldFile(
            path=f"{package}/benchmark-mapping.json",
            mediaType="application/json",
            content=_pretty_json(
                canonical_spec.benchmark_mapping.model_dump(
                    mode="json",
                    by_alias=True,
                )
            ),
        ),
        CapabilityScaffoldFile(
            path=f"{package}/capability-definition.schema.json",
            mediaType="application/schema+json",
            content=_pretty_json(CapabilityDefinition.model_json_schema(by_alias=True)),
        ),
        CapabilityScaffoldFile(
            path=f"{package}/metadata.json",
            mediaType="application/json",
            content=_pretty_json(
                canonical_spec.definition.model_dump(mode="json", by_alias=True)
            ),
        ),
        CapabilityScaffoldFile(
            path=f"{package}/parameter-schema.json",
            mediaType="application/schema+json",
            content=_pretty_json(canonical_spec.parameter_schema),
        ),
        CapabilityScaffoldFile(
            path=f"{package}/py.typed",
            mediaType="text/plain",
            content="",
        ),
        CapabilityScaffoldFile(
            path=f"tests/test_{package}_authorities.py",
            mediaType="text/x-python",
            content=_render_negative_test(canonical_spec),
        ),
    )
    return CapabilityScaffold(
        specDigest=canonical_spec.spec_digest,
        capability=canonical_spec.definition.reference(),
        packageName=package,
        benchmarkMappingDigest=canonical_spec.benchmark_mapping.mapping_digest,
        files=tuple(sorted(files, key=lambda item: item.path)),
    )


def write_capability_scaffold(
    scaffold: CapabilityScaffold,
    destination: Path,
) -> Path:
    """Write a scaffold once into a new directory, with the manifest committed last."""

    try:
        canonical = CapabilityScaffold.model_validate(
            scaffold.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise CapabilityScaffoldError(
            "Capability scaffold writer requires a canonical scaffold"
        ) from exc

    root = Path(os.path.abspath(os.fspath(Path(destination).expanduser())))
    if not root.name or root.name in {".", ".."}:
        raise CapabilityScaffoldError(
            "Capability scaffold destination requires a directory name"
        )
    parent = root.parent
    if (
        not parent.is_dir()
        or parent.is_symlink()
        or parent.is_junction()
    ):
        raise CapabilityScaffoldError(
            "Capability scaffold destination parent must be an existing real directory"
        )
    try:
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise CapabilityScaffoldError(
            "Capability scaffold destination already exists"
        ) from exc
    except OSError as exc:
        raise CapabilityScaffoldError(
            "Capability scaffold destination cannot be created safely"
        ) from exc

    try:
        for item in canonical.files:
            relative = PurePosixPath(item.path)
            target = root.joinpath(*relative.parts)
            atomic_write_text_no_follow(
                target,
                item.content,
                label=f"Capability scaffold file {item.path}",
            )
        atomic_write_text_no_follow(
            root / "scaffold-manifest.json",
            canonical.manifest_json(),
            label="Capability scaffold manifest",
        )
    except (OSError, TypeError, ValueError) as exc:
        raise CapabilityScaffoldError(
            "Capability scaffold write failed; incomplete directory was left without a manifest"
        ) from exc
    return root


def _render_authorities(spec: CapabilityScaffoldSpec) -> str:
    reference_json = json.dumps(
        spec.definition.reference().model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    imports = [
        '"""Generated inert CAP-002 authority templates.',
        "",
        "Implement every abstract method and replace the generated negative test before",
        "registration.",
        '"""',
        "",
        "from pajin.capabilities import (",
        "    ActionCompilerTemplate,",
        "    CapabilityDefinitionRef,",
        "    CleanupHandlerTemplate,",
        "    ExecutorAdapterTemplate,",
        "    MaterializerTemplate,",
        "    ReplayStrategyTemplate,",
        "    ResultNormalizerTemplate,",
        "    SuccessOracleTemplate,",
        ")",
        "",
        (
            "CAPABILITY_REFERENCE = CapabilityDefinitionRef.model_validate_json("
            f"{reference_json!r})"
        ),
        "",
    ]
    classes: list[str] = []
    for role, suffix, template, summary in _generated_role_descriptors(spec):
        classes.extend(
            [
                f"class {spec.class_prefix}{suffix}({template}):",
                f'    """{summary}"""',
                "",
                f"    AUTHORITY_ID = {_generated_authority_id(spec.definition, role)!r}",
                f"    AUTHORITY_VERSION = {spec.authority_version!r}",
                "    CAPABILITY_REFERENCE = CAPABILITY_REFERENCE",
                f"    IMPLEMENTATION_VERSION = {spec.authority_version!r}",
                "",
                "    def stable_execution_context(self) -> dict[str, object]:",
                "        return dict(super().stable_execution_context())",
                "",
                "",
            ]
        )
    return "\n".join([*imports, *classes]).rstrip() + "\n"


def _render_package_init(spec: CapabilityScaffoldSpec) -> str:
    names = [
        f"{spec.class_prefix}{suffix}"
        for _role, suffix, _template, _summary in _generated_role_descriptors(spec)
    ]
    lines = [
        '"""Generated Capability authority package."""',
        "",
        "from .authorities import (",
        *(f"    {name}," for name in names),
        ")",
        "",
        "__all__ = [",
        *(f'    "{name}",' for name in names),
        "]",
        "",
    ]
    return "\n".join(lines)


def _render_negative_test(spec: CapabilityScaffoldSpec) -> str:
    names = [
        f"{spec.class_prefix}{suffix}"
        for _role, suffix, _template, _summary in _generated_role_descriptors(spec)
    ]
    package = spec.package_name
    lines = [
        '"""Generated fail-closed tests for an unimplemented Capability scaffold."""',
        "",
        "from __future__ import annotations",
        "",
        "from inspect import isabstract",
        "import json",
        "from pathlib import Path",
        "",
        "import pytest",
        "",
        "from pajin.capabilities import (",
        "    CapabilityDefinition,",
        "    capability_parameter_schema_digest,",
        ")",
        f"from {package}.authorities import (",
        *(f"    {name}," for name in names),
        ")",
        "",
        "",
        "AUTHORITY_TYPES = (",
        *(f"    {name}," for name in names),
        ")",
        "",
        "",
        "def test_generated_authorities_are_inert_until_implemented() -> None:",
        "    assert all(isabstract(authority_type) for authority_type in AUTHORITY_TYPES)",
        "    for authority_type in AUTHORITY_TYPES:",
        "        with pytest.raises(TypeError):",
        "            authority_type()",
        "",
        "",
        "def test_generated_parameter_schema_matches_exact_metadata_digest() -> None:",
        "    root = Path(__file__).parents[1]",
        f'    package_root = root / "{package}"',
        "    definition = CapabilityDefinition.model_validate_json(",
        '        (package_root / "metadata.json").read_text(encoding="utf-8")',
        "    )",
        "    schema = json.loads(",
        '        (package_root / "parameter-schema.json").read_text(encoding="utf-8")',
        "    )",
        "    assert definition.parameter_schema_digest == (",
        "        capability_parameter_schema_digest(schema)",
        "    )",
        "",
    ]
    return "\n".join(lines)


def _render_readme(spec: CapabilityScaffoldSpec) -> str:
    definition = spec.definition
    role_rows = [
        f"- `{spec.class_prefix}{suffix}` — {summary}"
        for _role, suffix, _template, summary in _generated_role_descriptors(spec)
    ]
    lines = [
        f"# {definition.capability_id} Capability scaffold",
        "",
        "> Generated by PAJIN CAP-003. Generated authority classes are intentionally abstract",
        "> and cannot be registered or executed until every required method is implemented.",
        "",
        "## Exact identities",
        "",
        f"- Capability version: `{definition.capability_version}`",
        f"- Capability digest: `{definition.capability_digest}`",
        f"- Parameter-schema digest: `{definition.parameter_schema_digest}`",
        f"- Scaffold-spec digest: `{spec.spec_digest}`",
        f"- Benchmark-mapping digest: `{spec.benchmark_mapping.mapping_digest}`",
        "",
        "## Generated authority templates",
        "",
        *role_rows,
        "",
        "## Authoring sequence",
        "",
        "1. Implement each abstract method without changing request, Tool, target, method, or",
        "   materialized argument authority.",
        "2. Replace the generated abstract-stub negative test with positive, negative, and",
        "   adversarial CAP-002 Registry/wrapper conformance tests.",
        "3. Keep `metadata.json`, `parameter-schema.json`, and",
        "   `benchmark-mapping.json` digest-bound.",
        "4. Register only the complete seven-role set by exact `CodeBackedCapabilityRef`.",
        "5. Do not add dynamic imports, module scanning, free-form shell, or a YAML attack DSL.",
        "6. Complete CAP-004 review/signing/activation before stable production use.",
        "",
        "The root `scaffold-manifest.json` is written last. Its absence means generation was",
        "incomplete and the directory must not be consumed.",
        "",
    ]
    return "\n".join(lines)


def _generated_role_descriptors(
    spec: CapabilityScaffoldSpec,
) -> tuple[tuple[CapabilityAuthorityRole, str, str, str], ...]:
    del spec
    return (
        (
            CapabilityAuthorityRole.MATERIALIZER,
            "Materializer",
            "MaterializerTemplate",
            "Normalize bounded proposal parameters.",
        ),
        (
            CapabilityAuthorityRole.ACTION_COMPILER,
            "ActionCompiler",
            "ActionCompilerTemplate",
            "Compile an exact ToolRequest without expanding authority.",
        ),
        (
            CapabilityAuthorityRole.EXECUTOR_ADAPTER,
            "ExecutorAdapter",
            "ExecutorAdapterTemplate",
            "Prepare an isolated WorkerJob for an authorized request.",
        ),
        (
            CapabilityAuthorityRole.RESULT_NORMALIZER,
            "ResultNormalizer",
            "ResultNormalizerTemplate",
            "Normalize Worker output into the ToolResult contract.",
        ),
        (
            CapabilityAuthorityRole.SUCCESS_ORACLE,
            "SuccessOracle",
            "SuccessOracleTemplate",
            "Classify semantic success without creating Finding authority.",
        ),
        (
            CapabilityAuthorityRole.REPLAY_STRATEGY,
            "ReplayStrategy",
            "ReplayStrategyTemplate",
            "Produce a bounded non-executable replay plan.",
        ),
        (
            CapabilityAuthorityRole.CLEANUP_HANDLER,
            "CleanupHandler",
            "CleanupHandlerTemplate",
            "Produce a bounded non-executable cleanup plan.",
        ),
    )


def _generated_authority_id(
    definition: CapabilityDefinition,
    role: CapabilityAuthorityRole,
) -> str:
    return f"{definition.capability_id}:{role.value}"


def _pretty_json(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
    except (TypeError, UnicodeError, ValueError) as exc:
        raise CapabilityScaffoldError(
            "Capability scaffold artifact is not canonical JSON"
        ) from exc
    return encoded + "\n"


def _canonical_json_mapping(
    value: Mapping[str, JsonValue],
    *,
    label: str,
) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise CapabilityScaffoldError(f"{label} must be a string-keyed JSON object")
    try:
        encoded = canonical_capability_json(dict(value), label=label)
        decoded = json.loads(encoded)
    except (
        CapabilityDefinitionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise CapabilityScaffoldError(f"{label} is not bounded canonical JSON") from exc
    if not isinstance(decoded, dict):
        raise CapabilityScaffoldError(f"{label} must be a JSON object")
    return cast(dict[str, JsonValue], decoded)


def _validate_local_schema_references(
    value: object,
    *,
    references: set[str],
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _FORBIDDEN_SCHEMA_REFERENCE_KEYS:
                raise CapabilityScaffoldError(
                    "Capability parameter schema cannot change standalone reference scope"
                )
            if key == "$ref" and (
                not isinstance(child, str)
                or _LOCAL_SCHEMA_REFERENCE_PATTERN.fullmatch(child) is None
            ):
                raise CapabilityScaffoldError(
                    "Capability parameter schema may use only bounded local $defs references"
                )
            if key == "$ref":
                assert isinstance(child, str)
                references.add(child)
            _validate_local_schema_references(child, references=references)
    elif isinstance(value, list):
        for child in value:
            _validate_local_schema_references(child, references=references)


def _is_identifier(value: str) -> bool:
    return (
        1 <= len(value) <= 200
        and re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", value) is not None
    )


def _require_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _is_identifier(value):
        raise CapabilityScaffoldError(f"{label} must be a bounded identifier")
    return value
