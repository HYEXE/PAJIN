"""Bounded, unambiguous YAML loading for security-sensitive manifests."""

from __future__ import annotations

import math
from collections.abc import Hashable
from pathlib import Path
from typing import Any, cast

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError, SafeConstructor
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode

_MAX_YAML_BYTES = 1_048_576
_MAX_YAML_DEPTH = 64
_MAX_YAML_NODES = 20_000


class _BoundedStrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects aliases, duplicate keys, and ambiguous booleans."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._pajin_depth = 0
        self._pajin_nodes = 0

    def compose_node(self, parent: Node | None, index: int) -> Node:
        if self.check_event(AliasEvent):  # type: ignore[no-untyped-call]
            event = self.peek_event()  # type: ignore[no-untyped-call]
            raise ComposerError(
                None,
                None,
                "YAML aliases are not allowed in PAJIN manifests",
                event.start_mark,
            )
        self._pajin_nodes += 1
        if self._pajin_nodes > _MAX_YAML_NODES:
            event = self.peek_event()  # type: ignore[no-untyped-call]
            raise ComposerError(
                None,
                None,
                f"YAML document exceeds {_MAX_YAML_NODES} nodes",
                event.start_mark,
            )
        self._pajin_depth += 1
        if self._pajin_depth > _MAX_YAML_DEPTH:
            event = self.peek_event()  # type: ignore[no-untyped-call]
            raise ComposerError(
                None,
                None,
                f"YAML document exceeds {_MAX_YAML_DEPTH} levels",
                event.start_mark,
            )
        try:
            return cast(Node, super().compose_node(parent, index))
        finally:
            self._pajin_depth -= 1

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(
                None,
                None,
                "expected a YAML mapping",
                node.start_mark,
            )
        self.flatten_mapping(node)
        result: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "PAJIN manifest keys must be strings",
                    key_node.start_mark,
                )
            if key in result:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate YAML key is not allowed: {key!r}",
                    key_node.start_mark,
                )
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _construct_finite_float(loader: _BoundedStrictLoader, node: ScalarNode) -> float:
    value = SafeConstructor.construct_yaml_float(loader, node)
    if not math.isfinite(value):
        raise ConstructorError(
            None,
            None,
            "non-finite YAML numbers are not allowed",
            node.start_mark,
        )
    return value


def _construct_canonical_bool(loader: _BoundedStrictLoader, node: ScalarNode) -> bool:
    raw = loader.construct_scalar(node)
    normalized = raw.casefold()
    if normalized not in {"true", "false"}:
        raise ConstructorError(
            None,
            None,
            "YAML booleans must be written as true or false",
            node.start_mark,
        )
    return normalized == "true"


def _construct_timestamp_text(loader: _BoundedStrictLoader, node: ScalarNode) -> str:
    return loader.construct_scalar(node)


_BoundedStrictLoader.add_constructor("tag:yaml.org,2002:float", _construct_finite_float)
_BoundedStrictLoader.add_constructor("tag:yaml.org,2002:bool", _construct_canonical_bool)
_BoundedStrictLoader.add_constructor("tag:yaml.org,2002:timestamp", _construct_timestamp_text)


def load_yaml_mapping(path: Path, *, label: str) -> dict[str, Any]:
    """Read one UTF-8 YAML mapping within strict resource and syntax limits."""

    try:
        with path.open("rb") as handle:
            content = handle.read(_MAX_YAML_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"{label} could not be read") from exc
    if len(content) > _MAX_YAML_BYTES:
        raise ValueError(f"{label} exceeds the {_MAX_YAML_BYTES}-byte input limit")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be valid UTF-8") from exc

    try:
        raw: object = yaml.load(text, Loader=_BoundedStrictLoader)
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        reason = _safe_yaml_failure_reason(exc)
        raise ValueError(f"{label} is not valid bounded YAML: {reason}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must contain a YAML mapping")
    try:
        _require_json_value(raw)
    except ValueError as exc:
        reason = _safe_yaml_value_failure_reason(exc)
        raise ValueError(f"{label} contains unsupported YAML values: {reason}") from exc
    return cast(dict[str, Any], raw)


def _safe_yaml_failure_reason(error: BaseException) -> str:
    """Choose one fixed parser reason without copying YAML source text."""

    try:
        detail = str(error)
    except BaseException:
        return "syntax or value violation"
    for marker, reason in (
        ("aliases are not allowed", "YAML aliases are not allowed"),
        ("duplicate YAML key", "duplicate YAML key is not allowed"),
        (
            "booleans must be written as true or false",
            "YAML booleans must be written as true or false",
        ),
        ("non-finite YAML numbers", "non-finite YAML numbers are not allowed"),
        ("keys must be strings", "YAML mapping keys must be strings"),
        (f"exceeds {_MAX_YAML_DEPTH} levels", f"YAML document exceeds {_MAX_YAML_DEPTH} levels"),
        (f"exceeds {_MAX_YAML_NODES} nodes", f"YAML document exceeds {_MAX_YAML_NODES} nodes"),
        ("not JSON-compatible", "YAML value is not JSON-compatible"),
    ):
        if marker in detail:
            return reason
    return "syntax or value violation"


def _safe_yaml_value_failure_reason(error: BaseException) -> str:
    """Classify post-construction YAML values without reflecting their values or types."""

    try:
        detail = str(error)
    except BaseException:
        return "value is not JSON-compatible"
    if "non-finite number" in detail:
        return "non-finite number"
    if "mapping key is not a string" in detail:
        return "mapping keys must be strings"
    return "value is not JSON-compatible"


def _require_json_value(value: object) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _require_json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("mapping key is not a string")
            _require_json_value(item)
        return
    raise ValueError(f"value type {type(value).__name__!r} is not JSON-compatible")
