from collections.abc import Callable
from pathlib import Path

import pytest

from pajin.domain.manifest import load_manifest
from pajin.domain.yaml_loader import load_yaml_mapping
from pajin.modes.bug_bounty.reporting import load_bug_bounty_finding_index
from pajin.modes.bug_bounty.service import load_bug_bounty_program
from pajin.modes.ctf.service import load_ctf_challenge

_SECURITY_SENSITIVE_YAML_LOADERS: tuple[tuple[Callable[[Path], object], str], ...] = (
    (load_manifest, "examples/ai-redteam.yaml"),
    (load_bug_bounty_program, "examples/bug-bounty-program.yaml"),
    (load_bug_bounty_finding_index, "examples/bug-bounty-known-findings.yaml"),
    (load_ctf_challenge, "examples/ctf-web-backup-lab.yaml"),
)


@pytest.mark.parametrize(("loader", "example"), _SECURITY_SENSITIVE_YAML_LOADERS)
def test_security_sensitive_yaml_loaders_accept_supported_examples(
    loader: Callable[[Path], object],
    example: str,
) -> None:
    assert loader(Path(example)) is not None


@pytest.mark.parametrize(
    ("loader", "example"),
    _SECURITY_SENSITIVE_YAML_LOADERS,
)
def test_security_sensitive_yaml_loaders_reject_duplicate_root_keys(
    tmp_path: Path,
    loader: Callable[[Path], object],
    example: str,
) -> None:
    content = Path(example).read_text(encoding="utf-8")
    duplicate = content.replace("kind: ", "kind: duplicate-must-not-win\nkind: ", 1)
    path = tmp_path / "duplicate.yaml"
    path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate YAML key"):
        loader(path)


@pytest.mark.parametrize(
    "content, message",
    [
        ("first: &shared\n  value: 1\nsecond: *shared\n", "aliases are not allowed"),
        ("cycle: &cycle\n  self: *cycle\n", "aliases are not allowed"),
        (
            "leaf: &leaf\n  - value\nfanout: [*leaf, *leaf, *leaf, *leaf]\n",
            "aliases are not allowed",
        ),
        ("outer:\n  key: first\n  key: second\n", "duplicate YAML key"),
        ("flag: yes\n", "booleans must be written as true or false"),
        ("value: .inf\n", "non-finite YAML numbers"),
        ("value: !!binary YWJj\n", "not JSON-compatible"),
        ("1: value\n", "keys must be strings"),
    ],
)
def test_bounded_yaml_rejects_ambiguous_or_non_json_constructs(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    path = tmp_path / "input.yaml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_yaml_mapping(path, label="test manifest")


def test_bounded_yaml_rejects_excessive_depth_and_size(tmp_path: Path) -> None:
    deep = "".join("  " * index + f"level{index}:\n" for index in range(66))
    deep += "  " * 66 + "value: 1\n"
    deep_path = tmp_path / "deep.yaml"
    deep_path.write_text(deep, encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds 64 levels"):
        load_yaml_mapping(deep_path, label="deep manifest")

    large_path = tmp_path / "large.yaml"
    large_path.write_bytes(b"value: " + (b"x" * 1_048_576))
    with pytest.raises(ValueError, match="1048576-byte input limit"):
        load_yaml_mapping(large_path, label="large manifest")


def test_bounded_yaml_rejects_excessive_node_count(tmp_path: Path) -> None:
    path = tmp_path / "many-nodes.yaml"
    path.write_text("items:\n" + ("  - value\n" * 20_001), encoding="utf-8")

    with pytest.raises(ValueError, match="exceeds 20000 nodes"):
        load_yaml_mapping(path, label="many-node manifest")
