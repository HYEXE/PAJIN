from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from platform_test_support import symlink_or_skip

import pajin.runtime.safe_files as safe_files
from pajin.runtime.safe_files import (
    load_bounded_strict_json,
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)


def test_bounded_regular_reader_enforces_size_and_leaf_identity(tmp_path: Path) -> None:
    source = tmp_path / "artifact.json"
    source.write_bytes(b'{"value":1}')

    assert read_bounded_regular_bytes(source, max_bytes=11, label="artifact") == b'{"value":1}'
    with pytest.raises(ValueError, match="10-byte limit"):
        read_bounded_regular_bytes(source, max_bytes=10, label="artifact")

    alias = tmp_path / "alias.json"
    symlink_or_skip(alias, source)
    with pytest.raises(ValueError, match=r"regular file|symbolic link"):
        read_bounded_regular_bytes(alias, max_bytes=64, label="artifact")


def test_bounded_regular_reader_rejects_symlinked_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    (real_parent / "artifact.json").write_bytes(b"{}")
    linked_parent = tmp_path / "linked"
    symlink_or_skip(linked_parent, real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="parent contains a symbolic link"):
        read_bounded_regular_bytes(
            linked_parent / "artifact.json",
            max_bytes=64,
            label="artifact",
        )


@pytest.mark.parametrize(
    "content",
    [
        b'{"key":1,"key":2}',
        b'{"nested":{"key":1,"key":2}}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1e9999}',
    ],
)
def test_strict_json_parser_rejects_ambiguous_or_nonfinite_content(content: bytes) -> None:
    with pytest.raises(ValueError, match="not strict JSON"):
        parse_strict_json_bytes(content, label="artifact")


def test_bounded_strict_json_loader_returns_exact_structure(tmp_path: Path) -> None:
    source = tmp_path / "artifact.json"
    source.write_bytes(b'{"items":[1,true,null],"nested":{"value":"ok"}}')

    assert load_bounded_strict_json(source, max_bytes=128, label="artifact") == {
        "items": [1, True, None],
        "nested": {"value": "ok"},
    }


@pytest.mark.parametrize(
    ("content", "limits", "message"),
    [
        (b"[[[0]]]", {"max_depth": 1}, "nesting-depth"),
        (b"[0,1,2]", {"max_nodes": 3}, "node-count"),
    ],
)
def test_strict_json_structural_limits_fail_before_stdlib_decode(
    content: bytes,
    limits: dict[str, int],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_decode(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("stdlib decoder ran before structural preflight")

    monkeypatch.setattr(safe_files.json, "loads", unexpected_decode)

    with pytest.raises(ValueError, match=message):
        parse_strict_json_bytes(content, label="artifact", **limits)


def test_strict_json_post_parse_walk_revalidates_resource_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def substituted_decode(*_args: object, **_kwargs: object) -> object:
        return [[[0]]]

    monkeypatch.setattr(safe_files.json, "loads", substituted_decode)

    with pytest.raises(ValueError, match="nesting-depth"):
        parse_strict_json_bytes(b"0", label="artifact", max_depth=1)


def test_bounded_read_limits_require_positive_plain_integers(tmp_path: Path) -> None:
    source = tmp_path / "artifact.json"
    source.write_bytes(b"{}")

    for invalid in (0, -1, True):
        with pytest.raises(ValueError, match="positive integer"):
            read_bounded_regular_bytes(source, max_bytes=invalid, label="artifact")


def test_revision_guard_can_ignore_only_cross_view_change_time() -> None:
    expected = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_dev=1,
        st_ino=2,
        st_size=3,
        st_mtime_ns=4,
        st_ctime_ns=5,
    )
    cross_view_values = vars(expected) | {"st_ctime_ns": 6}
    cross_view = SimpleNamespace(**cross_view_values)

    safe_files._require_same_revision(
        expected,
        cross_view,
        label="artifact",
        compare_change_time=False,
    )
    with pytest.raises(ValueError, match="changed while being read"):
        safe_files._require_same_revision(expected, cross_view, label="artifact")

    changed_content_values = vars(cross_view) | {"st_mtime_ns": 7}
    changed_content = SimpleNamespace(**changed_content_values)
    with pytest.raises(ValueError, match="changed while being read"):
        safe_files._require_same_revision(
            expected,
            changed_content,
            label="artifact",
            compare_change_time=False,
        )
