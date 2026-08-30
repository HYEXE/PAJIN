import re
from pathlib import Path
from urllib.parse import unquote

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = REPOSITORY_ROOT / "docs"

MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def test_repository_uses_one_canonical_markdown_file_per_subject() -> None:
    repository_docs = [*REPOSITORY_ROOT.glob("*.md"), *DOCS_ROOT.rglob("*.md")]
    localized_docs = sorted(
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in repository_docs
        if path.name.endswith((".en.md", ".ko.md"))
    )

    assert localized_docs == []


def test_repository_owns_one_bounded_operational_state_set() -> None:
    assert not (DOCS_ROOT / "PAJIN_PRODUCT_PLAN.md").exists()

    names = (
        "AGENTS.md",
        "PLAN.md",
        "HANDOFF.md",
        "DECISIONS.md",
        "KNOWN_ISSUES.md",
    )
    state_documents = [REPOSITORY_ROOT / name for name in names]
    for path in state_documents:
        assert path.is_file()
        repository_bytes = path.read_bytes().replace(b"\r\n", b"\n")
        assert len(repository_bytes) < 64 * 1024

    policy = (DOCS_ROOT / "DOCUMENTATION_POLICY.md").read_text(encoding="utf-8")
    assert "repository-first documentation model" in policy
    assert "Roadmap, priority, milestones, and completion criteria" in policy
    assert "The five root operational-state documents use Korean" in policy
    assert "The former Notion roadmap" in policy

    active_navigation = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            REPOSITORY_ROOT / "README.md",
            DOCS_ROOT / "README.md",
            DOCS_ROOT / "DOCUMENTATION_POLICY.md",
            DOCS_ROOT / "rfc" / "0001-pajin-architecture-v2.md",
        )
    )
    assert "https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a" not in active_navigation


def test_repository_markdown_relative_links_resolve() -> None:
    repository_docs = [*REPOSITORY_ROOT.glob("*.md"), *DOCS_ROOT.rglob("*.md")]
    broken: list[str] = []

    for document in repository_docs:
        text = document.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK_PATTERN.finditer(text):
            target = match.group(1).strip("<>")
            if target.startswith("#") or ":" in target.split("/", maxsplit=1)[0]:
                continue
            relative_target = unquote(target.split("#", maxsplit=1)[0])
            if relative_target and not (document.parent / relative_target).exists():
                source = document.relative_to(REPOSITORY_ROOT).as_posix()
                broken.append(f"{source} -> {target}")

    assert sorted(broken) == []
