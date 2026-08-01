from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = REPOSITORY_ROOT / "docs"


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
        assert path.stat().st_size < 64 * 1024

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
