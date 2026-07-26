from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = REPOSITORY_ROOT / "docs"


def test_repository_uses_one_canonical_markdown_file_per_subject() -> None:
    repository_docs = [*REPOSITORY_ROOT.glob("README*.md"), *DOCS_ROOT.rglob("*.md")]
    localized_docs = sorted(
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in repository_docs
        if path.name.endswith((".en.md", ".ko.md"))
    )

    assert localized_docs == []


def test_live_product_plan_is_not_duplicated_in_repository() -> None:
    assert not (DOCS_ROOT / "PAJIN_PRODUCT_PLAN.md").exists()

    policy = (DOCS_ROOT / "DOCUMENTATION_POLICY.md").read_text(encoding="utf-8")
    assert "https://app.notion.com/p/3a94b2ea35f081329974c7f57eda299a" in policy
    assert "Roadmap, priority, progress, blockers, and milestones" in policy
