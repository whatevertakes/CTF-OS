from pathlib import Path

import pytest

from ctf_os.challenge import SelectionError, resolve_selector
from ctf_os.contest import ContestError, parse_contest
from conftest import write_contest


def test_korean_english_alias_multiline_override_and_stable_order(repo: Path) -> None:
    path = write_contest(repo, """# 대회명: Demo CTF
- 날짜: 2026-01-02
- Flag Format: DEMO{...}
## 문제 목록
### pwn/한글 문제
- 점수: 500
- 설명: 첫 줄
  둘째 줄
- Remote: nc example.com 31337
### web/Same
- Description: web app
- Flag Pattern: \\ADEMO\\{web-[0-9]+\\}\\Z
""")
    first = parse_contest(path)
    second = parse_contest(path)
    assert [c.number for c in first.challenges] == [1, 2]
    assert first.challenges[0].description == "첫 줄\n둘째 줄"
    assert first.challenges[0].score == 500
    assert first.challenges[0].id == second.challenges[0].id
    assert first.challenges[0].workspace_name.isascii()
    assert first.challenges[1].flag_pattern == r"\ADEMO\{web-[0-9]+\}\Z"


@pytest.mark.parametrize("selector", ["1", "01", "1번", "1번 문제", "pwn/한글 문제", "한글 문제"])
def test_selectors(repo: Path, selector: str) -> None:
    manifest = parse_contest(write_contest(repo, "# Demo CTF\n### pwn/한글 문제\n- 설명: x\n"))
    assert resolve_selector(manifest.challenges, selector).number == 1


def test_ambiguous_name_and_duplicates_are_rejected(repo: Path) -> None:
    manifest = parse_contest(write_contest(repo, "# Demo CTF\n### pwn/Same\n### web/Same\n"))
    with pytest.raises(SelectionError) as exc:
        resolve_selector(manifest.challenges, "Same")
    assert len(exc.value.candidates) == 2
    duplicate = repo / "incoming" / "Other" / "contest.md"
    duplicate.parent.mkdir()
    duplicate.write_text("# Other\n### pwn/X\n### PWN/x\n", encoding="utf-8")
    with pytest.raises(ContestError, match="duplicate"):
        parse_contest(duplicate)


def test_path_and_category_safety(repo: Path) -> None:
    path = write_contest(repo, "# Demo CTF\n### pwn/../escape\n")
    with pytest.raises(ContestError, match="unsafe"):
        parse_contest(path)
    path.write_text("# Demo CTF\n### unknown/X\n", encoding="utf-8")
    with pytest.raises(ContestError, match="unsupported"):
        parse_contest(path)


def test_unknown_fields_are_preserved_with_sensitive_typo_suggestions(repo: Path) -> None:
    path = write_contest(repo, """# Demo CTF
- Team: blue
### web/App
- Remtoe: https://example.test
- Descriptiom: typo
""")
    manifest = parse_contest(path)
    assert manifest.warnings[0].field == "Team"
    warnings = manifest.challenges[0].warnings
    assert [(warning.suggestion, warning.severity) for warning in warnings] == [
        ("remote", "HIGH"), ("description", "HIGH"),
    ]
    payload = manifest.to_dict()
    assert payload["challenges"][0]["warnings"][0]["line"] == 4


def test_empty_manifest_and_html_comment_examples_do_not_create_challenges(repo: Path) -> None:
    path = write_contest(repo, """# Demo CTF
- 입력 프로필: standard

<!--
### pwn/Example
- 설명: this is documentation, not a challenge
-->
""")

    manifest = parse_contest(path)

    assert manifest.name == "Demo CTF"
    assert manifest.challenges == ()


def test_fenced_markdown_examples_do_not_create_challenges(repo: Path) -> None:
    path = write_contest(repo, """# Demo CTF

```markdown
### pwn/Example
- 설명: this is documentation, not a challenge
```
""")

    manifest = parse_contest(path)

    assert manifest.name == "Demo CTF"
    assert manifest.challenges == ()


def test_fenced_examples_require_a_matching_fence_to_resume_parsing(repo: Path) -> None:
    path = write_contest(repo, """# Demo CTF

````markdown
### pwn/Example
```
### web/StillExample
````
""")

    manifest = parse_contest(path)

    assert manifest.challenges == ()


@pytest.mark.parametrize("category", ["mobile", "hardware", "blockchain", "jail", "windows"])
def test_extended_categories_use_generic_playbook_without_being_blocked(repo: Path, category: str) -> None:
    manifest = parse_contest(write_contest(repo, f"# Demo CTF\n### {category}/X\n"))
    challenge = manifest.challenges[0]
    assert challenge.category == category
    assert challenge.playbook_category == "misc"


@pytest.mark.parametrize("category", ["osint", "ai", "cloud"])
def test_first_class_extended_categories_have_dedicated_playbooks(repo: Path, category: str) -> None:
    manifest = parse_contest(write_contest(repo, f"# Demo CTF\n### {category}/X\n"))
    assert manifest.challenges[0].playbook_category == category


def test_input_profile_defaults_overrides_and_rejects_arbitrary_limits(repo: Path) -> None:
    path = write_contest(repo, """# Demo CTF
- Input Profile: large
### forensic/Disk
### misc/Small
- 입력 프로필: standard
""")
    manifest = parse_contest(path)
    assert manifest.input_profile == "large"
    assert [challenge.input_profile for challenge in manifest.challenges] == ["large", "standard"]
    path.write_text("# Demo CTF\n### forensic/Disk\n- Input Profile: huge\n", encoding="utf-8")
    with pytest.raises(ContestError, match="allowed"):
        parse_contest(path)
