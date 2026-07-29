"""Create CTF challenge workspaces and launch interactive Codex sessions."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path, PureWindowsPath


class CLIError(Exception):
    """An expected, user-facing CLI failure."""

    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[object]]
INCOMING_DIRECTORY = "incoming"


def _validate_component(value: str, label: str) -> str:
    """Validate one literal directory name without normalizing it."""
    if not value or not value.strip():
        raise CLIError(f"{label} 이름은 비어 있을 수 없습니다.")
    if value in {".", ".."}:
        raise CLIError(f"{label} 이름으로 '.' 또는 '..'을 사용할 수 없습니다.")
    if Path(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise CLIError(f"{label} 이름에 절대경로를 사용할 수 없습니다: {value!r}")
    if "/" in value or "\\" in value:
        raise CLIError(f"{label} 이름에 경로 구분자를 사용할 수 없습니다: {value!r}")
    if "\0" in value:
        raise CLIError(f"{label} 이름에 NUL 문자를 사용할 수 없습니다.")
    return value


def _parse_challenge(value: str) -> tuple[str, str]:
    """Parse the exact ``category/challenge`` form accepted by init-contest."""
    if value.count("/") != 1 or "\\" in value:
        raise CLIError(
            "--challenge는 정확히 '카테고리/문제' 형식이어야 합니다."
        )

    category, challenge = value.split("/", 1)
    return (
        _validate_component(category, "카테고리"),
        _validate_component(challenge, "문제"),
    )


def _workspace_path(root: Path, *components: str) -> Path:
    """Build a path and reject escapes, including escapes through symlinks."""
    root = root.resolve()
    candidate = root.joinpath(*components)

    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as error:
        raise CLIError("대상 경로가 현재 작업공간 밖을 가리킵니다.") from error

    return candidate


def init_contest(root: Path, contest: str, challenge_spec: str) -> Path:
    """Create and return one contest/category/challenge directory."""
    contest = _validate_component(contest, "대회")
    category, challenge = _parse_challenge(challenge_spec)
    challenge_dir = _workspace_path(
        root, INCOMING_DIRECTORY, contest, category, challenge
    )

    try:
        challenge_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise CLIError(
            f"문제 폴더를 생성할 수 없습니다: {challenge_dir} ({error})"
        ) from error

    if not challenge_dir.is_dir():
        raise CLIError(f"문제 경로가 디렉터리가 아닙니다: {challenge_dir}")

    return challenge_dir


def build_initial_prompt(
    contest: str, category: str, challenge: str, details: str
) -> str:
    """Combine stable challenge context with the user's supplied details."""
    context = f"{contest}의 {category} 카테고리 {challenge} 문제다."
    if not details:
        return context
    return f"{context}\n\n{details}"


def solve(
    root: Path,
    contest: str,
    category: str,
    challenge: str,
    details: str,
    runner: Runner = subprocess.run,
) -> int:
    """Run Codex interactively for an existing challenge directory."""
    contest = _validate_component(contest, "대회")
    category = _validate_component(category, "카테고리")
    challenge = _validate_component(challenge, "문제")
    challenge_dir = _workspace_path(
        root, INCOMING_DIRECTORY, contest, category, challenge
    )

    if not challenge_dir.exists():
        raise CLIError(
            "문제 폴더가 존재하지 않습니다. 먼저 init-contest를 실행하세요: "
            f"{challenge_dir}"
        )
    if not challenge_dir.is_dir():
        raise CLIError(f"문제 경로가 디렉터리가 아닙니다: {challenge_dir}")

    prompt = build_initial_prompt(contest, category, challenge, details)
    command = ["codex", "-C", str(challenge_dir), prompt]

    try:
        result = runner(command)
    except FileNotFoundError as error:
        raise CLIError(
            "Codex 실행 파일을 찾을 수 없습니다. 'codex'가 PATH에 있는지 "
            "확인하세요.",
            exit_code=127,
        ) from error
    except OSError as error:
        raise CLIError(
            f"Codex를 실행할 수 없습니다: {error}", exit_code=126
        ) from error

    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf_os.agent_tools",
        description="CTF 문제 작업공간을 만들고 Codex 풀이 세션을 시작합니다.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init-contest", help="대회 아래에 문제 폴더 하나를 만듭니다."
    )
    init_parser.add_argument("contest", metavar="대회")
    init_parser.add_argument(
        "--challenge",
        required=True,
        metavar="카테고리/문제",
        help="추가할 문제를 정확히 '카테고리/문제' 형식으로 지정합니다.",
    )

    solve_parser = subparsers.add_parser(
        "solve", help="기존 문제 폴더에서 Codex 풀이 세션을 시작합니다."
    )
    solve_parser.add_argument("contest", metavar="대회")
    solve_parser.add_argument("category", metavar="카테고리")
    solve_parser.add_argument("challenge", metavar="문제")
    solve_parser.add_argument("details", metavar="문제정보")

    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path | None = None,
    runner: Runner = subprocess.run,
) -> int:
    """CLI entry point, with injectable root and runner for verification."""
    args = build_parser().parse_args(argv)
    workspace_root = (root if root is not None else Path.cwd()).resolve()

    try:
        if args.command == "init-contest":
            challenge_dir = init_contest(
                workspace_root, args.contest, args.challenge
            )
            print(f"문제 폴더 준비 완료: {challenge_dir}")
            return 0

        if args.command == "solve":
            return solve(
                workspace_root,
                args.contest,
                args.category,
                args.challenge,
                args.details,
                runner,
            )
    except CLIError as error:
        print(f"오류: {error}", file=sys.stderr)
        return error.exit_code

    raise AssertionError(f"처리되지 않은 명령: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
