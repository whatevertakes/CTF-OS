# CTF 워크스페이스

이 저장소는 `whatevertakes` 팀 프로젝트의 표준 CTF 실행 워크스페이스입니다.

아키텍처는 의도적으로 고정되어 있습니다. 소유자는 프레임워크, 스킬, 도구,
문서, 벤치마크 정의, 저장소 정책을 관리합니다. 벤치마크 러너는 배정된 CTF
케이스를 실행하고, 정제된 실행 데이터만 제출합니다.

## 역할

- 소유자: `jiwoongchoi-norun`
  - `main`을 소유합니다.
  - 모든 변경 사항을 검토하고 병합합니다.
  - 프레임워크 파일, 도구, 스킬, 문서, 템플릿, 벤치마크 정의를 수정할 수
    있습니다.
- 벤치마크 러너:
  - 저장소를 클론하고 동일한 워크스페이스 레이아웃을 유지합니다.
  - 배정된 벤치마크 CTF 문제를 실행합니다.
  - 정제된 벤치마크 데이터만 제출합니다.
  - 프레임워크 아키텍처, 도구, 스킬, 템플릿, 참조 인덱스, 정책 파일을
    수정하지 않습니다.

## 클론 및 설정

원하는 로컬 경로에 클론하되, 저장소 안의 레이아웃은 동일하게 유지합니다.

```bash
git clone git@github.com:whatevertakes/ctf_workspace.git <workspace-dir>
cd <workspace-dir>
```

팀원은 자기 브랜치에서 팀원용 설정 스크립트를 실행합니다.

```bash
tools/team_member_setup.sh
```

이 스크립트는 팀 브랜치를 확인하고, 팀 기준에 맞춘 Ubuntu, Python, Ruby, MCP
유틸리티 CLI, CTF 카테고리별 CLI 도구 표면을 설치하며, `.venv`와
`requirements.txt`를 준비합니다. 또한
`.codex/config.toml.template`에서 현재 클론 경로에 맞는 로컬
`.codex/config.toml`을 생성하고, strict preflight, team parity, `codex mcp
list`의 `angr`/`playwright`/`radare2` 연결까지 확인합니다. 자세한 팀 설정
흐름은 [docs/SETUP_WSL2.md](docs/SETUP_WSL2.md)를 참조하세요.

설정이나 MCP가 멈추면 긴 명령 블록을 수동으로 붙여넣지 말고 복구 스크립트를
실행하세요.

```bash
tools/repair_team_setup.sh
```

예상되는 성공 표시:

```text
summary failures=0 warnings=0
team parity summary failures=0
```

`codex mcp list`에는 `angr`, `playwright`, `radare2`가 표시되어야 합니다. 이
로컬 stdio MCP 서버에서 `Auth Unsupported`가 표시되는 것은 정상입니다.
`mcp`, `fastmcp`, `mcp-proxy`, `mcp-reverse-proxy`는 서버 등록 항목이 아니라
CLI 유틸리티로 점검합니다.

깔끔한 버전 보고서를 보려면 다음을 실행합니다.

```bash
tools/version_report.sh
```

오류별 복구 절차와 예상 출력은
[docs/TEAM_SETUP_TROUBLESHOOTING.md](docs/TEAM_SETUP_TROUBLESHOOTING.md)를
참조하세요.

일부 항목을 수동으로 설치해야 한다면 vendored dependency가 아니라 명령어와
패키지 매니저를 사용하세요.

```bash
sudo apt-get update
sudo apt-get install -y bash binutils binutils-avr build-essential ca-certificates curl docker.io file gdb gcc-avr git jq libffi-dev libssl-dev netcat-openbsd nodejs npm pkg-config python3 python3-pip python3-venv unzip xz-utils avr-libc
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -r requirements.txt
tools/bootstrap_wsl2.sh --skip-apt --skip-python --skip-preflight
```

워크스페이스를 검증합니다.

```bash
python3 tools/preflight_check.py
python3 tools/preflight_check.py --strict-optional
python3 tools/check_team_parity.py
python3 tools/evaluate_corpus.py
```

## 워크스페이스 레이아웃

모든 챌린지는 표준 계약 아래에 유지합니다.

```text
challenges/<event>/<category>/<challenge>/
  state.json
  notes.md
  replay.sh
  evidence/
  dist/
  work/
```

- `dist/`: 원본 챌린지 배포 파일.
- `work/`: 로컬 스크래치 파일, 추출 파일, 빌드 출력, 프로브, 임시 dependency
  체크아웃. 광범위한 vendored dependency나 로컬 빌드 트리는 제출하지 않습니다.
- `evidence/`: 리플레이 요약과 정제된 증명 출력.
- `state.json`, `notes.md`, `replay.sh`: 보존해야 하는 벤치마크 실행 메타데이터.

## 벤치마크 러너 워크플로

배정된 챌린지를 실행합니다.

```bash
python3 tools/benchmark_runner.py run challenges/<event>/<category>/<challenge>
```

corpus 일관성을 다시 확인합니다.

```bash
python3 tools/evaluate_corpus.py
```

원시 로그나 출력에 플래그, 토큰, 키, 챌린지 시크릿이 포함되어 있다면 제출 전에
정제합니다.

```bash
python3 tools/report_sanitize.py challenges/<event>/<category>/<challenge>/evidence/<raw-log>.log --check
```

## 제출 정책

벤치마크 러너는 데이터 경로만 제출할 수 있습니다.

```text
benchmarks/*_SANITIZED_BENCHMARK_REPORT.md
challenges/<event>/<category>/<challenge>/state.json
challenges/<event>/<category>/<challenge>/notes.md
challenges/<event>/<category>/<challenge>/replay.sh
challenges/<event>/<category>/<challenge>/evidence/*.summary.md
```

다음 경로는 소유자 전용입니다.

```text
AGENTS.md
.codex/
.github/
tools/
templates/
skills/
capabilities/
docs/
benchmarks/corpus.yaml
references.yaml
references.lock.json
```

다음은 제출하지 않습니다.

```text
flags, tokens, private keys, .env files
raw replay logs containing secrets
work/extracted/
work/docker_pinned/
work/pinned_build/
work/simavr*/
local virtualenvs, caches, node_modules, or build output
```

## Git 워크플로

표준 저장소의 `main`은 소유자 `jiwoongchoi-norun`만 push합니다. 팀원은 자기
이름의 고정 브랜치에만 commit/push합니다.

팀 브랜치:

```text
shyunseok1029
holymo-ly
jiwoongchoi-norun
```

처음 클론한 뒤 자기 브랜치를 체크아웃합니다.

```bash
git fetch origin
git switch --track origin/<github-user>
tools/team_member_setup.sh
```

`main` 업데이트를 자기 브랜치에 반영하려면:

```bash
git fetch origin
git switch <github-user>
git merge origin/main
```

제출할 때는 승인된 데이터 파일만 commit하고 자기 브랜치로 push합니다.

```bash
git add benchmarks/*_SANITIZED_BENCHMARK_REPORT.md \
  challenges/<event>/<category>/<challenge>/state.json \
  challenges/<event>/<category>/<challenge>/notes.md \
  challenges/<event>/<category>/<challenge>/replay.sh \
  challenges/<event>/<category>/<challenge>/evidence/*.summary.md
git commit -m "submit benchmark data for <benchmark-id>"
git push origin HEAD:<github-user>
```

자기 브랜치에서 `main`으로 pull request를 엽니다. 직접 브랜치 push가
불가능한 경우 동일한 정제 파일을 GitHub issue에 첨부합니다. 소유자가 데이터를
검증하고 승인된 데이터만 `main`에 병합합니다.

pull request를 열기 전에 다음을 실행합니다.

```bash
python3 tools/validate_data_submission.py --base origin/main
```

전체 데이터 전용 제출 흐름은
[docs/TEAM_DATA_WORKFLOW.md](docs/TEAM_DATA_WORKFLOW.md)를 참조하세요.
