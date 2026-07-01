# WSL2 설정

이 문서는 Ubuntu WSL2에서 Codex를 실행하는 팀원을 위한 1단계 설정 절차입니다.
이 단계는 이후 Level 3 설계 작업에 사용할 재현 가능한 CTF 풀이 데이터를
수집하는 데 필요한 기본 dependency만 설치합니다.

## 클론

```bash
git clone git@github.com:whatevertakes/ctf_workspace.git <workspace-dir>
cd <workspace-dir>
```

챌린지 출력 작업은 `main`에서 직접 하지 않습니다. 클론 직후 자기 팀 브랜치로
전환하세요.

```bash
git fetch origin
git switch --track origin/<github-user>
```

현재 팀 브랜치는 `shyunseok1029`, `holymo-ly`, `jiwoongchoi-norun`입니다.

## 팀원용 설정

저장소 루트에서 팀원용 설정 스크립트를 실행합니다.

```bash
tools/team_member_setup.sh
```

이 스크립트는 팀 브랜치를 확인하고, 팀 기준에 맞춘 Ubuntu, Python, Ruby, MCP,
리버싱 도구 표면을 설치하며, `.venv`와 `requirements.txt`를 준비합니다. 또한
`.codex/config.toml.template`에서 현재 클론 경로에 맞는 로컬
`.codex/config.toml`을 생성하고 다음 검증을 실행합니다.

```bash
python3 tools/preflight_check.py --strict-optional
python3 tools/check_team_parity.py
codex mcp list
```

고급 CTF 카테고리별 도구 프로필까지 검수하려면 다음을 사용합니다.

```bash
tools/team_member_setup.sh --deep
```

시스템 패키지를 별도로 관리한다면 다음을 사용합니다.

```bash
tools/team_member_setup.sh --skip-apt
```

Python dependency가 이미 설치되어 있다면 다음을 사용합니다.

```bash
tools/team_member_setup.sh --skip-python
```

전체 parity 툴체인 없이 가벼운 baseline만 맞추려면 다음을 사용합니다.

```bash
tools/team_member_setup.sh --minimal
```

## Docker

많은 챌린지 replay가 로컬 서비스 topology에 의존하므로 Docker는 baseline에
포함됩니다. 설치 후 `docker info`가 권한 오류로 실패하면 다음을 실행합니다.

```bash
sudo usermod -aG docker "$USER"
```

이후 WSL2 셸을 다시 시작하고 다음을 다시 실행합니다.

```bash
. .codex/env.sh
python3 tools/preflight_check.py
```

## 예상 출력

`tools/preflight_check.py --strict-optional`은 failure 없이 끝나야 합니다. 팀
parity 검증도 통과해야 합니다.

```bash
python3 tools/check_team_parity.py
```

## 데이터 목표

1단계에서는 러너에게 프레임워크 파일 수정을 요구하지 않습니다. 목표는 모든
러너가 비교 가능한 챌린지 데이터를 생성하도록 만드는 것입니다.

```text
challenges/<event>/<category>/<challenge>/state.json
challenges/<event>/<category>/<challenge>/notes.md
challenges/<event>/<category>/<challenge>/replay.sh
challenges/<event>/<category>/<challenge>/evidence/*.summary.md
benchmarks/*_SANITIZED_BENCHMARK_REPORT.md
```
