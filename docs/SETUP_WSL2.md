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

이 스크립트는 팀 브랜치를 확인하고, 팀 기준에 맞춘 Ubuntu, Python, Ruby, MCP
유틸리티 CLI, CTF 카테고리별 CLI 도구 표면을 설치하며, `.venv`와
`requirements.txt`를 준비합니다. 또한
`.codex/config.toml.template`에서 현재 클론 경로에 맞는 로컬
`.codex/config.toml`을 생성하고 다음 검증을 실행합니다.

```bash
python3 tools/preflight_check.py --strict-optional
python3 tools/check_team_parity.py
codex mcp list
```

`codex mcp list`의 서버 기준은 `angr`, `playwright`, `radare2`입니다. `mcp`,
`fastmcp`, `mcp-proxy`, `mcp-reverse-proxy`는 MCP 서버로 추가 등록하지 않고
CLI 유틸리티로 설치와 실행 가능 여부를 점검합니다.

기본 parity CLI에는 `RsaCtfTool`, `arjun`, `flask-unsign`, `floss`, `frida`,
`shodan`, `stegolsb`, `zsteg`, `wafw00f`, `pwninit`이 포함됩니다. `Burp Suite`와
`Caido`는 외부 GUI 도구라 있으면 보고만 하고 팀 setup 실패 조건으로 삼지
않습니다.

## 웹 프록시 브리지

고급 웹 CTF에서는 Windows 브라우저 트래픽뿐 아니라 WSL의 `curl`, Python
exploit, replay script 트래픽도 Caido/Burp로 확인해야 할 때가 많습니다. 이
저장소는 Windows Caido CLI를 CTF 전용 포트로 띄우고 WSL에서 접근 가능한
portproxy를 만드는 helper를 제공합니다.

```bash
ctf-proxy-start
. .codex/proxy.env
ctf-proxy-check
```

기본 포트는 다음과 같습니다.

```text
Windows Caido proxy: 127.0.0.1:18086
Windows Caido UI:    127.0.0.1:18087
WSL proxy env:       http://<windows-vEthernet-WSL-ip>:18086
```

`ctf-proxy-start`는 Windows Caido CLI가 없으면 최신 Windows CLI를
`%LOCALAPPDATA%\ctf-workspace\caido-cli`에 설치합니다. 그 다음 현재 머신의
Windows WSL vEthernet 주소를 감지해서 로컬 전용 `.codex/proxy.env`를 생성합니다.
이 파일은 Git에 저장하지 않습니다. Caido UI에서 실행 중인 인스턴스를 선택해야
실제 요청 중계가 됩니다. UI가 프로젝트를 요구하는 경우에만 프로젝트를 생성하거나
선택하세요. `ctf-proxy-check`가 `Caido instance/project repository is not ready`를
출력하는 것은 브리지 자체가 아니라 Caido UI에서 인스턴스/프로젝트 저장소가 아직
준비되지 않은 상태입니다.

프록시가 필요 없는 풀이 단계에서는 다음으로 현재 셸의 프록시만 끕니다.

```bash
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
```

## Main 업데이트와 Level 2 Reference 동기화

`main`의 최신 도구, 문서, reference lock, category index를 받은 뒤 소유자와
같은 Level 2 reference 환경을 만들려면 다음을 실행합니다.

```bash
git pull origin main
tools/bootstrap_wsl2.sh
. .codex/env.sh
python3 tools/reference_refresh.py --materialize-all --jobs 4
python3 tools/reference_index.py --all --max-files-per-ref 120
python3 tools/preflight_check.py --strict-optional
python3 tools/check_team_parity.py
python3 tools/check_level3_tool_routing.py
```

`references.yaml`, `references.lock.json`, `docs/reference-index/`는 Git으로
공유됩니다. `.cache/references/`는 Git에 저장하지 않는 로컬 캐시이므로 각
팀원이 위 `reference_refresh.py --materialize-all` 명령으로 같은
commit/snapshot 기준 자료를 내려받아야 합니다.

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
