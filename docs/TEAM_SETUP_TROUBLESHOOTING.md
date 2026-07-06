# 팀 설정 문제 해결

팀원이 저장소를 이미 클론했지만 설정이나 MCP가 소유자 환경처럼 동작하지 않을
때 이 문서를 사용합니다.

## 한 번에 복구

저장소 루트에서 실행합니다.

```bash
tools/setup_workspace.sh repair
```

이 명령은 다음 작업을 수행합니다.

- 이전 tracked `.codex/config.toml` 변경이 pull을 막는 경우 되돌립니다.
- 최신 `main`을 가져옵니다.
- 현재 클론 경로에 맞는 로컬 `.codex/config.toml`을 다시 생성합니다.
- 엄격한 설정 검증을 다시 실행합니다.
- `codex mcp list`를 출력합니다.

팀원 브랜치에서 처음 설정하거나 전체 검증을 다시 돌릴 때는 다음을 사용합니다.

```bash
tools/setup_workspace.sh team
```

이 명령은 고급 CTF 도구 설치와 카테고리별 deep profile 검증까지 포함합니다.

예상 성공 표시:

```text
summary failures=0 warnings=0
team parity summary failures=0
```

고급 도구 설치는 설치 단계와 검증 단계를 분리합니다. 설치 스크립트는 가능한
경로를 최대한 시도하고, 최종 성공 여부는 `preflight --strict-deep`가 판정합니다.
따라서 `install_* || true` 형태의 best-effort 단계가 있어도 정상입니다. 설치
중단을 줄이기 위한 구조이며, managed 도구 누락은 뒤의 strict deep 검증에서
실패로 다시 드러납니다.

비대화형 Codex 세션에서 `sudo -n true`가 `sudo: a password is required`를
반환하면 apt 구간은 통째로 스킵됩니다. 이 경우 apt 대상 도구는 설치되지 않고,
Go/Cargo/source/user-local fallback이 있는 도구만 추가로 시도됩니다. apt 기반
coverage가 필요하면 일반 터미널에서 sudo가 가능한 상태로 다음을 다시 실행합니다.

```bash
. .codex/env.sh
tools/setup_workspace.sh advanced
```

기본 apt 저장소에 패키지 후보가 없는 경우도 있습니다. 예를 들어 `zeek`처럼
`Candidate: (none)`인 패키지는 sudo가 가능해도 기본 repo만으로는 설치되지 않을
수 있습니다. 이런 도구는 installer가 별도 repo, upstream binary, Cargo/Go, 또는
source fallback을 시도하고, 실패하면 `WARN fallback <tool> failed`로 남깁니다.

`XSStrike`, `phpggc`, `dotnet`, `dnspy`, `NetworkMiner`, `MobSF`, `diec`,
`pestudio`, `gcloud`, `az`, `terraform`, `kubescape`, `baudline` 같은 도구는
external/manual 표면입니다. 기본 team setup에서는 자동 설치하지 않고
`EXTERNAL ...` report와 summary count로만 표시합니다. full workstation parity가
필요할 때만 다음처럼 external 누락도 실패로 처리합니다.

```bash
tools/setup_workspace.sh team --strict-external
```

`codex mcp list`에는 다음 서버가 포함되어야 합니다.

```text
angr
playwright
radare2
```

이 로컬 stdio MCP 서버에서 `Auth Unsupported`가 표시되는 것은 정상입니다.
`mcp`, `fastmcp`, `mcp-proxy`, `mcp-reverse-proxy`는 CLI 유틸리티이며 이 목록에
별도 서버로 나타나지 않는 것이 정상입니다.

## 버전 보고서

깔끔한 버전 보고서를 보려면 긴 수동 명령 블록을 붙여넣지 말고 다음을
실행합니다.

```bash
tools/version_report.sh
```

예상되는 마지막 섹션:

```text
== final checks ==
summary failures=0 warnings=0
team parity summary failures=0
```

## Codex 시작

복구가 성공하면 저장소 루트에서 새 Codex 세션을 시작합니다.

```bash
. .codex/env.sh
codex
```

Codex 안에서 다음을 실행합니다.

```text
/mcp
```

예상 MCP 서버:

```text
angr
playwright
radare2
```

## 흔한 오류

### `.codex/config.toml would be overwritten by merge`

다음을 실행합니다.

```bash
tools/setup_workspace.sh repair
```

복구 스크립트는 필요한 경우 pull 전에 이전 tracked `.codex/config.toml` 변경을
되돌립니다. 챌린지 데이터는 `.codex/config.toml`에 저장하지 않습니다.

### `MCP client for angr failed to start`

다음을 실행합니다.

```bash
git pull origin main
tools/setup_workspace.sh bootstrap --skip-apt --skip-python --skip-preflight
```

현재 `main`은 `angr-mcp`의 FastMCP 시작 배너를 억제합니다. 이 env 설정이
없으면 stdio handshaking이 실패할 수 있습니다.

### `mcp` prints `typer is required`

다음을 실행합니다.

```bash
tools/setup_workspace.sh bootstrap --skip-apt --skip-preflight
. .codex/env.sh
mcp --help
```

`requirements.txt`는 `mcp[cli]`와 `fastmcp`를 함께 설치합니다. 이전 venv가
남아 있으면 `mcp` 명령만 있고 CLI extra가 빠진 상태가 될 수 있습니다.

### `mcp-reverse-proxy` import error

다음을 실행합니다.

```bash
tools/setup_workspace.sh bootstrap --skip-apt --skip-preflight
. .codex/env.sh
mcp-reverse-proxy --version
```

현재 기준은 `mcp-proxy`입니다. bootstrap은 과거 `mcp-reverse-proxy` 진입점이
깨져 있으면 같은 CLI 표면을 유지하는 compatibility wrapper를 생성합니다.
기존 `.venv`가 다른 clone 경로에서 만들어진 상태라면 bootstrap이 자동으로
감지해 `.venv`를 재생성합니다. 이 경우 `cannot execute: required file not
found`나 `cannot import name 'client'` 오류가 같이 사라져야 합니다.

### `RsaCtfTool` starts but crashes

다음을 실행합니다.

```bash
tools/setup_workspace.sh bootstrap --skip-apt --skip-preflight
RsaCtfTool --help
```

`RsaCtfTool`은 메인 `.venv`에 직접 넣지 않고 별도 venv로 격리합니다. 이 도구의
고정 dependency가 일반 HTTP/crypto 패키지를 다운그레이드할 수 있기 때문입니다.

### WSL `curl` does not appear in Caido

먼저 CTF 전용 Caido 브리지를 다시 생성합니다.

```bash
ctf-proxy-start
. .codex/proxy.env
ctf-proxy-check
```

정상 상태에서는 UI가 `200`을 반환합니다. 프록시 중계가 `500`이고
`Caido instance/project repository is not ready` 경고가 나오면 Caido UI에서
실행 중인 인스턴스를 먼저 선택하세요. UI가 프로젝트를 요구하는 경우에만 프로젝트를
생성하거나 선택하면 됩니다.

Windows 방화벽이나 portproxy가 깨진 경우에도 `ctf-proxy-start`가 다음 항목을
다시 설정합니다.

```text
CTF Proxy 18086
CTF Proxy 18087
Windows portproxy <WSL vEthernet IP>:18086 -> 127.0.0.1:18086
Windows portproxy <WSL vEthernet IP>:18087 -> 127.0.0.1:18087
```

Caido CLI가 설치되어 있지 않으면 `ctf-proxy-start`가 최신 Windows CLI를
`%LOCALAPPDATA%\ctf-workspace\caido-cli`에 내려받아 사용합니다. 설치 다운로드가
실패하면 Windows 인터넷 연결과 GitHub/Caido download 접근을 확인하세요.

프록시가 필요 없는 replay나 benchmark에서는 현재 셸에서만 끕니다.

```bash
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
```

### `shodan` cannot import `pkg_resources`

다음을 실행합니다.

```bash
python3 -m pip install -r requirements.txt
shodan version
```

`requirements.txt`는 `setuptools<81`을 고정합니다. 최신 setuptools에서는
`pkg_resources`가 빠져 `shodan` CLI가 실패할 수 있습니다.

### `. .codex/env.sh` prints nothing

정상입니다. 이 명령은 현재 셸 환경을 갱신합니다. 다음으로 확인하세요.

```bash
echo "$CTF_WORKSPACE_ROOT"
which angr-mcp
```

예상 형태:

```text
/path/to/<workspace-dir>
/path/to/<workspace-dir>/.venv/bin/angr-mcp
```
