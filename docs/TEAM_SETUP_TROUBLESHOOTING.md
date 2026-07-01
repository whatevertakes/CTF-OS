# 팀 설정 문제 해결

팀원이 저장소를 이미 클론했지만 설정이나 MCP가 소유자 환경처럼 동작하지 않을
때 이 문서를 사용합니다.

## 한 번에 복구

저장소 루트에서 실행합니다.

```bash
tools/repair_team_setup.sh
```

이 명령은 다음 작업을 수행합니다.

- 이전 tracked `.codex/config.toml` 변경이 pull을 막는 경우 되돌립니다.
- 최신 `main`을 가져옵니다.
- 현재 클론 경로에 맞는 로컬 `.codex/config.toml`을 다시 생성합니다.
- 엄격한 설정 검증을 다시 실행합니다.
- `codex mcp list`를 출력합니다.

예상 성공 표시:

```text
summary failures=0 warnings=0
team parity summary failures=0
```

`codex mcp list`에는 다음 서버가 포함되어야 합니다.

```text
angr
playwright
radare2
```

이 로컬 stdio MCP 서버에서 `Auth Unsupported`가 표시되는 것은 정상입니다.

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
tools/repair_team_setup.sh
```

복구 스크립트는 필요한 경우 pull 전에 이전 tracked `.codex/config.toml` 변경을
되돌립니다. 챌린지 데이터는 `.codex/config.toml`에 저장하지 않습니다.

### `MCP client for angr failed to start`

다음을 실행합니다.

```bash
git pull origin main
tools/bootstrap_wsl2.sh --skip-apt --skip-python --skip-preflight
```

현재 `main`은 `angr-mcp`의 FastMCP 시작 배너를 억제합니다. 이 env 설정이
없으면 stdio handshaking이 실패할 수 있습니다.

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
