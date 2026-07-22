# CTF-OS

허가된 CTF 문제 하나를 준비하고, 격리된 sandbox에서 풀이 명령을 실행하는 도구다. 플래그 제출은 자동화하지 않는다.

## 1. 대회 전에 준비하기

Docker와 `uv`가 설치된 환경에서 의존성과 category image를 준비한다.

```bash
uv sync --frozen
sandbox/build-images.sh
uv run python -m ctf_os.agent_tools doctor
```

풀이 중에는 image를 새로 빌드하거나 내려받지 않는다. `doctor`가 실패하면 대회 전에 원인을 해결한다.

## 2. 문제 파일 배치하기

대회 입력은 `incoming/<대회>/` 아래에 둔다.

```text
incoming/
└── Demo CTF/
    ├── contest.md
    └── web/
        └── Example/
            ├── app.py
            └── Dockerfile
```

`contest.md` 예시:

```markdown
# 대회명: Demo CTF
- 플래그 패턴: \ACTF\{[^}\r\n]+\}\Z

### web/Example
- 설명: Example challenge
- 원격: https://example.invalid/
```

원격 주소가 여러 개면 `- 원격:`을 여러 번 적는다. 문제별 플래그 형식이나 패턴은 해당 문제 항목에 따로 적을 수 있다.

## 3. 문제 하나 준비하기

```bash
uv run python -m ctf_os.agent_tools race-prepare \
  'web/Example' --contest 'Demo CTF'
```

명령은 JSON으로 준비 결과를 반환한다. 다음 두 값을 먼저 확인한다.

```text
attack_ready: true
root_sandbox.status: READY
```

결과의 `root_sandbox.metadata_path`가 이후 명령에 사용할 sandbox metadata 경로다. 별도의 sandbox 생성 명령은 필요 없다.

## 4. 풀이 명령 실행하기

문제 파일 확인, 분석기, 컴파일러, 스크립트와 원격 요청은 모두 `sandbox-exec`로 실행한다.

```bash
uv run python -m ctf_os.agent_tools sandbox-exec \
  --metadata '<root_sandbox.metadata_path>' -- \
  file /challenge/app.py
```

원격 요청에는 `contest.md`에 적은 값을 그대로 `--target-identity`로 전달한다.

```bash
uv run python -m ctf_os.agent_tools sandbox-exec \
  --metadata '<root_sandbox.metadata_path>' \
  --target-identity 'https://example.invalid/' -- \
  curl -fsS https://example.invalid/
```

긴 셸이나 원격 연결은 persistent session을 사용한다.

```bash
uv run python -m ctf_os.agent_tools session-open \
  --metadata '<root_sandbox.metadata_path>' \
  --session solve-shell --kind shell -- /bin/bash

uv run python -m ctf_os.agent_tools session-send \
  --metadata '<root_sandbox.metadata_path>' \
  --session solve-shell --data $'ls -la /challenge\n' --timeout 10

uv run python -m ctf_os.agent_tools session-read \
  --metadata '<root_sandbox.metadata_path>' \
  --session solve-shell --limit 65536 --timeout 2

uv run python -m ctf_os.agent_tools session-close \
  --metadata '<root_sandbox.metadata_path>' \
  --session solve-shell
```

설치된 도구는 필요할 때 조회한다.

```bash
uv run python -m ctf_os.agent_tools list-tools \
  --metadata '<root_sandbox.metadata_path>'
uv run python -m ctf_os.agent_tools tool-help gdb \
  --metadata '<root_sandbox.metadata_path>'
uv run python -m ctf_os.agent_tools tool-version gdb \
  --metadata '<root_sandbox.metadata_path>'
```

## 5. 병렬 worker 준비하기

필요한 경우 최대 세 lane을 한 번에 준비한다. 각 lane에는 서로 다른 `attack_family`와 구체적인 작업을 지정한다.

```bash
uv run python -m ctf_os.agent_tools race-bootstrap \
  'web/Example' --contest 'Demo CTF' --lanes-json '[
    {
      "model_profile": "sol-xhigh",
      "role": "alternate attacker",
      "task": "test protocol state transitions",
      "context_mode": "fresh",
      "attack_family": "protocol-state"
    }
  ]'
```

반환된 각 lane의 `spawn_agent_args`로 native worker를 시작하고, 실제 thread ID를 기록한다.

```bash
uv run python -m ctf_os.agent_tools race-spawn-confirm \
  --run-id '<run_id>' --lane '<lane_id>' \
  --native-session '<thread_id>'
```

worker를 중단한 뒤에는 같은 thread ID로 종료를 확인한다.

```bash
uv run python -m ctf_os.agent_tools race-stop-confirm \
  --run-id '<run_id>' --lane '<lane_id>' \
  --native-session '<thread_id>'
```

## 6. 상태 확인과 종료

현재 진행 상황, 중복 실행과 정체 신호를 확인한다.

```bash
uv run python -m ctf_os.agent_tools race-status --run-id '<run_id>'
```

실제 실행 결과에서 유효한 플래그 후보가 검출되면 결과에 즉시 표시된다. 다른 worker를 중단한 뒤 사람이 직접 제출한다.

풀이를 중단할 때는 run을 종료한 다음 CTF-OS가 만든 해당 run의 자원만 정리한다.

```bash
uv run python -m ctf_os.agent_tools race-end \
  --run-id '<run_id>' --reason STOPPED

uv run python -m ctf_os.agent_tools race-cleanup \
  --run-id '<run_id>'
```

모든 명령과 옵션은 다음처럼 확인할 수 있다.

```bash
uv run python -m ctf_os.agent_tools --help
uv run python -m ctf_os.agent_tools race-prepare --help
```
