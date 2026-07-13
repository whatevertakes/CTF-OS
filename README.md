# CTF-OS manual Solve Session workbench

CTF-OS는 사람이 문제를 선택하고 지휘하는 로컬 CTF 워크벤치입니다. 대회 전체를
자동으로 순회하거나 문제를 자동 배정하지 않습니다.

## 하지 않는 일

- 대회 전체 자동 queue/scheduler
- 자동 문제 배정, 자동 재시도, 세션 밖 worker 자동 생성
- CTFd polling, 로그인 또는 flag 제출
- 팀원 PC 제어나 원격 worker 사용
- `contest.md`에 없는 원격 접속
- 별도 TUI

Flag처럼 보이는 값은 `findings.jsonl`에 후보와 증거로만 기록됩니다. 실제 제출은
사람이 합니다.

## 1. 설치와 초기화

필수 환경은 Linux, Python 3.11 이상, `uv`, Docker, 로그인된 Codex CLI입니다.

```bash
uv sync --frozen
uv run ctf-os init "SCA CTF 2026" \
  --config local.sca-team.jiwoong.yaml \
  --team-id sca-team \
  --member jiwoong
```

생성된 설정에서 담당 카테고리와 model routing을 확인합니다.

```yaml
mode: manual_workbench
solver_mode: manual_solve_session

member:
  name: jiwoong
  owned_categories: [pwn, web]

model_routing:
  enabled: true
  config_path: config/model-routing.yaml
```

## 2. 사람이 입력 준비

`incoming/<contest>/contest.md`를 작성합니다.

```markdown
# 대회명: SCA CTF 2026

## 문제 목록

### pwn/NBB
- 설명: organizer가 제공한 실제 설명
- 원격: nc challenge.example 31337
```

점수는 생략할 수 있습니다. 문제 파일은 다음 중 하나로 둡니다.

```text
incoming/<contest>/pwn/NBB.zip
incoming/<contest>/pwn/NBB/
```

현재 sandbox egress는 정확한 `nc HOST PORT` 한 개만 지원합니다. HTTP/HTTPS는
Host/TLS-SNI 강제 계층이 없어 fail-closed로 거부됩니다.

## 3. Intake만 실행

```bash
uv run ctf-os intake --config local.sca-team.jiwoong.yaml
```

이 명령은 Codex나 solver container를 시작하지 않습니다. 각 문제를 독립적으로
검사하고 다음 보고서를 만듭니다.

```text
output/<team>/<member>/<contest>/briefs/<challenge>/intake.md
```

한 문제의 ZIP, Docker 또는 파일 오류는 그 문제만 `BLOCKED`로 기록합니다. 다른 문제의
보고서는 계속 만들어집니다. 결과는 `ready`, `blocked`, `needs_preparation` 중 하나입니다.

## 4. 사람이 문제 하나를 선택해 Solve Session 시작

```bash
uv run ctf-os solve NBB \
  --config local.sca-team.jiwoong.yaml \
  --lead sol \
  --max-subworkers 3 \
  --priority high \
  --runtime standard
```

이 명령은 NBB 하나의 lead session만 시작합니다. 다른 문제에는 worker가 생기지
않습니다. Sol은 필요할 때만 고유하고 겹치지 않는 scope로 Terra/Luna/Sol worker를
요청할 수 있고, 총수는 사람이 지정한 `--max-subworkers`를 넘을 수 없습니다.

- Sol: 전체 공격 전략, 복잡한 분석, 전략 변경, 최종 evidence 검토
- Terra: exploit 구현, 로컬 재현, 자동화 코드
- Luna: 빠른 recon, 파일·환경 조사, 대안 가설

모든 challenge 명령은 attempt Docker 안에서 실행합니다. worker는 다른 문제나 다른
worker의 경로를 수정할 수 없고 승인 원격 외에는 접속할 수 없습니다.

## 5. 산출물

```text
output/<team>/<member>/<contest>/<challenge>/
  intake.md
  plan.md
  notes.md
  evidence.log
  findings.jsonl
  exploit/
  writeup.md
  handoff.md
  session.json
  workers/<worker-id>/
```

별도 TUI는 없습니다. 현재 터미널의 Sol 진행 출력과 위 파일을 봅니다. 정상 종료,
사람의 Ctrl-C, 실패 시 `session.json`은 각각 `COMPLETED`, `STOPPED`, `FAILED`로 정리됩니다.

## Runtime profile

기본값은 `standard`입니다.

`nested_podman_trusted_ctf`는 Dockerfile/Compose 재현이 꼭 필요한 검토된 CTF 문제만을
위한 명시적 opt-in입니다. 자동 선택되지 않으며 설정에서 활성화하고 전용 image를
지정해야 합니다. intake 보고서는 권한 확장과 nested-container 위험을 표시합니다.

```yaml
runtime_profiles:
  standard:
    enabled: true
  nested_podman_trusted_ctf:
    enabled: false
    trusted_ctf_only: true
    image: ctf-os-nested-podman:reviewed
```

## 폐기된 명령

`ctf-os tui`와 `ctf-os parse` 명령은 제거되었습니다. `ctf-os run`은 더 이상 자동 실행을
시작하지 않고 `intake`/`solve` 사용 안내와 함께 종료합니다. `pause`, `resume`, `retry`는
선택한 문제의 수동 session index에만 적용되며 worker를 자동 재시작하지 않습니다.

상세 설계는 [manual Solve Session 설계](docs/manual-solve-session-design.md)에 있습니다.

## 검증

```bash
uv run pytest -q tests/test_manual_workbench.py
uv run python scripts/validate_profiles.py
```
