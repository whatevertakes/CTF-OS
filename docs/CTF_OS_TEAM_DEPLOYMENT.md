# CTF-OS 팀 배포 — 수동 Solve Session

각 팀원은 같은 검증된 source commit을 사용하지만 설정, incoming, output, Docker,
Codex 로그인과 실행 상태는 자기 PC에만 둡니다. 노드 사이 상태 동기화나 원격 제어는
없습니다.

## 노드 식별

같은 참가 팀은 같은 `contest.team_id`와 대회 이름을 사용하고, `member.name`과
`paths.output`은 PC마다 다르게 둡니다.

```yaml
mode: manual_workbench
solver_mode: manual_solve_session

contest:
  name: "SCA CTF 2026"
  team_id: "sca-team"

member:
  name: "jiwoong"
  owned_categories: [pwn, web]

paths:
  incoming: incoming
  output: output/sca-team/jiwoong
```

SQLite를 사용하는 유지보수 명령은 기존 DB의 `team_id + member + contest` 정체성을
계속 검증합니다. 다른 팀이나 대회로 기존 설정/DB를 바꾸지 말고 새 설정을 만듭니다.

## 설치

```bash
git switch main
git pull --ff-only origin main
uv sync --frozen
uv run ctf-os init "SCA CTF 2026" \
  --config local.sca-team.jiwoong.yaml \
  --team-id sca-team \
  --member jiwoong
scripts/deploy_ctf_os.sh --config local.sca-team.jiwoong.yaml
```

실제 풀이 전 `model_routing.enabled: true`와 검토된 routing 파일을 설정합니다.
`ctf-os solve`는 sandbox image를 자동으로 빌드하지 않으므로 배포 스크립트와
`doctor --non-mock`을 먼저 성공시켜야 합니다.

## 대회 운영

사람이 `contest.md`와 문제 파일을 준비한 뒤 intake만 실행합니다.

```bash
uv run ctf-os intake --config local.sca-team.jiwoong.yaml
```

출력된 문제별 `ready`, `needs_preparation`, `blocked` 목록과 `briefs/*/intake.md`를
사람이 확인합니다. 그다음 담당자가 문제 하나를 명시적으로 시작합니다.

```bash
uv run ctf-os solve NBB \
  --config local.sca-team.jiwoong.yaml \
  --lead sol \
  --max-subworkers 3 \
  --priority high \
  --runtime standard
```

다른 문제는 자동 시작되지 않습니다. 별도 TUI는 없으며 solve 터미널과 문제별
`plan.md`, `notes.md`, `evidence.log`, `findings.jsonl`, `session.json`을 확인합니다.
Flag 제출은 사람이 CTFd에서 직접 합니다.

## 공유 금지

Git이나 team bundle에는 source만 넣습니다. 다음은 공유하거나 커밋하지 않습니다.

- `local.*.yaml`
- `incoming/`
- `output/` 및 SQLite
- Codex/CTFd 자격 증명
- 실제 flag와 로컬 evidence

`ctf-os run`은 전역 scheduler를 시작하지 않습니다. `ctf-os parse`와 `ctf-os tui`는
제거되었습니다.
