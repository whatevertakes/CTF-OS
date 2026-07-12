# CTF-OS

CTF-OS는 팀원 각자의 PC에서 독립적으로 실행되는 로컬 CTF 풀이 시스템입니다.
문제를 세부 유형으로 분류하고, 전략별 Docker harness를 실행하며, 발견 사항에
따라 계약을 재계획합니다. 상태와 artifact는 각 PC의 SQLite/output에만 남습니다.

이 시스템이 하지 않는 일도 명확합니다.

- 다른 팀원 PC의 process나 상태를 제어하지 않습니다.
- `contest.md`에 선언되지 않은 원격 대상에 접근하지 않습니다.
- CTFd에 플래그를 자동 제출하지 않습니다.
- 설정, SQLite, credential, 실제 flag를 Git이나 팀 bundle로 공유하지 않습니다.

## 5분 시작

필요한 것은 Linux, Git, Docker, `uv`, 인증된 Codex CLI입니다. 모든 명령은
저장소 루트에서 실행합니다.

```bash
git clone https://github.com/whatevertakes/CTF-OS.git
cd CTF-OS
uv sync --frozen

uv run ctf-os init "Next CTF 2026" \
  --config local.next-a.jiwoong.yaml \
  --team-id next-a \
  --member jiwoong

scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml
uv run ctf-os doctor --config local.next-a.jiwoong.yaml --non-mock
```

초기화가 만든 `incoming/Next CTF 2026/contest.md`에 문제를 추가합니다.

```markdown
# 대회명: Next CTF 2026

## 대회 정보
- 팀: next-a

## 문제 목록

### pwn/heap-school
- 점수: 400
- 원격: nc challenge.example 31337
- 설명: 승인된 대회 문제

### web/login
- 점수: 200
- 설명: 로컬 파일로 제공되는 웹 문제
```

문제 파일은 `incoming/Next CTF 2026/<category>/<challenge>/` 아래에 둡니다.
그다음 현재 PC 담당 문제만 queue에 넣고 실행합니다.

```bash
uv run ctf-os parse --config local.next-a.jiwoong.yaml
uv run ctf-os tui --plain --config local.next-a.jiwoong.yaml
uv run ctf-os run --config local.next-a.jiwoong.yaml
```

플래그 후보와 검증 결과는 로컬 화면에서 확인하고, 실제 제출은 사람이 합니다.

## 팀이 먼저 맞출 세 값

| 값 | 팀 규칙 | 예시 |
| --- | --- | --- |
| 대회 이름 | 같은 대회 참가자는 완전히 같은 철자 | `Next CTF 2026` |
| `team_id` | 같은 참가 팀끼리 동일 | `next-a` |
| `member.name` | PC마다 고유 | `jiwoong` |

설정 파일은 `local.<team>.<member>.yaml`, output은
`output/<team>/<member>`를 사용합니다. SQLite는 최초의
`team_id + member + contest` 조합에 묶이므로 다른 대회나 다른 팀 설정으로
기존 DB를 열면 안전하게 거부됩니다.

팀원끼리 공유하는 것은 다음뿐입니다.

- 같은 Git commit 또는 검증된 team source bundle
- 같은 대회 이름, `team_id`, `contest.md` 문제 식별자
- 사람이 합의한 문제 담당 범위

공유하지 않는 것은 `local.*.yaml`, `incoming/`, `output/`, SQLite, Codex 로그인,
Docker runtime, credential, 실제 flag입니다.

### KISIA four-member example

| member | `team_id` | 담당 예시 | 로컬 설정 |
| --- | --- | --- | --- |
| `jiwoong` | `sca-jiwoong-team` | pwn, web | `local.sca-jiwoong-team.jiwoong.yaml` |
| `jueon` | `sca-jiwoong-team` | rev, crypto | `local.sca-jiwoong-team.jueon.yaml` |
| `hyunseok` | `sca-jiwoong-team` | forensics, misc | `local.sca-jiwoong-team.hyunseok.yaml` |
| `howon` | `sca-jiwoong-team` | cloud, web | `local.sca-jiwoong-team.howon.yaml` |

네 노드는 같은 코드를 사용하지만 설정, DB, output, worker는 완전히 분리됩니다.

## 팀원별 설정

`init` 후 `local.<team>.<member>.yaml`에서 주로 아래만 바꿉니다.

```yaml
contest:
  name: "Next CTF 2026"
  team_id: "next-a"
  flag_patterns:
    - "FLAG\\{[^}]+\\}"

member:
  name: "jiwoong"
  owned_categories: [pwn, web]

paths:
  incoming: "incoming"
  output: "output/next-a/jiwoong"

model_routing:
  enabled: true
  config_path: "config/model-routing.yaml"
```

Sol은 계획·감독·검증, Terra는 일반 풀이와 구현, Luna는 recon과 저비용 시도를
담당합니다. 실제 선택은 [model-routing.yaml](config/model-routing.yaml)에 따라
자동으로 이루어집니다.

## 대회 전 체크리스트

각 팀원이 자기 PC에서 순서대로 실행합니다.

```bash
git status --short
git pull --ff-only origin main
scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml
uv run ctf-os doctor --config local.next-a.jiwoong.yaml --non-mock
uv run ctf-os capabilities
uv run ctf-os parse --config local.next-a.jiwoong.yaml
uv run ctf-os tui --plain --config local.next-a.jiwoong.yaml
```

- 네 PC가 같은 Git commit인지 확인합니다.
- 같은 참가 팀의 `team_id`와 대회 이름이 같은지 확인합니다.
- 각 `member.name`과 output 경로가 겹치지 않는지 확인합니다.
- `contest.md`의 원격이 승인된 challenge endpoint인지 확인합니다.
- `doctor --non-mock`이 성공하기 전에는 실제 worker를 실행하지 않습니다.

## 대회 중 자주 쓰는 명령

| 명령 | 용도 |
| --- | --- |
| `uv run ctf-os run --config <CONFIG>` | queue를 계속 처리 |
| `uv run ctf-os run --once --config <CONFIG>` | 현재 queue를 한 번 처리 |
| `uv run ctf-os tui --config <CONFIG>` | 로컬 진행 상황 확인 |
| `uv run ctf-os tui --readonly --config <CONFIG>` | worker를 건드리지 않고 상태만 관찰 |
| `uv run ctf-os pause <문제> --config <CONFIG>` | 현재 PC의 문제 중지 |
| `uv run ctf-os resume <문제> --config <CONFIG>` | 중지한 문제 재개 |
| `uv run ctf-os retry <문제> --config <CONFIG>` | 실패한 문제 재시도 |
| `uv run ctf-os sandbox cleanup --config <CONFIG>` | 현재 team/member/contest container만 정리 |

## 대회가 바뀔 때

기존 설정의 대회 이름이나 `team_id`를 수정하지 않습니다. 새 대회마다 새 설정과
새 output을 만듭니다.

```bash
uv run ctf-os init "Another CTF 2026" \
  --config local.another-a.jiwoong.yaml \
  --team-id another-a \
  --member jiwoong
```

이 방식이면 과거 대회의 DB와 artifact를 보존하면서 대회 수에 제한 없이 확장할
수 있습니다. 4인 팀이 일시적으로 2+2로 나뉘는 경우에도 각 참가 팀에 새
`team_id`와 설정 파일을 만들고, 이전 설정은 그대로 둡니다.

자세한 운영 예시는 [팀 배포 가이드](docs/CTF_OS_TEAM_DEPLOYMENT.md)를 참고하세요.

## 인터넷 없이 팀원에게 전달하기

commit된 source만 재현 가능한 gzip bundle로 만들 수 있습니다.

```bash
make team-bundle
cd dist/team-bundle
sha256sum -c ctf-os-team-*.tar.gz.sha256
tar -xzf ctf-os-team-*.tar.gz
cd CTF-OS
```

bundle에는 로컬 설정, DB, incoming 문제, output, credential, flag, benchmark 결과가
들어가지 않습니다. Docker image는 크고 플랫폼 의존적이므로 포함하지 않으며,
압축을 푼 각 PC에서 아래 명령으로 재현합니다.

```bash
uv sync --frozen
scripts/deploy_ctf_os.sh --config local.<team>.<member>.yaml
```

패키징 상세는 [release packaging 문서](docs/release-packaging.md)에 있습니다.

## Tactical engine이 확장되는 위치

새 대회는 보통 코드 변경 없이 `contest.md`와 문제 파일만 추가하면 됩니다. 새로운
유형이나 도구가 필요할 때는 아래 extension point만 확장합니다.

| 확장 대상 | 파일 | 검증 |
| --- | --- | --- |
| 문제 subtype/evidence | [profiles.py](ctf_os/tactical_engine/profiles.py) | classifier test |
| subtype 전문 planner | [planners.py](ctf_os/tactical_engine/planners.py) | planner coverage test |
| strategy/harness/artifact | [strategies.py](ctf_os/tactical_engine/strategies.py) | strategy bootstrap test |
| semantic replan rule | [rules.py](ctf_os/tactical_engine/rules.py) | parser/evaluator/idempotency test |
| Docker capability profile | [Dockerfile.profiles](sandbox/Dockerfile.profiles) | `make smoke-profiles` |
| 로컬 지식 | `knowledge/` | knowledge index/query test |
| 실제 회귀 challenge | `benchmarks/fixtures/` | smoke/real benchmark |

strategy는 registry에 등록하고, subtype은 정확한 planner로 연결하며, artifact에는
producer·hash·consumer provenance를 남깁니다. 큰 `if/elif`, prompt-only 전략,
reference flag 주입은 extension으로 인정하지 않습니다.

구조와 schema는 [tactical engine 문서](docs/tactical-engine.md)에 설명되어 있습니다.

## 개발 및 배포 검증

```bash
make test                   # 전체 테스트
make validate-profiles      # registry/profile 정적 검증
make smoke-profiles         # base/pwn/web/forensics build 및 runtime smoke
make benchmark-smoke        # 외부 모델 없는 빠른 E2E
make benchmark-real         # 실제 Codex + Docker E2E
make benchmark-compare-real # 동일 seed legacy/tactical 측정
```

benchmark parent verifier는 정답을 worker/model/workspace에 전달하지 않고 candidate
hash와 검증 결과만 event/report에 남깁니다. benchmark도 flag를 자동 제출하지
않습니다.

## 자주 막히는 문제

- `uv` cache 권한 오류: `export UV_CACHE_DIR="${TMPDIR:-/tmp}/ctf-os-uv-cache-$UID"`
- DB identity 오류: 기존 DB를 수정하지 말고 현재 대회용 새 config/output 생성
- `degraded` capability: `uv run ctf-os capabilities`에서 누락 도구와 fallback 확인
- Docker image 변경: `scripts/deploy_ctf_os.sh --config <CONFIG> --rebuild-image`
- 문제 수가 다름: `owned_categories`와 `contest.md`의 `category/name` 철자 확인
- 원격 연결 거부: `contest.md`의 정확한 `nc HOST PORT` 선언과 allowlist 확인

운영 복구 절차는 [팀 배포 가이드](docs/CTF_OS_TEAM_DEPLOYMENT.md), 엔진 문제 해결은
[tactical engine 문서](docs/tactical-engine.md)를 참고하세요.
