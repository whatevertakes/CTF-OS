# CTF-OS 팀 배포 가이드

이 문서는 4명이 각자 저장소를 clone해 운영하고, 다음 대회만 2명+2명으로 나뉘는 경우를 기준으로 합니다. 핵심은 코드만 Git으로 맞추고, 설정과 SQLite는 PC별로 분리하며, TeamSync JSONL만 `team_id`별 폴더 안에서 공유하는 것입니다.

## 먼저 이해할 구조

```text
설정 파일 (PC별)
├─ contest.team_id ───────────────┐
├─ member.name (PC마다 고유) ────┴─ sync root/<team_id>/*.events.jsonl
└─ paths.output ─────────────────── output/<team_id>/<member>/<contest>/local_state.db
```

SQLite의 `local_state.db`는 처음 연 `team_id`, `member.name`, `contest.name`을 하나의 노드 정체성으로 저장합니다. 이후 같은 DB를 이 셋 중 하나라도 다른 설정으로 열면 교차 노드 오염을 막기 위해 실행을 거부합니다. 이 오류를 없애려고 DB를 편집하거나 다른 노드의 DB를 복사하면 안 됩니다.

`paths.output`은 마지막 두 폴더가 정확히 `<team_id>/<member>`여야 합니다. 이 규칙은 DB가 이미 있는지와 관계없이 설정을 읽을 때 검사하므로, 잘못된 경로라면 빈 DB도 만들기 전에 거부됩니다.

설정 안의 상대 경로는 현재 터미널 위치가 아니라 **설정 파일이 있는 폴더**를 기준으로 계산됩니다. 설정 파일을 저장소 루트에 두는 운영이 가장 단순합니다.

## 팀 식별자 계획

### 평소 4명 한 팀

| 팀원 예시 | `team_id` | `member` | 설정 파일 | output |
| --- | --- | --- | --- | --- |
| jiwoong | `sca-jiwoong-team` | `jiwoong` | `local.sca-jiwoong-team.jiwoong.yaml` | `output/sca-jiwoong-team/jiwoong` |
| jueon | `sca-jiwoong-team` | `jueon` | `local.sca-jiwoong-team.jueon.yaml` | `output/sca-jiwoong-team/jueon` |
| hyunseok | `sca-jiwoong-team` | `hyunseok` | `local.sca-jiwoong-team.hyunseok.yaml` | `output/sca-jiwoong-team/hyunseok` |
| howon | `sca-jiwoong-team` | `howon` | `local.sca-jiwoong-team.howon.yaml` | `output/sca-jiwoong-team/howon` |

네 사람의 `contest.team_id`는 같고, `member.name`은 모두 달라야 합니다.

### 다음 대회만 2명+2명

| 참가 팀 | 팀원 예시 | `team_id` | 설정 파일 예시 |
| --- | --- | --- | --- |
| A팀 | jiwoong, jueon | `next-a` | `local.next-a.jiwoong.yaml`, `local.next-a.jueon.yaml` |
| B팀 | hyunseok, howon | `next-b` | `local.next-b.hyunseok.yaml`, `local.next-b.howon.yaml` |

A팀과 B팀은 같은 대회 이름을 써도 됩니다. 단, `team_id`, 설정 파일, output, `sync/<team_id>`가 달라야 합니다. A팀 JSONL이 B팀 폴더에 들어가지 않도록 공유 폴더 권한과 동기화 대상을 확인하세요.

다음 대회 뒤 4명으로 돌아갈 때는 A/B 설정의 `team_id`를 수정하지 않습니다. 새 대회용 설정을 `sca-jiwoong-team`으로 다시 만들면 A/B 대회의 DB와 기록을 손상하지 않고 4명 운영을 재개할 수 있습니다.

## clone한 PC마다 최초 1회 세팅

아래 명령은 A팀 `jiwoong` 예시입니다.

| 명령 | 한 줄 설명 |
| --- | --- |
| `git clone https://github.com/whatevertakes/CTF-OS.git` | Git에는 코드와 예시만 있으므로 각 PC에서 clone합니다. |
| `cd CTF-OS` | 모든 예시 명령은 저장소 루트에서 실행합니다. |
| `uv sync --frozen` | `uv.lock`에 고정된 의존성을 설치합니다. |
| `uv run ctf-os init "Next CTF 2026" --config local.next-a.jiwoong.yaml --team-id next-a --member jiwoong` | 팀과 PC가 분리된 로컬 노드를 새로 만듭니다. |

설정 파일 이름은 항상 `local.<team>.<member>.yaml` 규칙을 사용합니다. 이 패턴은 Git에서 제외되어 clone 간 로컬 설정이 섞이는 실수를 막습니다. `init`이 만드는 기본 output은 `output/next-a/jiwoong`입니다. 실제 DB는 대회 하위의 `output/next-a/jiwoong/Next CTF 2026/local_state.db`에 생깁니다. output 앞부분은 절대 경로나 다른 로컬 폴더여도 되지만, 끝은 반드시 `next-a/jiwoong`이어야 합니다.

같은 저장소에서 다른 팀/노드도 시험하려면 기존 설정을 재사용하지 말고 다른 `--config`, `--team-id`, `--member` 조합으로 다시 `init`하세요. 이미 존재하는 설정과 다른 팀 또는 member를 `--force`로 바꾸는 것도 거부됩니다.

## 사람이 편집할 설정

초기화 직후 설정 파일에서 아래만 검토합니다.

```yaml
contest:
  name: "Next CTF 2026"       # 폴더와 contest.md의 대회명도 정확히 같게
  team_id: "next-a"           # 같은 참가 팀끼리 같게
  flag_patterns:
    - "FLAG\\{[^}]+\\}"

member:
  name: "jiwoong"             # PC마다 고유하게
  display_name: "jiwoong"
  owned_categories:            # 이 PC가 실제 맡은 분야만
    - pwn
    - web

paths:
  incoming: "incoming"        # 입력은 PC 로컬
  output: "output/next-a/jiwoong"  # 끝은 team_id/member, 공유 폴더로 지정하지 않음

model_routing:
  enabled: true                # 생성된 routing 파일을 검토한 뒤 실제 실행 때 활성화
  config_path: "config/model-routing.yaml"

sync:
  enabled: true
  type: "file"
  root: "sync"                # 또는 팀이 합의한 공유 폴더의 절대 경로
```

`paths.sync`를 별도로 적으면 `sync.root`보다 우선합니다. 혼동을 막으려면 생성된 설정처럼 `sync.root` 한 곳만 사용하세요.

신규 설정은 `contest.team_id`를 TeamSync 팀 폴더의 단일 기준으로 사용합니다. 기존 YAML에 `sync.team_namespace`가 남아 있으면 하위 호환 검증을 위해 `contest.team_id`와 같은 값이어야 하지만, 새 설정에 추가할 필요는 없습니다.

모델 라우팅은 사람이 매 실행마다 모델을 고르는 방식이 아닙니다. 검토한 `config/model-routing.yaml`을 사용해 Sol은 감독·전략·최종 검증, Terra는 구현과 일반 풀이, Luna는 정찰·요약·가벼운 병렬 시도를 담당하게 합니다.

TeamSync가 PC 사이에서 보이려면 각 PC의 `sync.root`가 같은 파일 동기화/공유 폴더를 가리켜야 합니다. 기본값 `sync`는 현재 clone 내부의 로컬 폴더이므로 Git pull만으로 다른 PC와 동기화되지 않습니다. 각 노드는 `sync/<team_id>/<member>.events.jsonl` 중 자기 member 파일에만 추가하고, 팀원 파일은 읽기만 합니다.

## contest.md 준비

`incoming/`은 Git에서 제외됩니다. 한 사람이 기준 `contest.md`를 만든 뒤 같은 팀에 별도로 전달하고, 모든 PC에서 대회 이름과 문제의 `category/name` 철자를 같게 유지하세요.

```markdown
# 대회명: Next CTF 2026

## 대회 정보
- 팀: next-a
- 플래그 형식: FLAG{...}

## 문제 목록

### web/login
- 점수: 100
- 원격: nc challenge.example 31337
- 설명: 승인된 대회 문제
```

문제 제목은 반드시 `### category/name` 형식입니다. 원격 주소는 승인된 대회 대상만 적습니다. 현재 sandbox 네트워크 정책에서 실제 컨테이너 연결용 원격 선언은 정확한 `nc HOST PORT` 한 개만 허용됩니다.

## 세팅 완료 명령

| 명령 | 한 줄 설명 |
| --- | --- |
| `scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml` | 의존성 설치, 지정 DB 마이그레이션, Docker 이미지 준비와 smoke test를 수행합니다. |
| `uv run ctf-os doctor --config local.next-a.jiwoong.yaml --non-mock` | 실제 Codex·Docker 실행 조건과 로컬 경로를 검사합니다. |

배포 스크립트는 여러 번 실행해도 됩니다. `ctf-os run`은 이미지를 자동으로 빌드하지 않습니다. 따라서 최초 풀이 전 배포가 성공해야 합니다.

Dockerfile이 바뀌어 이미지를 의도적으로 다시 만들 때만 다음 명령을 사용합니다.

| 명령 | 한 줄 설명 |
| --- | --- |
| `scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml --rebuild-image` | 기존 태그의 sandbox 이미지를 새로 빌드하고 검증합니다. |
| `scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml --skip-image` | Docker 없이 설치와 DB 마이그레이션만 합니다. 실제 대회 준비 완료 상태는 아닙니다. |

## 실제 대회 직전 명령

각 명령이 성공한 뒤 다음 줄로 넘어갑니다.

| 명령 | 한 줄 설명 |
| --- | --- |
| `git status --short` | 뜻밖의 소스 수정이 없는지 확인합니다. 로컬 설정은 Git에 올리지 않습니다. |
| `git pull --ff-only origin main` | 팀원이 동일한 최신 코드로 맞춥니다. |
| `scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml` | 코드에 맞춰 환경·DB·이미지를 다시 준비합니다. |
| `uv run ctf-os doctor --config local.next-a.jiwoong.yaml --non-mock` | 실제 풀이 필수 조건을 최종 확인합니다. |
| `uv run ctf-os parse --config local.next-a.jiwoong.yaml` | 담당 카테고리 문제만 로컬 DB에 안전하게 반영합니다. |
| `uv run ctf-os tui --plain --team --config local.next-a.jiwoong.yaml` | 대회명, member, team ID와 팀 상태를 화면에서 확인합니다. |

`parse` 결과의 문제 수가 예상과 다르면 `member.owned_categories`와 `contest.md`의 category 철자를 먼저 확인하세요.

## 대회 중 명령

| 명령 | 한 줄 설명 |
| --- | --- |
| `uv run ctf-os run --config local.next-a.jiwoong.yaml` | 이 PC 큐를 계속 처리합니다. |
| `uv run ctf-os run --once --config local.next-a.jiwoong.yaml` | 한 번만 처리하고 종료해 설정을 점검할 때 사용합니다. |
| `uv run ctf-os tui --team --config local.next-a.jiwoong.yaml` | 로컬 DB와 같은 `team_id`의 TeamSync 상태를 봅니다. |
| `uv run ctf-os tui --readonly --team --config local.next-a.jiwoong.yaml` | worker를 건드리지 않고 상태 파일 변경만 계속 읽습니다. |
| `uv run ctf-os sync merge --config local.next-a.jiwoong.yaml` | 같은 팀 JSONL 이벤트를 정렬·중복 제거해 출력합니다. |
| `uv run ctf-os sync watch --config local.next-a.jiwoong.yaml` | 같은 팀 JSONL 변경을 읽기 전용으로 감시합니다. |
| `uv run ctf-os pause <문제명> --config local.next-a.jiwoong.yaml` | 현재 PC에서 문제 하나를 정지합니다. |
| `uv run ctf-os resume <문제명> --config local.next-a.jiwoong.yaml` | 정지한 문제를 현재 PC 큐에 다시 넣습니다. |
| `uv run ctf-os retry <문제명> --config local.next-a.jiwoong.yaml` | 실패한 문제를 현재 PC에서 다시 시도합니다. |
| `uv run ctf-os sandbox cleanup --config local.next-a.jiwoong.yaml` | 현재 team/member/contest 라벨의 컨테이너만 정리합니다. |

TeamSync는 명령 채널이 아닙니다. 다른 팀원의 worker를 pause/resume하거나 원격 실행하지 않으며, 플래그도 자동 제출하지 않습니다.

## clone 후 팀 맞춤 체크리스트

- [ ] 네 PC 모두 같은 `main` 커밋을 사용한다.
- [ ] 같은 참가 팀끼리 대회 이름과 `team_id` 철자가 완전히 같다.
- [ ] 같은 팀의 `contest.team_id`가 같고, 기존 `sync.team_namespace`가 있다면 그 값도 같다.
- [ ] 네 PC의 `member.name`이 서로 겹치지 않는다.
- [ ] 설정 파일 이름이 `local.<team>.<member>.yaml`이고 Git 추적 대상이 아니다.
- [ ] `paths.output`이 `output/<team_id>/<member>`이고 공유 폴더가 아니다.
- [ ] 기존 DB의 `team_id + member.name + contest.name`이 현재 설정과 모두 같다.
- [ ] 서로의 `output/` 또는 `local_state.db`를 복사하지 않았다.
- [ ] TeamSync를 공유한다면 `sync.root`만 같은 공유 위치를 가리킨다.
- [ ] A팀과 B팀의 `team_id` 및 `sync/<team_id>`가 다르다.
- [ ] `contest.md`의 대회명과 설정의 `contest.name`이 정확히 같다.
- [ ] 담당 category가 겹치는 것이 의도인지 확인했다.
- [ ] 각 PC에서 배포, `doctor --non-mock`, `parse`가 성공했다.
- [ ] `tui --plain --team` 제목의 대회명·member·team ID를 사람이 확인했다.

## DB ID 오류가 날 때

대표 오류는 기존 `local_state.db`의 `team_id`, `member.name` 또는 `contest.name`을 설정에서 바꾼 뒤 같은 DB 경로를 열 때 발생합니다. DB가 아직 없어도 `paths.output`이 `<team_id>/<member>`로 끝나지 않으면 설정 로드 단계에서 먼저 거부됩니다.

1. 실행을 멈추고 오류에 표시된 DB 경로를 기록합니다.
2. 사용한 `--config` 파일이 현재 참가 팀용인지 확인합니다.
3. `contest.team_id`가 현재 팀 값인지 확인하고, 기존 `sync.team_namespace`가 남아 있다면 같은지 확인합니다.
4. `contest.name`, `member.name`과 `paths.output`이 현재 노드용인지 확인합니다.
5. 팀을 옮긴 상황이면 기존 YAML을 수정하지 말고 새 이름의 설정을 `init`으로 만듭니다.
6. 새 설정이 새 `output/<team_id>/<member>`를 가리키는지 확인한 뒤 배포와 doctor를 다시 실행합니다.

기존 DB를 삭제·이름 변경·직접 편집하는 것은 자동 복구 절차가 아닙니다. 기록 보존 또는 정리가 필요하면 먼저 별도 백업 정책을 정하고 진행하세요.

예전 설정의 `paths.output`이 단순 `output`이라 새 suffix 검증에서 거부되는 경우도 같습니다. 기존 설정과 DB를 삭제·이동·편집하지 말고 보존한 뒤, 현재 대회 이름으로 다음과 같이 새 로컬 설정을 만드세요. 기존 `contest.md`가 있으면 `init`은 새 설정에서 그대로 재사용합니다.

```bash
uv run ctf-os init "Next CTF 2026" --config local.next-a.jiwoong.yaml --team-id next-a --member jiwoong
```

## 업데이트 원칙

```bash
git pull --ff-only origin main
scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml
uv run ctf-os doctor --config local.next-a.jiwoong.yaml --non-mock
```

Git으로 공유하는 것은 코드뿐입니다. 설정 YAML, `incoming/`, `output/`, `sync/`, SQLite, 로그, 자격 증명, 키, 실제 플래그는 커밋하지 않습니다. 배포 스크립트도 이 로컬 데이터를 삭제하거나 다른 PC로 전송하지 않습니다.
