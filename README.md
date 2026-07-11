# CTF-OS

CTF-OS는 각 PC에서 완전히 독립적으로 실행하는 로컬 CTF 풀이 도구입니다. 상태·발견 사항·플래그 이벤트는 해당 노드의 SQLite에만 저장하며 팀 공유 파일을 만들지 않습니다. 다른 PC의 프로세스를 실행하지 않으며 CTFd에 플래그를 자동 제출하지 않습니다.

승인된 대회와 원격 대상만 `incoming/<대회 이름>/contest.md`에 적어 사용하세요.

홈 캐시가 읽기 전용인 환경에서 `uv` 권한 오류가 나면, 현재 터미널에서
`export UV_CACHE_DIR="${TMPDIR:-/tmp}/ctf-os-uv-cache-$UID"`를 한 번 실행하세요.
`scripts/deploy_ctf_os.sh`는 이 안전한 기본값을 자동 적용합니다.

## 가장 중요한 규칙

한 로컬 DB는 처음 사용한 `team_id + member.name + contest.name` 조합에 묶입니다. 기존 DB를 둔 채 이 셋 중 하나만 바꾸면 오류가 나는 것이 정상입니다.

- 같은 팀: 운영상 합의한 `contest.team_id`를 사용할 수 있지만 실행과 상태는 PC별로 독립적입니다.
- 다른 팀: `contest.team_id`가 반드시 달라야 합니다.
- 각 PC: `member.name`은 겹치지 않게 정하고 `paths.output`은 반드시 `<team_id>/<member>`로 끝나게 분리합니다. 맞지 않으면 새 DB를 만들기 전 설정 단계에서 거부됩니다.
- 공유 금지: `output/`, `local_state.db`, Codex 로그인, Docker 컨테이너, 자격 증명과 플래그 파일은 PC 사이에 복사하지 않습니다.
- 팀을 옮길 때: 기존 설정을 수정하지 말고 새 설정 파일과 새 output 경로를 만듭니다.

## 1. 사람이 먼저 정할 값

대회마다 아래 값을 팀 채널에 먼저 확정한 뒤 모든 PC에서 그대로 사용합니다.

| 값 | 누가 같아야 하나 | 예시 |
| --- | --- | --- |
| 대회 이름 | 같은 대회 참가자 전원 | `Next CTF 2026` |
| `team_id` | 같은 참가 팀 2명 또는 4명 | `next-a` |
| `member` | PC마다 고유 | `jiwoong` |
| 설정 파일 | PC/팀 조합마다 별도 | `local.next-a.jiwoong.yaml` |
| output | PC/팀 조합마다 별도 | `output/next-a/jiwoong` |

`team_id`, `member`, 대회 이름에는 `/`, `\`를 쓰지 말고 값 전체를 `.` 또는 `..`로 정하지 마세요.

## 2. 최초 1회 세팅

아래 예시는 다음 대회의 A팀에 참가하는 `jiwoong` PC입니다. 따옴표 안의 대회 이름과 세 식별자는 실제 값으로 바꾸세요.

| 명령 | 설명 |
| --- | --- |
| `git clone https://github.com/whatevertakes/CTF-OS.git` | 코드를 처음 한 번 받습니다. |
| `cd CTF-OS` | 저장소로 이동합니다. |
| `uv sync --frozen` | 잠긴 버전 그대로 실행 환경을 설치합니다. |
| `uv run ctf-os init "Next CTF 2026" --config local.next-a.jiwoong.yaml --team-id next-a --member jiwoong` | 이 PC 전용 설정·입력 폴더·output 경로를 만듭니다. |

그다음 `local.next-a.jiwoong.yaml`에서 사람이 편집할 항목은 다음과 같습니다. `local.<team>.<member>.yaml` 이름은 로컬 설정임을 분명히 하며 Git에서 제외됩니다.

- `member.owned_categories`: 이 PC가 맡을 카테고리
- `contest.flag_patterns`: 실제 대회의 플래그 형식
- `model_routing.enabled`: 실제 Codex 실행은 라우팅 파일을 검토한 뒤 `true`
- `paths.output`: 자동 생성된 `output/next-a/jiwoong`처럼 마지막 두 폴더가 `team_id/member`인지 확인

신규 설정에서는 `contest.team_id`만 정하면 됩니다. 기존 YAML의 `sync` 항목은 무시되며 제거해도 됩니다. 초기화 뒤에는 기존 설정의 `contest.team_id`, `member.name`, `contest.name`을 다른 노드 값으로 바꾸지 마세요.

모델은 라우팅 파일에 따라 자동 선택합니다. Sol은 감독·전략·최종 검증, Terra는 구현과 일반 풀이, Luna는 정찰·요약·가벼운 병렬 시도를 맡는 것이 기본 운영 원칙입니다.

팀에서 받은 동일한 `contest.md`를 `incoming/Next CTF 2026/contest.md`에 놓고, 문제를 `### category/name` 형식으로 작성합니다. `incoming/`은 Git으로 배포되지 않으므로 팀끼리 별도로 전달해야 합니다.

| 명령 | 설명 |
| --- | --- |
| `scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml` | DB 마이그레이션, sandbox 이미지 준비와 smoke test를 한 번에 수행합니다. |
| `uv run ctf-os doctor --config local.next-a.jiwoong.yaml --non-mock` | Codex·Docker·이미지·broker와 경로가 실제 풀이 가능한지 검사합니다. |

## 3. 실제 대회 직전

| 명령 | 설명 |
| --- | --- |
| `git pull --ff-only origin main` | 최신 코드를 안전하게 받습니다. |
| `scripts/deploy_ctf_os.sh --config local.next-a.jiwoong.yaml` | 의존성·DB·Docker 이미지를 다시 검증합니다. |
| `uv run ctf-os doctor --config local.next-a.jiwoong.yaml --non-mock` | 실제 실행 전 필수 조건을 최종 확인합니다. |
| `uv run ctf-os parse --config local.next-a.jiwoong.yaml` | `contest.md`에서 이 PC 담당 카테고리만 로컬 DB에 넣습니다. |
| `uv run ctf-os tui --plain --config local.next-a.jiwoong.yaml` | 이 노드의 로컬 SQLite 상태를 한 번 출력합니다. |

어느 명령에서든 DB의 노드 정체성이 다르다는 오류가 나오면 DB를 덮어쓰지 마세요. 설정 파일의 `team_id`, `member`, 대회 이름과 output 경로를 확인하고 현재 노드용 새 설정으로 다시 초기화합니다. 자세한 복구 절차는 [팀 배포 가이드](docs/CTF_OS_TEAM_DEPLOYMENT.md)를 참고하세요.

예전 설정의 `paths.output`이 단순히 `output`이라면 새 경로 검증에서 거부될 수 있습니다. 기존 YAML과 DB는 그대로 보존하고, 현재 대회에 `init --config local.<team>.<member>.yaml`을 실행해 새 노드를 만드세요.

## 4. 대회 중

| 명령 | 설명 |
| --- | --- |
| `uv run ctf-os run --config local.next-a.jiwoong.yaml` | 이 PC 담당 문제를 계속 처리합니다. |
| `uv run ctf-os run --once --config local.next-a.jiwoong.yaml` | 현재 큐를 한 번만 처리하고 종료합니다. |
| `uv run ctf-os tui --config local.next-a.jiwoong.yaml` | 이 노드의 로컬 진행 상태를 대시보드로 봅니다. |
| `uv run ctf-os pause <문제명> --config local.next-a.jiwoong.yaml` | 이 PC의 문제 하나를 일시 정지합니다. |
| `uv run ctf-os resume <문제명> --config local.next-a.jiwoong.yaml` | 정지한 문제를 이 PC 큐에 다시 넣습니다. |
| `uv run ctf-os retry <문제명> --config local.next-a.jiwoong.yaml` | 실패한 문제를 명시적으로 다시 시도합니다. |

플래그 후보는 사람이 검증하고 직접 제출해야 합니다.

## 4명 기본 운영과 다음 대회 2+2 운영

### KISIA four-member example · 평소 4인 팀

평소에는 네 명이 `team_id: sca-jiwoong-team`을 공유하고, `member.name`과 담당 카테고리만 각자 다르게 둡니다.

| member | 담당 예시 |
| --- | --- |
| `jiwoong` | pwn, web |
| `jueon` | rev, crypto |
| `hyunseok` | forensics, misc |
| `howon` | cloud, web3 |

다음 대회만 두 팀으로 나뉜다면 A팀 2명은 `next-a`, B팀 2명은 `next-b`를 사용합니다. 각 PC는 설정 파일과 output을 분리합니다. 대회가 끝난 뒤 4명 운영으로 돌아갈 때는 기존 A/B 설정을 고치지 말고, 다음 대회용 `sca-jiwoong-team` 설정 파일을 새로 만드세요. 각 대회의 SQLite 기록은 그대로 보존됩니다.

더 자세한 clone 점검표, 설정 예시와 오류 복구는 [CTF-OS 팀 배포 가이드](docs/CTF_OS_TEAM_DEPLOYMENT.md)에 있습니다.
