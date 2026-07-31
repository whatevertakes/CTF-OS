# Contest start runbook

이 runbook은 일반 공개·비인증 userspace CTF의 대회 시작 직전 절차다. CTF-OS는
문제를 자동 선택하거나 자동 전환하지 않는다. 사람이 열기로 결정한 challenge만
아래 절차로 시작한다.

## 1. 릴리스 고정

tracked 변경을 모두 의도적으로 commit한 뒤 clean tree에서 image를 빌드하고
exact local ID를 pin한다.

```sh
git status --short
test -f .ctfos/engine.toml || ctfos init
DOCKER_BUILDKIT=1 docker build -t ctf-os:core ./ctf-os-image
CTFOS_RELEASE_IMAGE_ID="$(
  docker image inspect --format '{{.Id}}' ctf-os:core
)"
ctfos pin-image
ctfos doctor
uv run python scripts/check-release-acceptance.py \
  --image-digest "$CTFOS_RELEASE_IMAGE_ID"
```

바로 앞 acceptance 명령이 출력한 exact receipt path/hash를 보존하고 그 local
unsigned receipt가 현재 HEAD/pin/image/runtime과 일치하며 `ok: true`가 아니면
시작을 중단한다. 랜덤 `run-*` 이름으로 최신을 추정하지 않는다. 개별 gate의
PASS, 과거 report 또는 tag 이름은 이를 대신하지 않는다.

## 2. 대회 전 canonical-state 비변경 점검

```sh
ctfos contest-check --json
# 특정 대회만 볼 때
ctfos contest-check CONTEST --json
```

`contest-check`는 canonical challenge state를 변경하거나 challenge tool/remote를
실행하지 않지만, local host 진단과 network-none exact-image capability container를
실행한다. doctor failure, stale schema, 비어 있는 prompt, unarmed budget, active owner,
STALLED state, remote work의 target 결속 실패, 기록상 active background job은
자동 수정하지 않는다. 출력된 operator command를 사람이 검토해 실행한다.

## 3. 사람이 challenge를 연다

`incoming/` 아래 파일은 engine이 수정하지 않는 비신뢰 입력이다.

```sh
ctfos add-challenge CONTEST CATEGORY CHALLENGE \
  --prompt-file /trusted/operator/problem-prompt.txt \
  --budget-seconds 28800
```

원격 target이 없는 문제는 network deny를 유지한다. 원격 target이 있을 때만
사람이 endpoint를 등록하고 선택한다. `target check`는 lifecycle state를
기록하고, `target smoke`는 실제 원격 요청을 수행하므로 명시적으로 실행한다.

```sh
ctfos target add CONTEST CATEGORY CHALLENGE \
  https://challenge.example:443 --enforcement builtin
ctfos target select CONTEST CATEGORY CHALLENGE TARGET_ID
ctfos target check CONTEST CATEGORY CHALLENGE TARGET_ID
ctfos target smoke CONTEST CATEGORY CHALLENGE TARGET_ID \
  --mode dns --mode tcp --mode tls
ctfos preflight CONTEST CATEGORY CHALLENGE --json
```

인증 cookie/token/private key가 필요한 문제에는 raw secret을 prompt, state,
command argument 또는 run log에 넣지 않는다. typed secret channel이 구현되기
전에는 해당 문제를 기본 GO 범위로 취급하지 않는다.

## 4. 운영과 복구

```sh
ctfos status CONTEST
ctfos diagnose CONTEST CATEGORY CHALLENGE --json
ctfos jobs CONTEST CATEGORY CHALLENGE
ctfos jobs CONTEST CATEGORY CHALLENGE --recover
```

`diagnose`는 existing private store의 canonical snapshot만 읽고,
`contest-check`도 canonical state는 변경하지 않는다. `jobs --recover`, target
lifecycle, pause/resume, budget reset은 canonical state를 바꿀 수 있으므로 사람이
원인과 대상을 확인한 뒤 실행한다. long-running tool은 foreground 우회 대신
trusted background supervisor의 `ctfos tool start ...`를 쓰고 다음 정확한 형태로
조회·복구한다.

```sh
ctfos jobs CONTEST CATEGORY CHALLENGE
ctfos jobs CONTEST CATEGORY CHALLENGE --recover
ctfos jobs CONTEST CATEGORY CHALLENGE \
  --job-id JOB_ID --supervisor-id SUPERVISOR_ID --log
ctfos jobs CONTEST CATEGORY CHALLENGE \
  --job-id JOB_ID --supervisor-id SUPERVISOR_ID --cancel
```

오류가 나면 raw output을 prompt에 복사하지 말고 bounded artifact pointer와
failure capsule을 사용한다. source/image/pin drift가 보이면 해당 challenge만
재시도하지 말고 릴리스 고정 단계부터 다시 수행한다.

## 5. 제출과 범위 중단 기준

flag-looking 문자열은 즉시 운영자에게 표시하지만 후보일 뿐이다. 자동 제출하지
않고 proof 결과와 사람이 수행한 제출 outcome만 기록한다.

다음 문제는 기본 Docker release GO 밖이므로 별도 경계를 준비하기 전 시작하지
않는다.

- kernel, container escape 또는 악성 handout: 별도 VM/격리 host
- raw credential이 필요한 인증 target: typed secret channel
- DNS rebinding/SSRF가 핵심인 target: connection IP 결속과 private-range 차단
- AI/ML 정식 분야: dataset/checkpoint/seed/metric/GPU receipt contract
- 수십~수백 GiB DFIR: 실제 크기의 storage/time rehearsal

대회 후에는 solve 수만 기록하지 말고 동일 모델·effort·image·input·budget의
thin scaffold 3회와 CTF-OS 3회 blind/live cohort로 성능 주장을 별도 판정한다.
