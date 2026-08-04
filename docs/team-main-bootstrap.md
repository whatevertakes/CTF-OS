# Team bootstrap from `main`

이 절차는 새 x86-64 Linux/WSL2 장비에서 GitHub `main`의 tracked source와 기본
CTF-OS engine 설정을 재현합니다. Git은 challenge 입력, canonical state,
benchmark 결과, 모델 계정, 로컬 Docker image를 복제하지 않습니다.

## 1. Source와 Python 환경

```sh
git clone https://github.com/whatevertakes/CTF-OS.git
cd CTF-OS
git switch main
git pull --ff-only
uv sync --frozen
CTFOS_PYTHON=.venv/bin/python scripts/check-fresh-clone.sh
uv tool install --editable .
ctfos --help
```

지원 interpreter는 Python 3.13 이상입니다. interpreter와 `uv` 실행 파일
자체의 exact version은 `main`이 고정하지 않습니다. `uv sync --frozen`은
tracked `uv.lock`을 바꾸지 않고 개발·테스트 환경을 만듭니다. Codex CLI
로그인과 provider quota는 각 팀원의 호스트에서 별도로 준비하며 credentials를
이 저장소, prompt, `.ctfos/` run log에 복사하지 않습니다.

## 2. Managed image와 기본 설정

```sh
DOCKER_BUILDKIT=1 docker build -t ctf-os:core ./ctf-os-image
ctfos init
ctfos pin-image
ctfos doctor
```

`ctfos init`은 ignored `.ctfos/engine.toml`을 생성합니다. 기본값은 모든
논리 역할에 `gpt-5.6-sol`, Captain `ultra`, workers `max`를 사용하며 provider
동시성은 역할 또는 wave 폭과 독립적입니다. `pin-image` 뒤에는 tag가 아니라
그 호스트의 exact image ID가 실행 기준입니다.

Dockerfile의 일부 upstream package source는 floating하므로 서로 다른 시점에
각자 build한 image byte가 같다는 보장은 없습니다. exact image 동일성이
필요하면 운영자가 별도로 배포한 동일 OCI image ID를 load한 다음
`ctfos pin-image`를 실행해야 합니다. GitHub `main`만으로 보장하는 범위는
tracked source, lockfile, engine default와 검증 절차입니다.

## 3. 현재 checkout 수용성 검증

clean `HEAD`에서 실행합니다.

```sh
CTFOS_RELEASE_IMAGE_ID="$(docker image inspect --format '{{.Id}}' ctf-os:core)"
uv run python scripts/check-release-acceptance.py \
  --image-digest "$CTFOS_RELEASE_IMAGE_ID"
ctfos contest-check --json
```

acceptance가 출력한 local unsigned receipt의 `ok`가 `true`이고 HEAD, source
snapshot, image ID, pin과 runtime binding이 모두 현재 값과 일치해야 engine
release가 검증된 것입니다. 과거 receipt나 README의 역사적 test count는 현재
checkout의 승인을 대신하지 않습니다.

## 4. Challenge와 benchmark의 로컬 경계

다음 경로는 의도적으로 Git에서 제외됩니다.

- `incoming/`: 운영자가 직접 받은 untrusted challenge input
- `.ctfos/`: `state.json`, run artifact, handoff, receipt와 benchmark state
- `benchmarks/`, `benchmark-results/`: 실수로 root에 만든 bulk checkout/result

따라서 팀원은 공개 handout과 허용된 endpoint를 별도로 받아 challenge를
사람이 하나씩 등록해야 합니다. 다른 사람의 `.ctfos/state.json`이나 benchmark
결과를 복사하는 것은 source 재현 절차가 아닙니다. handoff를 내보낼 때도
root의 자유형 filename 대신 `.ctfos/handoffs/<name>.json`을 사용합니다.

NYU staging manifest와 다른 local benchmark receipt는
`.ctfos/benchmarks/<suite>/` 아래에 둡니다. raw dataset, private reference,
candidate value와 결과 bundle은 commit하지 않습니다.

## 5. CTFTiny operator-only hash verification

private reference는 반드시 아래 ignored root의 regular file이며 owner-only
mode여야 합니다.

```sh
chmod 0600 \
  .ctfos/benchmarks/external-pilots/private/ctftiny/TASK/verifier-reference.json
uv run ctfos --root "$PWD" benchmark ctftiny-verify \
  CONTEST CATEGORY CHALLENGE \
  --candidate-id C-CANDIDATE_ID \
  --reference \
  .ctfos/benchmarks/external-pilots/private/ctftiny/TASK/verifier-reference.json
```

이 `ctfos` 명령은 canonical candidate ID만 받고 candidate value와 expected
hash를 출력하지 않으며 state를 수정하거나 제출하지 않습니다. 기존
`scripts/ctftiny-operator-verify.py`는 호환 entrypoint로만 유지합니다. 종료
코드는 match `0`, mismatch `1`, invalid/error `2`입니다.
