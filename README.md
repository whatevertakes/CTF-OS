# CTF-OS

CTF-OS는 사람이 고른 문제 하나를 Live 또는 Batch 모드로 푸는
challenge-scoped Codex 엔진입니다. 대회 문제를 자동으로 고르는 스케줄러와
CTF 사이트 자동 제출 기능은 없습니다.

사람이 담당하는 일은 명확합니다.

1. 문제 폴더를 만든다.
2. 문제 파일을 직접 다운로드해 넣는다.
3. 문제 설명과 공개된 challenge endpoint를 풀이 프롬프트로 제공한다.
4. 터미널에 표시된 후보 플래그를 CTF 사이트에 직접 제출한다.
5. accepted/rejected 결과를 CTF-OS에 기록한다.

풀이 프롬프트에는 API key, CTFd 계정/세션, 비밀번호, 개인 token 같은
자격증명을 넣지 마십시오. 프롬프트와 상태·run 기록은 모델 context와 감사
자료에 포함됩니다. 인증이 필요한 원격 흐름은 model/log 비노출 typed secret
channel이 생기기 전까지 지원 범위가 아닙니다.

현재 코드가 실제로 구현한 범위와 남은 제한은
[구현 결과](ctf-reports/10-implementation-result.md), 요구사항별 판정 이력은
[수용성 기록](ctf-reports/12-final-acceptance.md)에 정리돼 있습니다.
명시적으로 고른 NYU CTF Bench 전-category cohort를 실행 없이 준비하는 절차는
[NYU CTF Bench operator staging](docs/nyu-ctf-bench-stage.md)에 있습니다.

## 현재 검증 상태

2026-07-28의 source freeze, image digest와 test 수치는 역사적 수용
기록입니다. 이후 managed hot path와 카테고리 게이트가 크게 바뀌었으므로
그 동결을 현재 source의 release 승인으로 사용하지 않습니다. `ad6ae43`
source에서는 exact image
`sha256:f39d2216ddaa93fae3134014b25be0609096bacd8648b1621121787db6196338`
로 7개 gate와 6개 category가 통과한 interim matrix receipt가 있습니다.
하지만 그 뒤 Crypto physical-run, Web network/log/impact, Rev/Misc/Pwn
physical provenance, Pwn interaction transport, Forensic 독립 실행기와
`d2fb1130b147605ca5d829ff7d20946fb2f3e41f`의 blind promotion
operator-input binding이 모두 강화됐습니다. 해당 promotion focused suite는
74/74를 110.727초에 통과했지만 실제 blind/live cohort는 아직 실행하지
않았습니다. 이 변경을 모두 포함한 최종 전체 회귀, clean exact-image
all-category matrix와 `ctfos doctor`를 새로 통과하기 전까지 현재 source는
**release candidate**이며, interim receipt를 현재 release 승인으로
사용하지 않습니다.

현재 구현된 결정론적 권위와 범위는 다음과 같습니다.

| 카테고리 | 현재 engine-owned 실행 게이트 | 정확한 경계 |
|---|---|---|
| Pwn | ELF 관측, D→V crash, runtime snapshot, address dependency의 L/N/A 판정, IP-control primitive, one-shot 3+3 exploit-effect와 data-only dynamic interaction 3+3 | `1c82147`은 dependency/effect의 physical sidecar·artifact·transport receipt를 다시 읽고 3회 cohort 재사용을 차단했다. 69개 Pwn 회귀, pinned 단일 16/16과 3회 48/48 clean proof, tamper control 3/3, network `none`을 통과했다. `c9eee37` interaction release proof도 23개 회귀와 6개 physical record를 통과했다. 실제 `zone` interaction은 flag, solve, remote portability나 자율 발견 증거는 아니다. |
| Web | 역할별 session/state, runtime request timeline, differential impact, race 3+3, OOB 3+3 | `dd929f0`은 concurrent target event stream을 strict bounded JSON으로 처리하고, `cf155cc`는 canonical state에서 impact sidecar·artifact·receipt를 다시 읽어 hostile rewrite/deletion을 거부한다. active Docker gate는 생성한 network의 `Internal:true`도 확인한다. 실제 대회 proxy·remote portability는 별도다. |
| Rev | assembly/dynamic evidence와 원본 바이너리 positive 3 / mutated control 3 | `3726adb`는 failed result/validation sidecar와 artifact deletion을 physical release evidence로 재검증해 거부한다. 범위는 network-none local standalone Linux ELF의 stdin oracle이다. |
| Crypto | managed Builder의 solver를 operator-preissued hidden variant로 Python/Sage 각각 3+3 검증 | hidden input은 challenge/model workspace 밖 engine-private authority다. `2610c52`부터 persisted physical Run 여섯 개를 재검증하고 `d550df15`는 request/result/validation과 stdout/stderr sidecar provenance까지 결속한다. actual pinned Docker에서 Python/Sage 각각 6/6을 통과하고 hostile sidecar·stdout 교체를 거부했다. 최종 clean matrix receipt는 대기 중이다. |
| Forensics | immutable index, pointer/hash 결속, readiness와 cross-tool assertion graph | `7c3d604`는 physical sidecar·artifact를 재검증하고 Python/pread와 Perl/sysread의 서로 다른 executable hash를 요구한다. focused 91개와 pinned Docker 7개가 37.961초에 통과했고 sidecar/artifact 및 duplicate-version 공격을 거부했다. `5e88071`은 이 계약을 matrix schema에도 고정했다. 지원 tool/profile과 evidence coverage 밖의 결론은 승격하지 않는다. |
| Misc | modality intake, hash-bound transform DAG, negative control과 3회 replay | `c690af0`은 failed physical run과 artifact deletion을 재검증해 거부한다. candidate-only이며 verifier 통과가 자동 제출 권한을 만들지 않는다. |

이 표는 코드와 local deterministic gate의 구현 범위입니다. 같은 모델·도구의
thin scaffold 대비 3회 중 2회 재현, blind/live solve@1, 카테고리 최저 성능과
CVE 발견 성능을 측정했다는 뜻이 아닙니다. CTF 성능과
ExploitGym/CyberGym-E2E/CVE 연구 축은 서로 분리해 평가합니다.

## 요구 환경

- Linux 또는 WSL2
- Python 3.13
- `uv`
- Docker daemon
- Codex CLI
- `ctf-os:core` Docker 이미지

프로젝트 CLI를 설치합니다.

```sh
uv tool install --editable .
ctfos --help
```

저장소 안에서만 실행할 때는 `uv run ctfos ...` 또는
`uv run python -m ctf_os ...`를 써도 됩니다.

도구 이미지는 대회 전에 빌드합니다. 대회 중 hot path에서 다시 빌드하는
운용은 권장하지 않습니다.

```sh
DOCKER_BUILDKIT=1 docker build -t ctf-os:core ./ctf-os-image
```

GPU를 쓸 호스트에서 NVIDIA Container Toolkit이 아직 없다면
`scripts/setup-nvidia-container-toolkit`을 별도로 실행할 수 있습니다. 이
스크립트는 호스트 패키지와 Docker 설정을 변경하므로 내용을 확인한 뒤
실행해야 합니다.

## 최초 설정과 점검

작업공간 루트에서 설정 파일을 만듭니다.

```sh
ctfos init
```

설정은 `.ctfos/engine.toml`에 생성됩니다. 기본 model ID는 모든 논리 역할에
동일한 `gpt-5.6-sol`을 배정합니다. 역할 차이는 약한 모델 라우팅이 아니라
artifact 계약으로 유지하며 Captain은 `ultra`, worker는 `max` reasoning
effort를 사용합니다. provider 한도는 호출을 대기시킬 뿐 역할이나 wave 폭을
줄이지 않습니다. 이 기본값은 설정과 local fixture에서 검증했지만, 실제
계정으로 전체 solve end-to-end를 검증했다는 뜻은 아닙니다.

`pin-image`는 현재 `runtime.image`가 가리키는 로컬 Docker image ID를
`runtime.image_digest`에 원자적으로 기록합니다. 이후 일반 도구와 clean
proof는 같은 exact image ID를 실행합니다. 이미지를 다시 빌드했다면 대회
시작 전에 `ctfos pin-image`를 다시 실행하십시오.

`doctor`는 Codex, Docker, 이미지, GPU/KVM, CPU/RAM/디스크와 정책을
읽기 전용으로 보고합니다. 또한 exact local image ID가 현재 tag와 일치하는지,
Managed 실행에 필요한 capability와 파일 attestation이 실제 pinned image
안에 모두 있는지를 network-none/read-only probe로 확인합니다.
`doctor --calibrate`도 설정을 자동 변경하지 않고 권장값만 출력합니다.
이미지가 미고정이거나 capability가 하나라도 빠지면 `ok`는 false입니다.

Managed 실행에 쓰는 이미지는 tag가 아니라 exact local image ID로 고정합니다.
최초 `ctfos init` 뒤의 릴리스 순서는
`build → exact-ID smoke → pin → doctor → challenge preflight`입니다.
tag를 다시 빌드하는 것만으로 이미 고정된 실행 참조가 바뀌지는 않습니다.

```sh
CTFOS_RELEASE_IMAGE_ID="$(
  docker image inspect --format '{{.Id}}' ctf-os:core
)"
uv run python scripts/check-pwn-docker-crash.py \
  --image-digest "$CTFOS_RELEASE_IMAGE_ID"
uv run python scripts/check-pwn-docker-snapshot.py \
  --image-digest "$CTFOS_RELEASE_IMAGE_ID"
uv run python scripts/check-rev-docker-proof.py \
  --image-digest "$CTFOS_RELEASE_IMAGE_ID"
uv run python scripts/check-all-category-release-matrix.py \
  --image-digest "$CTFOS_RELEASE_IMAGE_ID"
ctfos pin-image
ctfos doctor
```

challenge preflight는 전역 초기화 명령이 아닙니다. 아래 절차에서 사람이
해당 challenge를 등록한 뒤 첫 managed model call 전에 실행합니다.

Batch의 논리적 worker 수와 실제 provider 호출 상한은 서로 다른 값입니다.

```toml
[resources]
worker_slots_per_challenge = 3
wave_width_discovery = 3
wave_width_attack = 3
wave_width_proof = 3
provider_max_concurrent_calls = 4
```

세 역할은 제거되거나 합쳐지지 않습니다. Batch 호출이 **설정된**
계정/provider 상한에 도달하면 `.ctfos/runtime/model-calls.json`의 FIFO
대기열에서 기다립니다. CTF-OS가 구독 플랜이나 실제 provider quota를
자동 조회하는 것은 아니므로 대회 전에 확인한 보수적 값을 설정해야 합니다.
일시적으로 상한만 바꾸려면 양의 정수 환경 변수를 사용합니다.

```sh
CTFOS_MODEL_CONCURRENCY=2 ctfos run-challenge \
  'Demo CTF' web 'Example'
```

이 전역 대기는 CTF-OS가 직접 실행하는 Batch `codex exec`에 적용됩니다.
Interactive Live Captain 내부에서 Codex가 생성하는 native subcall에는
CTF-OS가 개별 리스를 걸 수 없습니다. Live는 세 논리 역할과 최대 thread 수를
프롬프트/CLI 설정으로 유지합니다. 실제 호출은 계정/provider 한도에서
대기할 수 있지만, CTF-OS가 local FIFO로 내부 호출의 시작 시점까지 하드
강제하지는 못합니다.

Live와 Batch는 공통으로 strict tool config를 사용합니다. Host shell과
`exec_command`/`write_stdin`을 끄고, `web_search`를 disabled로 고정하며,
apps, plugins, tool suggestion, browser/computer use, image generation과
user MCP를 비활성화합니다. Filesystem/network API가 없는 built-in V8
`exec`는 Live production surface에 남으며 host shell과 같은 도구가
아닙니다. Batch는 추가로 user config와 rules를 무시하고 native
multi-agent를 `agents.enabled=false`와 `features.multi_agent=false`로
이중 차단합니다. Live는 반대로 두 값을 모두 `true`로 고정해 명시한 세
native worker를 유지합니다. 따라서 Batch의 외부 세 역할이 내부 위임을
중첩해 비용을 늘리지는 않으며, Live의 세 worker 구성은 꺼지지 않습니다.
이는 세 Live worker가 즉시 동시에 호출된다는 보장과는 별개입니다.

## 대회 운영: 문제 추가

문제와 상태를 먼저 등록합니다.

```sh
ctfos add-challenge \
  'Demo CTF' web 'Example' \
  --description '로그인 없이 admin 문서를 읽는 문제' \
  --prompt-file ./prompts/example.txt
```

등록된 문제의 managed 요구사항은 문제별로 점검합니다.

```sh
ctfos preflight 'Demo CTF' web 'Example'
```

새 문제는 state schema v2와 28,800초 wall budget으로 생성됩니다.
`--budget-seconds N`으로 바꿀 수 있고, 무제한은
`--unbounded --reason '운영자 사유'`를 함께 써야 합니다.

정확한 flag prefix를 아는 경우 description에서 추측하게 두지 않고 안전한
prefix-brace DSL로 고정합니다. 문제 형식이 대회 형식보다 우선하며 exact
형식이 있으면 generic regex fallback을 사용하지 않습니다.

```sh
ctfos add-challenge 'Demo CTF' rev 'Example' \
  --contest-flag-prefix KCTF \
  --flag-prefix TASK \
  --flag-alphabet alnum_ \
  --flag-min-inner 4 --flag-max-inner 128
```

대회 형식은 첫 문제를 만들 때만 고정할 수 있고 이후 문제는 자동으로
상속합니다. 이미 문제가 있는 대회에서는 문제별 `--flag-prefix`를
사용합니다.

생성되는 사람이 관리하는 입력 폴더는 다음과 같습니다.

```text
incoming/Demo CTF/web/Example/
```

다운로드한 문제 파일은 이 폴더에 직접 넣습니다. CTF-OS는 파일을 대신
다운로드하지 않습니다. 다음 `solve`, `run-challenge`, `prove`,
`pwn-prove-effect` 또는 `pwn-prove-interaction` 전에 인벤토리와 SHA-256
manifest를 갱신합니다. symlink와 special file은 ingest에서 거부합니다.

구형 호출을 위한 호환 명령도 남아 있습니다.

```sh
ctfos init-contest 'Demo CTF' --challenge 'web/Example'
```

`ctf_os.agent_tools solve`와 `ctf-container`는 기존 자동화 호환을 위한
저수준 운영자 도구입니다. 전자는 strict Live broker를 거치지 않고, 후자는
기본 Docker `bridge` 동작을 보존하므로 **신뢰하지 않는 대회 입력에는
사용하지 않습니다.** 실제 풀이 hot path는 이 문서의 `ctfos solve`,
`ctfos run-challenge`, `ctfos tool run`, `ctfos prove`와 category-specific
`ctfos pwn-prove-effect`/`ctfos pwn-prove-interaction`을 사용합니다.

## 논문·소스 지식 추가

사람이 내려받아 검토한 논문 전문, 공식 사양 또는 GitHub 소스를 문제별
immutable 지식 저장소에 넣을 수 있습니다. 엔진이 임의 URL을 내려받거나
자격증명을 보관하지는 않습니다.

```sh
ctfos knowledge add \
  'Demo CTF' crypto 'Lattice' ./research/paper-full.txt \
  --source 'https://arxiv.org/abs/ARTICLE_ID' \
  --title 'Full paper text' \
  --sha256 EXPECTED_SHA256

ctfos knowledge list 'Demo CTF' crypto 'Lattice'
ctfos knowledge search 'Demo CTF' crypto 'Lattice' 'Coppersmith lattice'
```

입력은 bounded regular file로 복사되어 SHA-256과 함께 읽기 전용 보관됩니다.
텍스트는 검색 가능하지만 모델 context에는 bounded excerpt와 canonical
pointer만 들어갑니다. 원본이나 index가 바뀌면 hash 검증에 실패합니다.
URL의 userinfo, query, fragment는 자격증명 유출 가능성 때문에 거부됩니다.

## 8시간 문제 예산 초기화

국내 대회 운용 기본값인 8시간을 명시적으로 초기화합니다.

```sh
ctfos budget-reset 'Demo CTF' web 'Example'
```

다른 값은 초 단위로 지정합니다.

```sh
ctfos budget-reset 'Demo CTF' web 'Example' --seconds 14400
```

이 명령은 문제의 할당량, 사용량, no-progress 시간과 refusal 기록을
초기화하고 reset 시점 기준의 절대 UTC deadline도 함께 기록합니다. 그
state deadline으로 **이후 발급되는** 작업의 불변 monotonic `D`를 정합니다.
Batch wave는 invocation/context 준비 전에 하나의 `D`를 발급해 세 역할이
공유하고, Live는 `Popen` 전에 `D`를 고정합니다. Tool의 command `D`는
evidence 처리와 state lock 안의 finish까지, Proof의 attempt별 `D`는
evidence와 locked attempt commit까지 유지되며 마지막 attempt의 `D`가 최종
`READY_TO_SUBMIT` 승격도 막습니다.

`D` 뒤 도착한 결과는 canonical success로 승격되지 않습니다. 실행 중인
기본 Live TUI와 Batch process는 TERM→KILL 후 reap되고, 큐에서 만료된 Batch
호출은 `challenge_budget_expired` 단일 비재시도 failure가 됩니다. 다만
bounded descriptor scan/copy/evidence, exact cleanup과 `D` 전에 lock 안에서
이미 승인된 atomic persistence는 `D` 뒤에 끝날 수 있습니다. Unix sandbox
RPC의 응답 grace는 일반/init `D+65초`, clean proof `D+150초`이며 이 grace가
성공 승격이나 cleanup 완료를 보장하지는 않습니다. `spent_seconds`는 도구
실행 회계에도 남지만 새 성공의 정본 경계는 발급된 `D`입니다.

foreground tool이 실행되는 동안 사람이 예산을 초기화하면 reset 이전
실행시간은 새 예산에 다시 과금하지 않고, reset 뒤 실제로 실행된 구간만
새 `spent_seconds`에 반영합니다.

reset은 이미 발급된 Live/Batch/tool/proof의 `D`나 Live capability를
연장하지도, 단축·취소하지도 않습니다. 더 짧은 새 예산을 기존 작업의 동적
취소로 쓰지 않으며 새 경계를 즉시 적용하려면 사람이 기존 작업을 중단하고
새 세션/작업을 시작해야 합니다. Live를 계속하려면 세션을 닫고 `ctfos solve
... --resume-thread THREAD_ID`로 새 deadline snapshot과 capability를
발급받아 재개합니다.

## Assisted Live 모드

사람과 함께 푸는 초기 릴리스 기본 모드입니다. 명시적으로 쓰려면
`--mode assisted`를 붙입니다.

```sh
ctfos solve \
  'Demo CTF' web 'Example' \
  --mode assisted \
  '문제 설명, URL 또는 nc 주소, 포트, 대회 규칙상 허용 범위'
```

긴 프롬프트는 파일로 전달할 수 있습니다.

```sh
ctfos solve \
  'Demo CTF' web 'Example' \
  --prompt-file ./prompts/example.txt
```

Live의 설정 기본값은 Sol Ultra Captain과 동일한 Sol 모델의
Recon/Specialist/Falsifier 세 논리 역할입니다. 문제별 `SESSION.md`와
`AGENTS.md`를 생성해 interactive Codex를 시작하며, 같은 문제에서는
`runtime/session.lock` 때문에 Live와 Batch 소유자가 동시에 실행되지
않습니다. model ID와 reasoning effort는 설정값이며 실제 계정의 Live TUI
호출은 회귀 테스트에서 실행하지 않습니다.

`solve`, `run-challenge`, 직접 `update_prompt`와 기존 문제의
`add-challenge --prompt`는 먼저 `runtime/session.lock`을 얻고 나서 prompt를
commit합니다. 경쟁 호출이 `SessionAlreadyRunning`으로 실패하면 기존
prompt, revision과 `state.json` bytes를 바꾸지 않습니다. 이는 prompt
갱신 경계의 보장이지 target·knowledge·budget을 포함한 모든 operator
configuration mutation을 세션에 종속시킨다는 뜻은 아닙니다.

Codex를 시작하기 전에는 network `none`의 light resource lease로 실제 image
entrypoint를 한 번 실행해 빈 `/work`에 원본의 exact copy와 provenance를
초기화하고, 그 뒤 `SESSION.md`와 `AGENTS.md`를 씁니다. 다른 문제는 별도
터미널에서 대회 스케줄러 승인 없이 세션을 추가할 수 있지만, 이 짧은
초기화의 tool lease나 이후 실제 model call은 자원 상한에서 기다릴 수
있습니다.

부모 `ctfos solve` 프로세스는 TUI가 끝날 때까지 `session.lock`, canonical
state와 Docker sandbox를 소유합니다. Live Codex에는
`features.shell_tool=false`를 적용하고 사용자의 기존 MCP 설정을
`mcp_servers={}`로 지운 뒤, required local stdio MCP인 `ctfos_live` 하나만
등록합니다. MCP server는 PATH의 같은 이름 파일을 실행하지 않고 현재
CTF-OS Python의 검증된 절대 경로와 `-I -m ctf_os.live_mcp`로 시작합니다.
Live의 유일한 state/challenge-execution MCP는 다음 열다섯 canonical
operation만 제공합니다.

```text
agent.flag  agent.fact  agent.goal  agent.hypothesis
agent.experiment  agent.evaluate  agent.artifact
agent.progress  agent.transition  tool.start  tool.run  jobs  inspect
knowledge.search  knowledge.read
```

목표는 한 번에 하나만 active이며, 가설은 falsifier와 typed evidence를
가집니다. 실행이 끝난 실험은 모델의 성공 주장만으로 확정되지 않고
`AWAITING_EVALUATION`에서 `agent.evaluate`의 명시적
keep/drop/inconclusive 판정을 거칩니다. proof·submission 상태는 여전히
운영자 전용입니다.

Codex 0.145의 실제 production-model mock Responses request를 캡처한
검증에서는 external app, web/network, `request_plugin_install`,
`exec_command`/`write_stdin`/shell tool이 0개였습니다. 열다섯 개는 전체
built-in tool 수가 아니라 `ctfos_live`가 제공하는 canonical
state/challenge-execution operation 수입니다. 별도로 남는 built-in에는
`exec`, `wait`, `apply_patch`, native collaboration, `tool_search`,
`view_image`, plan·user-input과 generic MCP resource helper가 있습니다.
여기서 `exec`는 filesystem/network API가 없는 V8 orchestration이고,
`apply_patch`는 challenge workspace writer입니다. 둘 다 host shell이나
Docker/state 직접 실행 권한은 아닙니다.
`ctfos_live`는 MCP resources를 구현하지 않으므로 generic resource
list/read는 실패하며 state나 mailbox를 우회해 읽는 경로가 아닙니다.

`agent.transition`은 proof·submission 상태를 만들 수 없고, challenge 파일을
실행하는 유일한 model 경로는 부모가 문제 sandbox에서 처리하는
`tool.run`입니다. 제출, proof, 예산 reset과 target 변경은 사람의 별도
터미널에만 남습니다. MCP server가 required이므로 scope 환경이 빠지거나
시작에 실패하면 Live도 명시적으로 실패하며, model-visible local engine이나
host 실행 fallback은 없습니다. Command network도
`sandbox_workspace_write.network_access=false`로 유지됩니다.

부모는 canonical runtime 아래 `live-mailboxes/session-*`에 mode `0700`의
private mailbox를 만들지만 그 path나 capability를 model argv, prompt,
shell environment 또는 `--add-dir`로 주지 않습니다. 정확한 session marker,
mailbox path와 scope capability는 Codex가 required MCP subprocess에만
전달하는 명시적 `env_vars`입니다. MCP는 함께 전달받은 challenge identity를
요청마다 고정합니다. MCP bridge와 부모는 request ID를 파일명에 포함한
request/response JSON 파일로 통신하며 각 메시지는 최대 1 MiB입니다. 쓰기는
임시 파일에 완료한 뒤
`fsync`와 `replace`로 원자화합니다. 양쪽은 directory file descriptor에
anchor하고 `O_NOFOLLOW`, regular file, owner, link count 1, 읽기 전후
size/mtime 안정성을 검사합니다. 부모는 exact session capability, challenge
scope와 identity, operation allowlist를 확인하고 요청을 직렬 처리합니다.
세션 안에서 수락한 request ID는 최대 16,384개까지 보존해 같은 ID의
mutating operation을 두 번 dispatch하지 않습니다. 각 string-array
parameter는 최대 4,096개, item당 64 KiB, 합계 512 KiB이고 broker operation
timeout은 최대 28,800초입니다. Client wait에는 종료 처리를 위한 최대
180초 grace만 더할 수 있습니다.

Malformed/hostile request나 response entry 오류는 가능한 한 해당 request의
bounded error로 격리해 watcher를 계속 운용합니다. 반대로 mailbox 전체
entry가 4,096개를 넘거나 request failure조차 안전하게 게시할 수 없으면
server status를 terminal error로 바꾸고 client가 명시적으로 실패하게 하며,
조용히 request를 굶기지 않습니다.
종료할 때 active operation이 끝날 때까지 broker thread를 join한 뒤
`session.lock`을 놓습니다. Mailbox는 최대 scan entry 수만 재귀 없이
정리하며, model이 만든 하위 디렉터리나 잔여 entry가 있으면 private leaf를
억지로 재귀 삭제하지 않습니다.

회귀 테스트는 격리된 stdio MCP process가 실제 mailbox broker를 거쳐
`agent.flag`를 호출하고, 부모가 후보를 즉시 stderr에 출력·flush하면서
canonical state에 영속하는 경로를 검증합니다. Live Captain prompt도
plausible flag를 단순 출력만 하지 말고 즉시 `ctfos_live`의 `agent.flag`로
기록하도록 요구합니다. 실제 계정의 Sol interactive TUI 전체와 native 세
worker 병렬 실행은 테스트에서 호출하지 않습니다.

별도 실제 계정 probe에서는 `gpt-5.6-luna`를 required stdio `ctfos_live`와
private mailbox broker에 연결해 `agent.flag`로
`KCTF{luna_mcp_e2e}`를 호출했습니다. 후보가 터미널에 즉시 출력되고 canonical
state에 영속됐으며 `submissions=0`도 확인했습니다. 이 검증 범위는 Luna
단일 호출의 flag 전달 경로이며 Sol interactive TUI, native 세 worker 병렬
실행이나 전체 문제 solve를 증명하지 않습니다.

따라서 “다른 문제의 세션을 사람이 바로 요청할 수 있다”와 “준비가 즉시
끝난다” 또는 “세 native worker가 즉시 동시에 호출된다”는 같은 보장이
아닙니다. workspace 초기화는 host tool lease에서 기다릴 수 있고, native
model call은 계정/provider 한도에서 대기할 수 있습니다. Live native
subcall에는 CTF-OS의 local FIFO를 적용하지 않으며, Codex/provider가 정하는
실제 시작 시점을 CTF-OS가 완전히 관측하지도 못합니다. 대기가 생겨도 세
논리 역할은 삭제하거나 합치지 않습니다.

```sh
# 터미널 1
ctfos solve 'Demo CTF' pwn 'Heap'

# 터미널 2
ctfos solve 'Demo CTF' rev 'VM'
```

기존 Codex thread ID로 재개하려면 다음처럼 실행합니다.

```sh
ctfos solve 'Demo CTF' web 'Example' --resume-thread THREAD_ID
```

CTF-OS는 thread ID를 자동 발견하거나 background에서 Live TUI를 다시
붙이지 않습니다. 같은 문제의 동시 두 세션 대신 명시적 resume를 사용합니다.

## Managed 모드

Managed는 사람이 선택한 한 문제에서
`preflight → Captain → 정확히 3-role wave → deterministic action →
Receipt → checkpoint`를 엔진이 소유합니다. 장애가 나면 assisted로
fallback하지 않고 `PAUSED` 또는 `NEEDS_HUMAN`으로 멈춥니다.

```sh
ctfos preflight 'Demo CTF' web 'Example'
ctfos managed-cycle 'Demo CTF' web 'Example' --note '첫 cycle'
ctfos solve 'Demo CTF' web 'Example' --mode managed --max-cycles 8
```

### Managed thread continuity

`ctfos solve --mode managed`, `ctfos run-challenge --mode managed`,
`ctfos managed-cycle`에서 `--thread-continuity`를 생략하면 CLI의 effective
기본값은 `captain_lane`입니다. 이 정책은 완료된 이전 Captain run의
Captain lane만 resume합니다. Captain이 아닌 proof/explorer/builder/verifier
lane은 매번 fresh thread를 사용하므로 독립 검증은 그대로 유지됩니다.

모든 lane을 새로 시작하려면 `--thread-continuity=fresh`를 명시합니다.
assisted, thin, legacy 모드는 옵션을 생략했을 때 계속 `fresh`이며, 이
모드에서 명시한 non-fresh 정책은 거부됩니다. 이 기본값 변경은 CLI에만
적용됩니다. `ManagedOrchestrator.run_cycle()`과 `run_cycles()`를 직접
호출하는 programmatic API의 기본값은 계속 `fresh`입니다. Codex request
compression과 remote compaction은 thread 정책과 무관하게 이미 항상
활성화되어 있으므로 별도 continuity 옵션이 필요하지 않습니다.

provider 상한은 호출 시작만 대기시키며 예약된 논리 Run 세 개를 줄이지
않습니다. Managed role contract v2는 command마다 열린 가설 ID,
`expected_observation`, `keep_if`, `drop_if`, timeout/resource class와 원격
target generation pin을 요구합니다. 이 계약 버전은 durable worker-result
envelope 버전과 독립적으로 기록됩니다. production evaluation 정책은
`observe`입니다. pending strategic
evaluation은 다음 context의 최우선 evidence가 되지만 다음 cycle을 막는
hard barrier는 X-22를 통과하기 전에는 활성화하지 않습니다. `solve`의
기본값 역시 canary 승격 기준을 통과하기 전까지 assisted로 유지됩니다.

### Managed failure capsule

계약 위반, frontier 구성 실패, invalid wave, proof recipe 또는 proof 실행
실패는 단순한 checkpoint note로 끝나지 않습니다. 엔진이 최신 checkpoint에
typed failure capsule을 만들고 다음 Captain context의 mandatory
`resume_capsule`에 다시 넣습니다. capsule은 실패 stage와 machine
`reason_code`, cycle 전후 state revision, 실패 fingerprint, 관련
run/experiment/evidence ID, 미해결 hypothesis, 최대 세 개의 다음 판별
experiment를 기록합니다. source가 한도를 넘으면 recovery를 중단하지 않고
결정적으로 잘라 각 종류의 omitted count를 남깁니다. immutable capture
내용은 별도 content hash로 보호하고, 반복 판정용 fingerprint는 서로 다른
cycle의 동등한 실패만 묶습니다.

모델 command, provider/normalization message, checkpoint note 같은 자유
텍스트는 capsule에 복사하지 않습니다. 다음 모델에는 command SHA-256,
오류 개수와 machine failure kind, canonical run의 `result.json` 또는
`validation.json` exact pointer만 보입니다. experiment의 expected/keep/
drop 문구도 재주입하지 않고 contract hash와 state pointer로 대체합니다.
최소 4 KiB context에서도 최신
failure capsule과 적어도 하나의 정확한 run pointer를 유지하도록 별도
compact 표현을 사용합니다. 동일 fingerprint가 과거 checkpoint에 몇 번
나왔는지도 함께 보여 반복 실패를 구분합니다. fingerprint가 canonical
cycle evidence와 맞지 않으면 resume context 생성은 fail-closed합니다.

Pwn의 engine-owned crash gate가 `INCONCLUSIVE` 또는 `FAILED`로 끝난
경우에도 같은 failure capsule 경로를 사용합니다. 여섯 실행의 run,
receipt, stdout/stderr artifact ID와 typed verdict가 다음 context에
재진입하며, 1,536바이트 compact capsule에서도 해당 판정과 적어도 하나의
정확한 run/artifact pointer를 유지합니다. 일반 experiment의 복수 receipt는
계속 거부하고, Pwn gate의 정확한 여섯 receipt만 결과의 attempt 순서대로
묶습니다. terminal Pwn 결과는 원래 managed cycle의 selected action에서
사라질 수 없고, capsule reason/status/stage도 실제 non-pass 판정과
일치해야 합니다.

### Managed Pwn D→V crash gate

로컬 Pwn attack wave에는 모델의 “crash 성공” 주장을 그대로 믿지 않는 첫
실행 게이트가 연결돼 있습니다. Builder가 exact payload artifact와 열린
hypothesis를 `verify_pwn_crash`로 지정하면 엔진이 다음을 고정합니다.

- 현재 source manifest의 실행 가능한 ELF, payload size/SHA-256, pinned
  image digest와 capability attestation을 하나의 recipe로 결속합니다.
- network-none clean sandbox에서 payload 3회와 엔진이 만든 빈 control
  3회를 같은 전체 deadline 안에 one-shot으로 실행합니다.
- payload 실행 중 같은 허용 signal이 2/3회 이상 발생하고 세 control이
  모두 정상 종료할 때만 `CONFIRMED`입니다. 단순 exit code 139는 signal
  crash로 세지 않으며 control crash는 성공을 막습니다.
- 현재 v1 producer는 host의 piped `core_pattern`을 실행하지 않도록 fault
  signal을 전달 전에 관측하고 억제합니다. 성공 증거는 단일 스레드 root
  target의 default core-signal stop으로 한정합니다. caught/ignored signal,
  자식 process의 fault, thread를 만든 root target의 fault와 관측되지 않은
  terminal core signal은 bounded producer `ERROR`이며 성공으로 승격되지
  않습니다.
- target exec 전에 고정 seccomp filter를 설치해 `CLONE_UNTRACED`와
  cross-Tgid `CLONE_SIGHAND`를 차단하고 `clone3`는 `ENOSYS` fallback으로
  보냅니다. 일반 pthread clone은 허용하되 thread가 관측된 target의 core
  stop은 v1 proof 범위 밖으로 fail-closed합니다.
- 여섯 request/contract/receipt와 stdout/stderr artifact의 exact
  ID·path·SHA-256·size를 상태에 연결합니다. 외부 evaluator는 파일을
  bounded/no-follow로 다시 읽고 gate 판정을 독립 재계산합니다.
- 큰 stderr를 포함한 전체 실행 stream의 flag-looking 문자열은 즉시
  운영자에게 표시하지만 후보로만 기록하며 자동 제출하지 않습니다.
- `CONFIRMED`일 때만 hypothesis를 확인합니다. crash 확인만으로 Fact,
  exploit primitive, proof 또는 제출 상태를 만들지 않습니다.

프로세스가 commit 전에 죽으면 다음 session boundary가 typed experiment를
`FAILED`로 닫고, canonical state에 없는 정확한 orphan run/evidence만
symlink를 따라가지 않고 정리합니다. nonpass gate는 failure capsule로
다음 Captain에게 전달됩니다.

### Pwn address-resolution advisory

고정 선형 `leak 필수` 규칙 대신, exploit strategy가 선언한 각 address
dependency를 source-bound ELF profile과 함께 분류하는 순수 계약이 있습니다.
결과는 `RUNTIME_ADDRESS_RESOLUTION_REQUIRED`,
`CONDITIONAL_NOT_APPLICABLE`, `UNRESOLVED` 중 하나지만 어디까지나 advisory
입니다.

- exact strategy hash, dependency ID, source manifest/hash/size와 profile
  evidence hash가 모두 일치해야 합니다.
- 결과가 스스로 다른 dependency나 ET_EXEC profile을 써서 재분류하는
  coherent substitution은 거부합니다.
- dependency는 canonical order이고 strategy/result JSON은 bounded,
  duplicate-free, canonical bytes만 허용합니다.
- 모든 verdict는 global leak N/A, leak proof, primitive, proof 또는 stage
  advance 권한을 갖지 않습니다. 모델이 dependency를 누락하거나 모두
  relative로 선언해도 L단계를 통과할 수 없습니다.

실제 leak gate는 runtime disclosure provenance와 downstream
randomized-layout exploit replay가 추가된 뒤에만 이 advisory를 입력으로
사용합니다.

### Managed Pwn dynamic interaction oracle

정적 stdin payload로 표현할 수 없는 leak→derive→staged-send exploit은
canonical data-only `pwn_local_bounded_interaction_v1` recipe로 검증할 수
있습니다. 운영자가 이미 열린 Pwn challenge에서 typed RIP-control 또는
canonical executed parent experiment와 workspace recipe를 명시합니다.

```sh
ctfos pwn-prove-interaction \
  'Demo CTF' pwn 'Example' \
  --parent E-parent \
  --recipe pwn/interaction-v1.json
```

엔진은 현재 source manifest, exact image, configuration epoch, parent,
recipe SHA-256과 attested image producer를 결속하고, 첫 실행 전에 attack
3개와 matched producer-control 3개의 identity와 request를 `state.json`에
preissue합니다. 여섯 network-none clean workspace는 서로 다른 physical
identity를 사용하며 각 target stdout/stderr, transcript와 derivation DAG를
bounded artifact로 남깁니다. producer의 self-report가 아니라 별도 host
evaluator가 canonical recipe와 preissue를 다시 읽어 3+3 differential을
계산합니다.

실제 `zone`에서는 54-step recipe가 매 process의 stack/libc 값을 다시
capture·derive하고 staged `system()` chain을 실행했습니다. evaluation
artifact
`A-pwn-interaction-result-1ce8deede4d6b8211cdd7f9a49970d10`
의 SHA-256
`d622818d48afaec9b07f209d81f15a36794709ded83bde13935d8953bd3d2d5e`
에서 attack 3회는 effect를 보였고 matched control 3회는 거부됐습니다.
이 결과는 typed interaction **exploit-effect** 증거입니다. local flag
source와 active remote target이 없었고 recipe/parent도 운영자가
제공했으므로 flag, solve, remote portability 또는 자율 discovery를
증명하지 않습니다. candidate와 submission 권한도 만들지 않습니다.
정확한 pointer는
[Zone 실행 증거](ctf-reports/21-zone-solve-capable-exploit-evidence.md)에
기록돼 있습니다.

### Managed Rev executable oracle

로컬 Rev 문제에는 설명문이 아니라 원본 바이너리의 stdin 판정을 사용하는
첫 번째 완전한 managed proof 경로가 연결돼 있습니다. Reproducer가 proof
wave에서 durable candidate 하나와 canonical artifact 하나를
`accepted_input`으로 지정하면, 모델이 runner argv나 반복 횟수를 고르는 대신
엔진이 다음 계약을 강제합니다.

- 현재 source snapshot과 정확히 하나의 `CONFIRMED` inventory-v2 evidence,
  exact image ID, 설정 epoch, 요청 hash와 전체 deadline을 묶습니다.
- 입력은 최대 1 MiB이고 candidate literal을 포함할 수 없습니다.
- 고정 runner
  `/usr/bin/python3 /opt/ctf-templates/rev/stdin_exec.py`로 원본 바이너리를
  network-none clean container에서 실행합니다.
- 동일 입력 positive 3회 뒤 `xor-first`, `xor-last`, `truncate` control을
  각각 한 번 실행합니다. 빈 입력은 `00`, `0a`, `ff` control을 씁니다.
- positive의 engine-owned stdout/stderr에 exact candidate가 매번 있어야
  하고, 세 control에는 선택된 candidate뿐 아니라 flag-looking 문자열이
  하나도 없어야 합니다. 정상적인 nonzero control exit은 transport
  failure가 아닙니다.
- positive에서 exact candidate가 빠지거나 control에서 flag-looking
  문자열이 하나라도 나오면 의미적 반증으로 proof experiment를
  `COMPLETED`로 닫습니다. timeout, exit 125, capture 불완전, stale pin 같은
  구조적 오류는 `FAILED`입니다. 여섯 실행을 모두 통과한 경우만 candidate를
  `READY_TO_SUBMIT`으로 올립니다.

각 attempt는 서로 다른 clean workspace를 쓰고 bounded raw stream, 요약,
SHA-256과 exact artifact pointer를 보존합니다. 어느 경우에도 CTF
사이트로 자동 제출하지 않습니다. 현재 이 계약은 local standalone Linux
ELF stdin oracle에만 적용됩니다.

진행 중 세션을 운영자가 끝내려면 이유와 목표 상태를 명시합니다.

```sh
ctfos session cancel 'Demo CTF' web 'Example' \
  --reason '원격 인스턴스 교체 필요' --target NEEDS_HUMAN
```

사람이 accepted 결과를 기록하면 submission, active goal/session 종료와
referential `incomplete` closure가 같은 state commit에 남습니다. 이후
`ctfos close`는 이 자동 closure를 idempotent하게 완성하며, portable
요청이 크기 한도를 넘으면 referential로 명시해 기록합니다.

## Legacy Batch 모드

재현 가능한 Captain → worker wave 반복에는 Batch를 사용합니다.

```sh
ctfos run-challenge \
  'Demo CTF' web 'Example' \
  --mode legacy \
  --max-cycles 8
```

각 cycle은 Captain이 다음 단계를 고른 뒤 Discovery, Attack, Proof 중 하나의
세 역할을 병렬로 실행합니다. 세 역할은 유지되고 provider 상한에서는
호출만 FIFO로 대기합니다. 등록된 sandbox 실험을 실행하지 않고 모델 결과만
검사하려면 `--no-tools`를 추가합니다. 저장된 문제풀이 프롬프트가 없으면
`run-challenge`와 `wave`는 모델을 시작하기 전에 실패합니다.

각 Batch attempt는 pipe를 끝까지 drain하고 flag pattern을 streaming
scan하되, 파일에는 JSONL raw prefix 16 MiB와 stderr prefix 1 MiB만
보존합니다. structured result는 2 MiB를 넘으면 contract invalid입니다.
`attempt-*-capture.json`에는 전체 관측 byte 수, 저장 byte 수, limit,
truncation과 oversized 여부가 기록됩니다.

Raw stream에서 찾은 값과 structured result가 명시한 값은 같은 bounded
candidate 계약을 거칩니다. 비어 있거나 비출력 문자·개행이 있거나 1,024자
또는 UTF-8 4,096 bytes를 넘는 값은 canonical state에 들어가지 않습니다.
후보를 durable intent로 기록하는 callback이 실패하면 해당 wave는 성공으로
계속하지 않고 active sibling과 provider 대기자를 취소합니다. CTF 사이트
제출은 어느 경우에도 수행하지 않습니다.

Batch `codex exec`도 host shell/`exec_command`/`write_stdin`과 외부 tool surface를
비활성화하고 user MCP를 모두 지웁니다. `--ignore-user-config`,
`--ignore-rules`, `agents.enabled=false`, `features.multi_agent=false`를
start/resume에 함께 적용하므로 challenge 파일을 host command로 실행하거나
세 외부 논리 역할 밖으로 native 위임을 중첩하지 않습니다.
stdin은 별도 nonblocking writer가 보내고 stdout/stderr는 동시에 drain합니다.
timeout, callback 오류 또는 wave 취소·Ctrl-C가 발생하면 active Codex
process group을 TERM 후 KILL하고 reap하며, provider FIFO에서 기다리던
sibling도 즉시 취소합니다.

특정 wave 한 번만 실행할 수도 있습니다.

```sh
ctfos wave 'Demo CTF' web 'Example' discovery
ctfos wave 'Demo CTF' web 'Example' attack
ctfos wave 'Demo CTF' web 'Example' proof
```

대회 전체를 순회하거나 다음 문제로 자동 전환하는 명령은 없습니다. 사람은
풀 문제마다 별도 터미널에서 `solve` 또는 `run-challenge`를 명시적으로
실행합니다.

## 원격 대상과 네트워크 경계

기본 sandbox network는 `none`입니다. 원격 문제가 아니면 target을 추가하지
마십시오.

```sh
ctfos add-target \
  'Demo CTF' web 'Example' \
  'https://challenge.example:443'
```

state v2 managed remote 작업은 typed target을 추가한 뒤 사람이 primary를
선택해야 합니다. replace/revoke/expiry는 configuration epoch를 올리고
stale 결과를 의미 상태에 합치지 않습니다.

```sh
ctfos target add 'Demo CTF' web 'Example' \
  'https://challenge.example:443' --purpose 'challenge API'
ctfos target list 'Demo CTF' web 'Example'
ctfos target select 'Demo CTF' web 'Example' TARGET_ID
ctfos target check 'Demo CTF' web 'Example' TARGET_ID
ctfos target revoke 'Demo CTF' web 'Example' TARGET_ID \
  --reason 'challenge 종료'
```

`--enforcement declared`가 등록 기본값이지만 실행 권한은 아닙니다. 이
모드는 대상 metadata만 보존하며, Docker 기본 `bridge`가 목적지 allowlist를
커널에서 강제하지 못하므로 원격 command는 fail-closed로 거부됩니다.

원격 문제는 내장 경계(`builtin`) 또는 운영자가 준비한 외부 제한
proxy/network(`proxy`) 중 하나를 명시적으로 선택해야 합니다. 권장 기본은
내장 경계입니다.

```sh
ctfos target add \
  'Demo CTF' web 'Example' \
  'https://challenge.example:443' \
  --enforcement builtin \
  --docker-network bridge \
  --http-rate 2.0 \
  --http-burst 4
```

`builtin`은 문제 scope와 정책 digest로 이름이 정해지는 Docker
`--internal` network를 만들고, 풀이 컨테이너는 그 network에만 연결합니다.
별도 최소권한 proxy 컨테이너만 internal network와 지정한 upstream network에
이중 연결됩니다. proxy는 internal interface에만 listen하며 정확한
hostname/port allowlist 외 목적지를 HTTP forward/CONNECT와 SOCKS5 모두에서
거부합니다. 풀이 컨테이너에는 고정된 `HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY`가 주입되고 직접 egress route는 없습니다. Built-in target은
wildcard port를 허용하지 않으므로 endpoint에 포트를 반드시 적어야 합니다.
scheme도 경계에 포함되어 HTTP/WS는 forward proxy, HTTPS/WSS는 CONNECT,
scheme 없는 raw TCP와 `tcp://`만 SOCKS5를 사용할 수 있습니다.

proxy 컨테이너는 target별 token bucket을 유지합니다. 일반 HTTP와 `ws`
handshake는 실제 요청마다 토큰을 소비하므로 한 command가 여러 요청을 보내도
각각 계수됩니다. TLS를 종단하지 않는 보안 경계이므로 `HTTPS`/`wss`의
암호화된 tunnel 내부 요청은 볼 수 없고 CONNECT transaction 하나가 토큰
하나를 소비합니다. HTTPS 내부 요청까지 개별 계수해야 하는 대회에서는
운영자가 승인한 TLS-terminating proxy를 `proxy` 모드로 제공해야 합니다.

원격 트래픽 없는 lifecycle 검사와 실제 smoke는 분리되어 있습니다.

```sh
# 상태/만료만 검사하며 원격 요청을 하지 않음
ctfos target check 'Demo CTF' web 'Example' TARGET_ID

# 사람이 명시한 protocol만 built-in 경계 안에서 실제 검사
ctfos target smoke 'Demo CTF' web 'Example' TARGET_ID \
  --mode dns --mode tcp --mode tls

# WebSocket endpoint인 경우
ctfos target smoke 'Demo CTF' web 'Example' TARGET_ID \
  --mode websocket --path /socket
```

smoke helper는 DNS control resolution, SOCKS5 TCP connect, HTTP CONNECT 뒤의
인증서 검증 TLS handshake, RFC 6455 Upgrade를 각각 bounded JSON으로
기록합니다. target은 먼저 primary로 선택되어 있어야 하며 이 명령만 실제
원격 요청을 수행합니다.

기존 외부 경계를 사용하는 경우에는 목적지 제한 proxy/network를 먼저
구성하고 그 network를 `proxy` enforcement로 등록합니다.

```sh
ctfos add-target \
  'Demo CTF' web 'Example' \
  'https://challenge.example:443' \
  --docker-network ctfos-proxy-net \
  --enforcement proxy
```

외부 `proxy` 모드의 방화벽 규칙과 request 제한은 운영자 책임입니다.
두 enforcement 모두 CTF-OS가 시작하는 network tool/proof command를
정규화한 hostname별 공용 FIFO에서 기본 1초 간격으로 시작합니다. 값은
`resources.remote_command_min_interval_s`이며 `0`은 명시적 비활성화입니다.
이 FIFO는 token bucket과 독립적인 **command-start spacing**입니다.

## 상태, pause와 여러 세션

문제 상태를 확인합니다.

```sh
ctfos status 'Demo CTF'
ctfos status 'Demo CTF' --watch
ctfos inspect 'Demo CTF' web 'Example' summary
ctfos inspect 'Demo CTF' web 'Example' state
ctfos inspect 'Demo CTF' web 'Example' candidates
ctfos inspect 'Demo CTF' web 'Example' runs --offset 0 --limit 100
ctfos leases --json
```

작은 section은 기존 JSON list/dict를 그대로 반환합니다. 큰 state는 bounded
summary로 바뀌고 큰 목록은 `items`, `total`, `next_offset`, `revision`이
있는 page envelope로 바뀝니다. page 크기는 최대 200개이며 broker는 1 MiB
전송 한계 전에 768 KiB에서 응답을 자릅니다.

문제의 구조화 상태와 상태 전이 정본은 다음 경로의 `state.json`입니다.

```text
.ctfos/contests/<contest>/challenges/<category>/<challenge>/state.json
```

`state.prev.json`, 원자적 replace, revision 검사와 문제별 `.lock`의 짧은
`flock`으로 CAS·복구 writer를 직렬화합니다. 이 `.lock`은 세션 수명 lock이
아닙니다. 같은 문제의 Live/Batch/tool/proof owner 배제는
`runtime/session.lock`이 담당하고, `runtime/delegation-owner.json`은 Live
owner를 보여 주는 진단 marker일 뿐 lock이나 권한 정본이 아닙니다.

canonical state JSON의 읽기와 쓰기는 16 MiB로 제한됩니다. 최상위 typed
collection과 알려진 nested repeated-ID field는 각각 최대 16,384개입니다.
또한 state가 참조하는 canonical artifact의 **실제 파일 크기 합계**는 모든
commit에서 `runtime.work_tree_max_bytes` 이하인지 검사합니다.

`events.jsonl`, `context/current.md`, `board.md`, `board.json`, `exports/`는
state에서 다시 만들 수 있는 파생/감사 자료입니다. 반면 hash가 등록된
artifact/proof bytes는 상태 전이의 evidence이고,
`submissions.jsonl`은 accepted flag의 대회 전체 중복 판정에 쓰는 durable
ledger이므로 단순 파생 JSONL로 취급하지 않습니다.

사람 판단이 필요하면 현재 상태를 보존해 pause/resume할 수 있습니다.

```sh
ctfos pause  'Demo CTF' web 'Example'
ctfos resume 'Demo CTF' web 'Example'
```

최근 세 개의 실행에서 같은 명령, 같은 failure label, 새
fact/artifact/progress 부재 또는 같은 locator의 artifact churn이 관측되면
governor가 `ACTIVE → STALLED`로 전이합니다. 상태에는 고정 recovery
사다리의 다음 제안 하나만 기록하며 모델 교체, 도구 실행, 재분류 또는 새
세션을 자동으로 시작하지 않습니다. `run-challenge`도 STALLED 이후 추가
cycle을 진행하지 않습니다. 사람이 제안된 관측/반증 조치를 반영한 뒤에는
명시적으로 다시 활성화합니다.

```sh
ctfos agent transition \
  --contest 'Demo CTF' --category web --challenge 'Example' ACTIVE
```

## 도구 실행과 background 범위

문제별 typed command는 실행 전에 실험의 expected/keep/drop 조건을
등록하고 sandbox에서 실행합니다.

```sh
ctfos tool run \
  --contest 'Demo CTF' \
  --category web \
  --challenge 'Example' \
  --expected '비로그인 응답의 status와 redirect' \
  --keep-if '인증 없이 privileged state로 전이한다' \
  --drop-if '모든 경로가 로그인으로 수렴한다' \
  -- curl -i https://challenge.example/
```

문제별 원격 요청에는 사전에 등록한 target을 `--target`으로 명시해야
합니다.

```sh
ctfos tool run \
  --contest 'Demo CTF' --category web --challenge 'Example' \
  --target 'https://challenge.example:443' \
  -- curl -i https://challenge.example/
```

foreground 도구 명령은 one-shot `docker run --rm` 컨테이너에서
실행됩니다. 컨테이너 수명 자체가 명령과 그 자식 프로세스의 hard
supervisor이므로 명령이 끝나거나 timeout이면 host resource lease와
컨테이너도 함께 끝납니다. Docker control 호출 자체가 timeout이면 backend는
미리 생성한 challenge-scope·nonce 기반 exact container name 하나만
`docker container rm --force`로 정리를 시도하고 실패 detail을 원래 timeout
오류에 붙입니다. glob이나 넓은 이름 범위로 다른 컨테이너를 삭제하지
않습니다.

`ctfwrap`은 stdout/stderr pipe를 끝까지 drain하지만 raw log에는 기본적으로
stream마다 16 MiB prefix만 저장합니다. 각 stream의 실제 마지막 4 KiB는
summary tail로 따로 유지합니다. `stream-capture.json`, `result.json`과
`meta.json`에는 total/stored/limit, `truncation_known`, `truncated`와
`capture_complete` metadata가 남으므로 저장된 prefix를 완전한 원출력으로
해석하면 안 됩니다.

`runtime.work_tree_max_bytes`는 `/work`를 명령 전후에 descriptor-anchored
두 번의 안정된 scan으로 계측합니다. symlink를 따라가지 않고 sparse file은
논리 크기로, hard-linked 이름은 보수적으로 각각 계산합니다. 초과하면 다음
작업을 거부하며 stream/artifact/proof 개별 상한도 이 값 아래로 묶입니다.
기본값은 16 GiB입니다. 이는 커널 project quota가 아니므로 한 명령이 실행
중에 잠깐 상한을 넘는 write까지 즉시 막지는 않습니다.

문제별 누적 `.ctfos` 저장소는 별도의 bounded inventory로 계측합니다.
`runtime.challenge_storage_quota_bytes` 기본값은 64 GiB이며 문제 범위의
`runs/`, `artifacts/`(가역 quarantine 포함), `proof/`, `runtime/`,
`context/`, `knowledge/`, `exports/`를 모두 포함합니다. 이 중
`runtime/`, `context/`, `knowledge/`, `exports/`는 연속성·정본·운영자
산출물을 보존하는 root이므로 항상 reachable/canonical이며 GC와 영구
purge의 대상이 아닙니다. 문제 root의 `state.json`, `state.prev.json`,
`events.jsonl` 같은 control file과 contest 공용 `submissions.jsonl`은 이
quota에 포함되지 않습니다. scan은 기본 100,000 entry와 256 GiB
관찰량에서 중단하며, symlink·special file·hardlink 또는 scan 한계 때문에
exact total을 증명할 수 없으면 quota 판정을 fail-closed합니다.

```sh
ctfos storage inventory 'Demo CTF' rev 'VM'
ctfos storage plan 'Demo CTF' rev 'VM'

# 도달 불가능 파일을 삭제하지 않고 문제 범위 quarantine으로 이동
ctfos gc 'Demo CTF' rev 'VM'
ctfos storage restore 'Demo CTF' rev 'VM' QUARANTINE_ID

# 영구 삭제는 별도의 준비 결과를 exact하게 재확인해야 함
ctfos storage purge-prepare 'Demo CTF' rev 'VM' QUARANTINE_ID
ctfos storage purge 'Demo CTF' rev 'VM' QUARANTINE_ID \
  --manifest-sha256 MANIFEST_SHA256 --confirm 'EXACT_CONFIRMATION'
```

`ctfos gc`는 항상 가역 이동만 수행합니다. 영구 purge는 준비 manifest의
identity, 파일 집합, digest와 confirmation을 다시 검증하며, 중단된 이동,
복구 및 purge tombstone은 재실행 시 동일 문제 범위 안에서 조정됩니다.

도구 실행, flag callback, artifact scan 또는 결과 commit이 실패하면 해당
실험은 canonical state에서 `FAILED`와 failed run으로 종결됩니다. 진단용
`result.json`을 쓰는 과정 자체가 실패해도 실험을 `RUNNING`으로 남기지
않으며, 정본 state 전이 뒤 저장소 오류를 호출자에게 다시 알립니다.

profile의 lease vector는 같은 실행의 Docker 제한으로 직접 연결됩니다.

| profile | Docker CPU | Docker memory |
|---|---:|---:|
| `light` | 1 | 2 GiB |
| `standard` | 2 | 4 GiB |
| `heavy` | 4 | 8 GiB |
| `gpu` | 4 | 10 GiB |

`gpu`는 GPU lease를 얻은 뒤 host passthrough plan을 required mode로
검사하고, 성공할 때만 GPU Docker flags를 붙입니다. KVM이 필요한 실행은
`--kvm`을 명시해야 하며 KVM lease와 `/dev/kvm` 탐지가 모두 성공할 때만
장치를 붙입니다. GPU/KVM을 요청했는데 host capability가 없으면 Docker
실행 전에 실패합니다.

```sh
ctfos tool run \
  --contest 'Demo CTF' --category rev --challenge 'VM' \
  --profile gpu --kvm \
  -- python3 solve.py
```

이미지에는 `ctf-bg`, `ctf-jobs`, `ctf-log`, `ctf-kill` primitive가 있고
sandbox interface에는 lease-bound start/status/log/cancel/recover가
연결되어 있습니다. `ctfos tool start`는 신뢰 host supervisor를 먼저
분리하고, supervisor가 기존 global `LeaseBroker`의 전체 vector를 얻은
뒤에만 해당 job 전용 label·resource-limit Docker runtime을 만듭니다.
lease는 image job이 terminal status를 기록하고 그 exact runtime을 제거할
때까지 유지됩니다. 일반 foreground 명령에서 `ctf-bg`, `setsid`, `nohup`,
shell `&`를 우회 호출하는 경로는 계속 거부됩니다.

```sh
ctfos tool start \
  --contest 'Demo CTF' --category forensic --challenge Memory \
  --profile heavy --timeout 14400 --name volatility-scan \
  -- volatility3 -f memory.raw windows.pslist
```

launch 결과에는 `job_id`, scope fingerprint, runtime ID와 무작위
`supervisor_id`가 함께 나옵니다. 이후 작업은 이 exact receipt tuple을
사용합니다.

```sh
# 모든 receipt를 조회하면서 죽은 host monitor를 fail-closed reconcile
ctfos jobs 'Demo CTF' forensic Memory

# bounded tail
ctfos jobs 'Demo CTF' forensic Memory \
  --job-id job-00000001 --supervisor-id bg-0123456789abcdef0123456789abcdef \
  --log --tail-bytes 16384

# TERM/KILL 취소
ctfos jobs 'Demo CTF' forensic Memory \
  --job-id job-00000001 --supervisor-id bg-0123456789abcdef0123456789abcdef \
  --cancel --grace 3
```

Local client, capability-authenticated Unix daemon, attached Live broker/MCP가
같은 typed lifecycle을 사용합니다. host supervisor가 비정상 종료한
receipt는 다음 start/list/status/recover 경계에서 해당 exact container
job을 먼저 취소·제거한 후 stale flock metadata를 회수합니다. raw stdout와
stderr는 `/work/.ctf/jobs/JOB_ID`의 bounded log API로만 읽으며 supervisor
receipt에는 command output을 복제하지 않습니다.

## 후보 플래그, proof, 사람 제출

bounded scanner가 모델 또는 도구 출력에서 플래그 형식을 관측하면 발견
시점에 다음 형식으로 터미널의 stderr에 출력하고 flush합니다.

```text
🚩 FLAG CANDIDATE (미제출) [source]
flag{...}
```

이 표시는 성공이나 제출을 뜻하지 않습니다. 후보는 상태에도 기록되며 다음
명령으로 다시 확인할 수 있습니다.

Batch, foreground tool과 clean proof stream은 출력 전에 bounded
candidate-intent journal을 원자 저장하고 `fsync`합니다. 정상 경로에서는
같은 후보를 canonical state에 한 번 commit한 뒤 journal을 지웁니다. 그
사이 호스트 process가 죽어 journal이 남으면 다음 문제 세션 경계에서
후보를 터미널에 **다시 출력한 뒤** value 기준으로 멱등 reconcile합니다.
크래시 직전 이미 본 후보가 중복 표시될 수 있지만, 미출력 후보를 조용히
잃는 것보다 이를 우선합니다. Live `agent.flag`는 canonical state commit
뒤 출력합니다.

Batch model stream은 raw 파일 저장 상한 뒤에도 drain하며 scan하지만,
candidate는 기본 1,024개와 총 256 KiB 문자 상한을 가집니다. Foreground
tool도 저장하는 16 MiB raw prefix와 별개로 drain되는 stdout/stderr 전체를
`runtime.flag_patterns`로 rolling scan합니다. 일치값은
`flag-candidates.jsonl`에 후보 1,024개, 총 256 KiB 문자, 파일 1 MiB
상한으로 기록됩니다. 호스트는 이 regular-file sidecar를 raw scan 예산과
별도로 tail하므로 raw prefix와 4 KiB summary tail 사이에만 있던 후보도
실행 중 즉시 표시합니다. `capture_complete=false`인 비정상 pipe 종료 뒤의
미관측 bytes까지 탐지한다는 보장은 없습니다.

Clean proof는 일반 solver가 mount받는 `/work` 밖의 challenge-private
`.proof-live` sibling에서 exact temporary leaf만 실행합니다. 호스트
tailer가 실행 중 raw log와 full-stream sidecar를 별도 상한으로 읽고,
proof가 반환하기 전 intent를 `fsync`한 다음 후보를 즉시 출력합니다.
임시 leaf를 없애기 전에 sidecar를 최종 `/work/proof/clean-*` 증거
디렉터리에 최대 1 MiB로 복사하고, 정상 attempt state commit 뒤 intent를
지웁니다. 이 sidecar는 challenge-writable **후보 신호**이지 proof 성공
증거로 승격되지 않습니다. 선택한 candidate가 engine-managed canonical
stdout/stderr snapshot에 없으면 sidecar에서 관측됐더라도 proof는
통과하지 않습니다. Tailing 중인 growing live sidecar와 final persisted
copy에는 각각 독립적인 1 MiB 물리 read budget을 예약하며, 최종 저장
sidecar 자체도 최대 1 MiB입니다.

```sh
ctfos inspect 'Demo CTF' web 'Example' candidates
```

재현 명령이 준비됐다면 깨끗한 proof container에서 검증합니다.

```sh
ctfos prove \
  'Demo CTF' web 'Example' \
  --candidate CANDIDATE_ID \
  -- python3 solve.py
```

이 명령은 운영자가 argv와 반복 정책을 선택하는 generic proof 경로입니다.
위의 managed Rev proof-wave는 별도 엔진 소유 경로입니다. Reproducer는
candidate와 `accepted_input` artifact만 참조할 수 있고, runner argv,
positive/control 수, mutation 종류, network 정책은 바꿀 수 없습니다.
managed 결과는 canonical proof envelope와 여섯 run별 raw
stdout/stderr artifact pointer가 모두 맞아야 state에 반영됩니다.

Live/Builder가 등록한 workspace artifact는 mutable workspace path를 상태에
직접 신뢰하지 않습니다. regular file을 안전하게 열어 size/hash를 확인한
뒤 read-only `artifacts/snapshots/` 사본을 만들고 그 사본만 evidence로
등록합니다. Proof 입력도 evaluation 시작 시 한 번 snapshot해 SHA-256
manifest를 만들고 모든 반복 실행이 같은 bytes를 사용합니다. 각 proof
attempt의 stdout/stderr 역시 engine-managed evidence로 snapshot되며, exact
candidate가 그 durable output에 있어야 재현으로 셉니다.

여기서 “immutable”은 mode `0400`과 저장된 size/SHA-256을 evidence
검증 경계에서 다시 확인해 변조를 탐지하고 fail-closed한다는 뜻입니다.
`chattr +i`, fs-verity, 별도 Unix principal 같은 OS-level immutable
storage는 아닙니다. 같은 Unix UID는 mode를 바꿔 파일을 수정할 수 있지만
이후 hash 검증을 통과하지 못합니다.

원격 proof가 필요한 문제는 등록된 target을 함께 지정합니다.

```sh
ctfos prove \
  'Demo CTF' web 'Example' \
  --candidate CANDIDATE_ID \
  --target 'https://challenge.example:443' \
  -- python3 solve.py
```

CTF-OS는 CTF 사이트에 flag를 전송하지 않습니다. 후보를 화면에 다시
표시한 뒤 사람이 사이트에 복사해 제출합니다.

```sh
ctfos submit \
  'Demo CTF' web 'Example' \
  --candidate CANDIDATE_ID
```

사이트 응답을 확인한 뒤 결과만 기록합니다.

```sh
ctfos submit \
  'Demo CTF' web 'Example' \
  --candidate CANDIDATE_ID \
  --outcome accepted \
  --response 'correct' \
  --points 500
```

오답이면 `--outcome rejected`를 사용합니다. proof를 거치지 않고 사람이
외부에서 이미 제출한 예외만 `--allow-unproved`로 명시적으로 기록할 수
있습니다. 자동 제출 adapter, 인증정보 저장, 자동 재제출은 구현돼 있지
않습니다. 결과 기록은 contest-level submission lock 안에서 accepted flag
중복 검사, challenge revision 갱신과 contest ledger append를 직렬화하므로,
두 challenge가 같은 flag를 동시에 accepted로 기록할 수 없습니다.

## Export와 테스트

현재 상태와 Markdown 요약을 내보냅니다.

```sh
ctfos export 'Demo CTF' web 'Example'
```

저장된 canonical state와 hash-validated proof 결과만 읽어 성능을
집계할 수 있습니다.

```sh
ctfos evaluate --contest 'Demo CTF'
ctfos evaluate --contest 'Demo CTF' --category web --challenge 'Example'
```

이 명령은 model/tool/proof/submission을 새로 실행하지 않습니다.
`solve@1/3`, clean reproduction, Pwn crash gate pass rate, false proof,
proof 시간, 반복 명령, stall recovery 가용성, model usage, tool wall
time, refusal, invalid contract와 사람이 기록한 점수를 계산하며, 근거가
없는 값은 0으로 추측하지 않고 `unavailable` 또는 `partial`로 표시합니다.

`pwn_crash_gate_pass_rate`는 terminal typed Pwn gate 전체를 분모로 둡니다.
확인, 의미 오류, transport 오류, setup 실패, 독립 재검증 불가를 서로
분리하며 payload, 여섯 stdout/stderr, capability attestation과 여섯
request를 다시 읽어 판정을 재구성합니다. setup 실패와 unverifiable
terminal gate도 분모에서 빠지지 않습니다.

모델이 기록한 임의 progress marker의 최초 시간은
`time_to_first_claimed_progress`로만 집계합니다.
`time_to_first_primitive`는 engine-owned Pwn IP-control 결과 artifact를
bounded하게 다시 읽어 독립 검증할 수 있을 때만 값이 생기며, 해당 state에
그 결과가 없으면 `unavailable`입니다. 별도의 Pwn exploit-effect 게이트가
구현돼 있어도 임의 marker 문구나 `extra.engine_owned=true`는 primitive
근거로 승격되지 않습니다. 독립 재검증된 Pwn crash gate metric은
`schema_version: 3`에서 추가됐습니다. crash D→V만으로는 exploit
primitive가 아니므로 `time_to_first_primitive`의 근거가 되지 않습니다.
현재 evaluator에는 별도의 `pwn_interaction_gate_pass_rate`가 없습니다.
interaction result는 canonical fact/artifact로 보존되지만 전용 집계가
추가되기 전까지 crash pass rate나 solve로 합산하지 않습니다.

로컬 회귀 테스트:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
```

아래 역사적 동결 기록에서 사용한 수용 기준 인터프리터는 Python
`3.13.14`다. Managed Rev production
code freeze `79cbc53`에서 전체 901개 테스트가 175.985초에 통과했다(측정
wall 173.51초). deterministic remote-limiter test와 release 문서를 포함한
최종 production/test tree `abdea5b`에서도 fresh-clone의 901개 테스트,
capability, tool manifest, browser safety, Rev inventory/stdin runner와
shell/source 검증이 모두 통과했다(테스트 345.999초, 측정 wall 343.54초).
이 값은 당시 freeze의 역사적 기록이다.

Pwn D→V crash gate와 failure replay code freeze `c3de503`에서는 전체
1,010개 테스트가 218.286초에 통과했다. 같은 commit의 fresh-clone source
gate에서도 1,010개가 210.227초에 통과했고 capability contract, tool
manifest, browser safety, Pwn crash oracle 9개, Rev inventory 13개, Rev
stdin runner 17개와 shell/source 검증이 모두 통과했다. 다른 인터프리터
결과는 최종 gate에 사용하지 않는다.

core-file 비의존 Pwn observer와 address-resolution advisory를 포함한
`d3cb714` code tree에서는 전체 1,025개 테스트가 210.837초에 통과했다
(측정 wall 200.42초, exit 0). 이 수치는 실제 Docker smoke와 별개인 host
회귀 결과이며 solve 성능 측정으로 해석하지 않는다. 수용 기록 commit
`76bb84a`의 fresh clone에서도 같은 1,025개와 capability/browser/Pwn/Rev
source gate가 모두 통과했다(측정 wall 225.78초, exit 0).

Pwn runtime snapshot lifecycle/state/context를 연결한 `0456eeb`에서는
전체 1,060개 테스트가 461.378초에 통과했다. 같은 commit의 fresh-clone
source gate에서도 capability contract, tool manifest, browser safety,
Pwn crash 16개, Pwn snapshot 14개, Rev inventory 13개, Rev stdin 17개와
shell/source 검증이 모두 통과했다(측정 wall 454.71초, exit 0). 실제
Docker snapshot 3/3과 안전 probe, Pwn crash/Rev control 재검증은 exact
local image
`sha256:b35630c32f0ff00af423e81264a4ef57a56244fc5d0282d99aa505b4b9a6a5aa`
에서 별도로 통과했다.

이 테스트는 상태, 역할 계약, limiter, sandbox argv/권한, proof 정책과 CLI
동작을 검증하지만 실제 Codex 계정과 실제 대회 서버를 사용하는 end-to-end
성공을 보증하지 않습니다. Luna의 좁은 `agent.flag` model probe는 통과했지만
현재 기본값인 all-Sol 전체 solve와 실제 Sol Live TUI/native worker E2E는
호출하지 않았습니다. 이미지 내부 lifecycle은
`ctf-os-image/tests/`의 별도 테스트 대상입니다. 실제 Docker Rev proof는
opt-in `scripts/check-rev-docker-proof.py --image-digest sha256:...`로
positive 3회와 negative control 3회를 exact pinned image에서 추가 검증합니다.
실제 Docker Pwn crash proof는
`scripts/check-pwn-docker-crash.py --image-digest sha256:...`로 positive
3회와 빈 control 3회뿐 아니라 clone 추적 회피 차단, 정상 pthread,
caught/child/multithread core-stop의 fail-closed 판정까지 서로 다른 clean
workspace에서 검증합니다.
실제 Docker Pwn runtime snapshot은
`scripts/check-pwn-docker-snapshot.py --image-digest sha256:...`로
register/maps capture 3회와 descendant, shared-mm, re-exec 차단을 서로
다른 network-none clean workspace에서 검증합니다.

## 안전상 중요한 현재 제한

- Live native delegation의 개별 model call은 local FIFO limiter 밖에 있고,
  실제 계정/provider 한도에서는 provider 쪽에서 기다릴 수 있습니다.
- `declared` + Docker bridge 원격 실행은 fail-closed로 거부됩니다.
- `proxy`는 외부에서 제한된 proxy/network를 실제로 준비했을 때만
  강제 경로가 됩니다.
- `builtin`은 internal Docker network와 exact-allowlist proxy를 직접
  provision/attest합니다. Docker daemon과 upstream network 자체를 장악한
  동일 host 권한의 공격자를 막는 경계는 아닙니다.
- Live의 유일한 state/challenge-execution MCP는 required `ctfos_live`의
  열다섯 canonical operation입니다. Private mailbox path와 capability는 MCP subprocess env에만
  있고 model-visible local execution fallback은 없습니다. 부모가 canonical
  state와 Docker를 소유합니다. 다만 Codex 0.145에서 config로 제거할 수 없는
  `view_image`가 model request에 남습니다. 이는 read-only local utility이고
  외부 app/web/network egress나 command 실행 경로는 아닙니다. 그러나 legacy
  `workspace-write` filesystem sandbox에서는 추측 가능한 workspace 밖 host
  image path도 model input으로 올릴 수 있습니다. 현재 user config에
  `sandbox_mode`가 있으면 custom permission profile이 무시되고 interactive
  명령에는 Batch의 `--ignore-user-config`나 해당 값을 unset하는 방법이 없어
  강제로 닫지 못합니다. 이를 MEDIUM challenge-scope 잔여 위험으로 봅니다.
  대회 전에는 접근 가능 경로의 민감 이미지를 정리·이동해야 합니다. 별도
  `CODEX_HOME`을 쓰거나 user `sandbox_mode`를 제거해 custom profile을
  적용하는 것은 future hardening입니다. Generic MCP resource helper도
  남지만 `ctfos_live`가 resources를 구현하지 않아 list/read는 실패합니다.
  부모
  `ChallengeEngine`의 sandbox backend는 여전히 local client입니다. 별도
  권한으로 상시 운영되는 `ctfosd` lifecycle과 OS principal 분리는 기본
  운용 경로가 아닙니다. 같은 Unix UID가 raw Docker socket이나 capability
  secret을 읽지 못하게 하는 OS 경계도 제공하지 않으므로 현재 capability는
  협력적 scope 경계입니다.
- 대상 hostname별 command-start FIFO와 별도로 `builtin` proxy는 일반
  HTTP/request 및 CONNECT transaction을 target별 token bucket으로
  제한합니다. TLS tunnel을 MITM하지 않으므로 재사용된 CONNECT 내부의
  개별 HTTPS 요청은 볼 수 없으며, 그 수준의 제한은 외부 TLS-terminating
  `proxy` 정책 책임입니다.
- 8시간 예산은 Live/Batch/tool/proof의 대기와 실행에 발급 시점의 불변
  hard deadline으로 적용됩니다. `budget-reset`은 이미 발급된 `D`를
  연장하거나 단축·취소하지 않으므로 새 경계가 필요하면 기존 작업을
  중단하고 재시작/resume해야 합니다.
- background 시작은 challenge별 trusted host supervisor와 durable
  `LeaseBroker` reservation을 사용합니다. monitor가 죽어도 capacity를
  자동 재사용하지 않으며, 다음 start/list/status/recover가 exact
  supervisor label runtime을 제거한 뒤에만 orphan lease를 회수합니다.
  Docker control plane이 absence를 증명하지 못하면 `cleanup_pending`으로
  lease를 계속 잡습니다.
- 정상 timeout·cancel과 첫 `Ctrl-C`/`SystemExit`은 direct/wave Codex와
  Live TUI의 exact process group을 TERM→KILL→wait/reap하고, Docker
  daemon의 exact generated foreground container도 강제 정리합니다. 첫
  Docker cleanup 중 control interruption이 오면 같은 exact name으로 한 번
  더 시도합니다. Tool experiment/run을 실패 종결하고 proof
  input/evidence/final result를 포함해 commit되지 않은 snapshot만
  제거하며, 최종 state commit 뒤 인터럽트는 canonical evidence를
  보존합니다. 복구 중 들어오는 **두 번째 독립 control signal**,
  `SIGKILL`, 전원 단절은 이 보장 밖이라 container가 남을 수 있습니다.
  foreground에서 확인할 prefix는 `ctfos-run-`, `ctfos-init-`,
  `ctfos-proof-init-`, `ctfos-proof-`이고 이름은
  `<prefix><scope fingerprint 첫 12
  hex>-<random 12 hex>`입니다. PID-backed limiter/lease는 죽은 holder를
  회수하므로 재개 전에 exact orphan process/container를 확인·종료해야
  합니다. 이 foreground 경로는 persistent guardian 대신 one-shot
  container 수명 경계를 사용합니다. background runtime은 별도의
  `ctfos-job-` exact-name supervisor/recovery 경로를 사용합니다.
- Live `Popen` 생성은 main-thread control exception과 분리된 owner가
  CPython 3.13의 `_fork_exec` 반환→`self.pid` 게시 경계를 끝까지 소유합니다.
  정상 종료한 leader가 같은 process group의 background descendant를
  남겨도 이를 TERM→KILL→reap하고 return code 125로 fail-closed합니다.
  다만 POSIX의 숫자 PGID는 leader reap 뒤 generation-pinned handle이
  아니므로 극히 드문 host PID 재사용 경합에서는 replacement group을
  probe/signal할 수 있습니다. 이를 없애려면 Linux 6.9+ group pidfd,
  cgroup 또는 별도 supervisor가 필요해 현재 portability 범위의 P3로
  수용합니다.
- Batch wave는 executor 내부 thread registry와 별도로 callback admission과
  active 수명을 추적합니다. Gate close/cancel/drain 중 첫 control
  interruption도 완료 확인까지 재시도하므로 challenge session lock이
  worker보다 먼저 풀리지 않습니다. Live flag tailer도 stop publication과
  active callback join을 scope 종료 전에 완료합니다.
- Raw descriptor owner는 ownership을 먼저 retired/unowned로 게시하고
  lock이면 unlock한 뒤 close를 정확히 한 번만 시도합니다. close 오류 뒤
  숫자 FD의 inode를 검사·복구·재-close하지 않습니다. syscall 전에
  interruption이 오면 이미 unowned/unlocked인 FD 하나가 process exit까지
  남을 수 있지만, 같은 inode·같은 번호를 재사용한 peer FD를 잘못 닫지
  않기 위한 수용 잔여입니다.
- 설정/default 8시간 경로는 bounded wait만 사용합니다. 비정상적으로 큰
  finite public wait는 CPython `OverflowError`로 fail-closed할 수 있습니다.
- Clean proof는 pinned challenge/input, clean environment, durable evidence와
  exact output 반복을 증명합니다. 사람이 선택한 proof command의 원인성이나
  의도적으로 hardcode한 flag까지 일반적으로 판별하지는 못하며 이는
  operator trust 경계입니다.
- Managed Rev executable oracle의 현재 범위는 network-none local standalone
  Linux ELF와 stdin input 하나입니다. 원격 Rev, argv protocol, 여러 입력
  파일, non-native target과 이미지에 없는 dynamic library는 지원하지 않고
  fail-closed합니다. mutation control을 모두 거부하지 않는 의도적으로
  관대한 parser도 proof를 통과하지 못할 수 있습니다.
- Local Pwn에는 D→V crash, runtime snapshot, address-dependency L/N/A,
  IP-control primitive, one-shot 3+3 exploit-effect와 data-only dynamic
  interaction 3+3 gate가 있습니다. 실제 `zone`의
  leak→derive→staged-send 체인은 운영자 실행 증거를 parent로 삼아
  image-owned producer와 독립 evaluator에서도 attack 3/3, matched control
  3/3으로 통과했습니다. 따라서 typed interaction exploit-effect로
  기록하지만 local flag source와 active remote target이 없고 recipe/parent를
  운영자가 제공했으므로 flag/solve/remote portability나 자율 발견으로 세지
  않습니다.
  [정본 evidence pointer](ctf-reports/21-zone-solve-capable-exploit-evidence.md)를
  참고하십시오.
- Web multi-user/differential impact와 race/OOB, Crypto hidden
  metamorphic 3+3, Forensic pointer-bound assertion graph, Misc
  transform-DAG/negative-control oracle는 코드 hot path에 연결됐습니다.
  Web active release gate는 matching Docker network의 `Internal:true`를
  inspect하고, concurrent target이 같은 log line에 붙여 쓴 완전 JSON
  객체를 bounded stream으로 소비합니다. malformed/trailing/non-object,
  duplicate-key와 non-finite 값은 fail-closed합니다.
  Crypto/Misc의 hidden authority는 operator가 challenge 밖 host file에서
  Builder보다 먼저 preissue하고 engine-private artifact로 한 번만
  소비합니다. Crypto의 declared 성공 수는 여섯 physical Run의
  request/result/validation과 stdout/stderr provenance에 일치해야 합니다.
  `d550df15b13b47304872300989e6beeb94c93701`의 actual pinned Docker gate는
  42.122초에 Python/Sage 각각 physical 6/6을 통과했고 hostile
  sidecar·stdout replacement를 거부했습니다.
  `3726adb` Rev, `c690af0` Misc, `cf155cc` Web, `1c82147` Pwn dependency,
  `c9eee37` Pwn interaction과 `7c3d604`/`5e88071` Forensic release
  validation은 physical sidecar·artifact·receipt와 exact schema를 재검증하고
  hostile rewrite/deletion/reuse를 fail-closed합니다.
  `d2fb1130b147605ca5d829ff7d20946fb2f3e41f`는 promotion prepare에서
  prompt/description/category와 fresh incoming manifest/files/count/bytes,
  static source를 schema-v1 operator input으로 결속하고 launch/provider,
  finalize/capture/bundle verification에서 재확인하며 paired arms의 동일성을
  강제합니다. focused 74/74는 통과했지만 실제 blind/live cohort 결과는
  아닙니다. 현재 source의 최종 전체 회귀, clean Docker matrix와
  `ctfos doctor`가 끝나기 전에는 이 구현 상태를 release acceptance나 solve
  성능으로 확대하지 않습니다.
- image digest가 설정되지 않아도 실행은 가능하며 `doctor`가 경고합니다.
- `work_tree_max_bytes`와 문제별 누적 storage quota는 커널 filesystem
  quota가 아닙니다. 한 명령이 실행 중에 상한을 일시 초과할 수 있으며,
  문제 root control file과 contest 공용 `submissions.jsonl`은 문제별
  quota에 포함되지 않습니다. 보존 root인 `runtime/`, `context/`,
  `knowledge/`, `exports/`의 byte는 quota에는 포함하지만 GC/purge에는
  포함하지 않습니다. Work-tree와 누적 storage scan은 entry/byte 한계에서
  즉시 중단하고 불완전한 계측을 통과로 해석하지 않습니다. GC는 자동
  retention이 아니라 운영자가 문제별로 명시하는 가역 quarantine입니다.
- 자동 제출은 없습니다.

이 제한을 포함한 요구사항 판정 이력은
[12. 수용성 기록](ctf-reports/12-final-acceptance.md), 상세 구현은
[10. 구현 결과](ctf-reports/10-implementation-result.md)를 기준으로
판단하십시오.
