# CTF-OS 구현 결과

> 상태: 2026-07-28 코드 기준 as-built 정본  
> 범위: 저장소 루트의 `ctf_os/`, `tests/`, `pyproject.toml`과
> `ctf-os-image/` 연동 경계  
> 운영 방법: 저장소 루트의 [README](../README.md)  
> 요구사항 판정: [12 최종 수용성 기록](12-final-acceptance.md)  
> 설계 근거: [09 구현 설계도](09-implementation-blueprint.md)

이 문서는 09의 목표를 현재 코드가 어디까지 구현했는지 기록한다. 09는 설계
근거와 장기 방향이다. 충돌 시 현재 코드와 통과한 회귀, 12의 요구사항
판정, 이 문서, 09의 역사적 설계 순으로 따른다. 기능 이름이나 파일이
존재한다는 이유만으로 end-to-end 완료로 표시하지 않았다.

## 1. 확정된 운영 계약

사용자와 확정한 계약은 다음과 같다.

- 대회 문제를 자동 선택하거나 우선순위를 매기는 스케줄러를 두지 않는다.
- 사람이 문제를 고르고 폴더를 만들고, 파일을 다운로드하고, 문제풀이
  프롬프트를 준다.
- 프롬프트에는 계정, 세션 cookie, API key 같은 자격증명을 넣지 않는다.
  model/log 비노출 typed secret channel은 현재 구현돼 있지 않다.
- Live와 Deterministic Batch를 둘 다 제공한다.
- 각 문제 wave의 논리 역할 세 개는 유지한다. 실제 provider 호출은 계정
  한도에서 기다릴 수 있지만 역할을 삭제하거나 wave를 좁히지 않는다.
- 설정 기본 model ID는 역할별로 Sol/Terra/Luna에 라우팅한다. 실제
  `gpt-5.6-luna`의 좁은 Live MCP `agent.flag` 경로는 검증했지만 실제 계정의
  세 모델 전체 solve end-to-end는 아직 검증하지 않았다.
- bounded scanner가 예상 플래그를 관측하면 발견 즉시 터미널에
  `FLAG CANDIDATE (미제출)`로 표시한다.
- CTF 사이트 제출은 사람이 한다. 자동 제출과 자격증명 저장은 없다.
- 사람은 원할 때 다른 문제의 풀이 세션을 추가한다.
- 국내 대회 운용의 문제 예산은 사람이 명시적으로 초기화하며 기본 명령값은
  8시간이다.

이 중 Batch 모델 대기와 역할 폭은 하드 강제된다. Live 내부 native
delegation은 Codex 프로세스 안에서 일어나므로 CTF-OS의 local FIFO를
개별 subcall에 적용할 수 없다. 실제 호출은 계정/provider 한도에서
Codex/provider가 대기시킬 수 있다. 이 차이는 §5에 적었다.

## 2. 실제 실행 구조

```text
Human
  ├─ incoming/<contest>/<category>/<challenge>/ 에 파일 배치
  ├─ ctfos solve ...          → parent session owner + interactive Live Captain
  ├─ ctfos run-challenge ...  → Captain + 3-role Batch wave
  └─ CTF 사이트에 직접 flag 제출

Challenge Engine
  ├─ StateStore               → 문제별 단일 writer
  ├─ required ctfos_live MCP  → 14 canonical state/challenge-execution operation
  ├─ Codex Live/Batch         → configured Sol/Terra/Luna 역할
  ├─ Sandbox client/backend   → 문제별 Docker tool runtime
  ├─ Resource/Model limiter   → host tool + Batch provider 대기
  └─ Proof/manual submission  → clean proof와 사람 결과 기록
```

엔진 단위는 `contest/category/challenge`로 식별되는 문제 하나다. 서로 다른
문제는 별도 `runtime/session.lock`을 가지므로 여러 터미널에서 병행할 수
있다. 같은 문제에는 한 시점에 Live 또는 Batch 소유자 하나만 허용한다.

대회 전체를 순회하거나 다음 문제로 자동 전환하는 CLI는 없다. 사람은 풀
문제마다 `solve` 또는 `run-challenge`를 명시적으로 실행한다.

## 3. 구현 상태 요약

| 영역 | 상태 | 현재 구현 |
|---|---|---|
| 문제 입력과 ingest | 구현 | 사람이 만든 `incoming/` 폴더, deterministic inventory, SHA-256 manifest, symlink/special-file 거부 |
| 파일 상태 | 구현 | `state.json`, `state.prev.json`, revision CAS, `flock`, temp + `fsync` + `os.replace`, 이전 상태 복구 |
| 상태 모델 | 구현 | 단일 active goal/dependency, fact provenance, typed hypothesis/falsifier, experiment 실행 후 명시적 evaluation, progress, budget, candidate, submission, run/artifact 참조 |
| 파생 뷰 | 구현 | `context/current.md`, `board.md`, `board.json`, exports |
| Live | 구현(잔여 위험 명시) | network-none light lease로 fresh `/work` 초기화, external app/web/network/host shell 차단, required `ctfos_live`가 유일한 state/challenge-execution MCP로 14 canonical operation 제공(전체 built-in tool 수가 아님), capability/path는 MCP env에만 전달, `agents.enabled=true` + `features.multi_agent=true`로 native 3-worker 구성 유지, 장기 tool lane과 flag fast-path 분리, bounded inspect pagination, 부모가 session lock/state/Docker와 private mailbox broker 소유. `view_image` host-path 잔여 위험과 실제 계정 Sol TUI/native 3-worker E2E는 검증 범위 밖 |
| Batch | 구현 | Captain 후 3-role wave, external/app/web/shell 차단, user config/rules ignore와 `agents.enabled=false` + `features.multi_agent=false`로 중첩 delegation 차단, strict output schema, 재시도, JSONL/usage/refusal 수집, cross-process FIFO provider limiter, bounded raw/capture metadata, wave-scoped process-group cancellation. 한 model item의 잘못된 semantic ID는 그 item만 rollback·진단하고 나머지 결과를 보존 |
| 모델 라우팅 | 구현 | 역할별 configured Sol/Terra/Luna model ID와 ultra/max 설정. 실제 `gpt-5.6-luna`의 required MCP `agent.flag` 전달은 검증, 실제 계정 세 모델 전체 solve E2E는 미검증 |
| 도구 자원 리스 | 구현 | CPU/RAM/GPU/KVM/network 자원 벡터, FIFO, 프로세스 사망 회수, engine bundle 원자 발급, 같은 vector를 Docker limits에 결속 |
| sandbox foreground | 구현 | one-shot `docker run --rm`, lease와 같은 `--cpus/--memory`, 요청 시에만 GPU/KVM detection·device, `/challenge:ro`, `/work:rw`, timeout과 정상 `BaseException`의 exact generated container cleanup+원 예외 보존, stream당 기본 16 MiB raw prefix와 실제 tail·capture completeness metadata, configurable `/work` 전후 안정 scan cap |
| sandbox background | 비활성 | image primitive와 typed interface는 있으나 모든 실제 `start_job` 경로가 lease supervisor 부재로 명시적 거부 |
| 네트워크 기본 거부 | 구현 | target이 없으면 Docker `none`, 명령의 target과 문제 allowlist 대조 |
| 네트워크 목적지 강제 | 부분 구현 | declared bridge 실행은 fail-closed; 외부 제한 proxy/network는 운영자가 준비해야 함 |
| host별 remote 제한 | 부분 구현 | 정규화 hostname별 cross-process FIFO가 tool/proof command의 실제 시작을 기본 1초 간격화. command 내부 HTTP 요청 수/token bucket과 실제 egress는 외부 제한 proxy 책임 |
| flag 즉시 표시 | 구현 | Batch/tool/proof stream 후보는 bounded fsynced intent journal에 먼저 기록한 뒤 stderr flush하고 정상 single commit 후 clear. Proof는 일반 `/work` 밖 private sibling의 live raw/sidecar를 실행 중 tail하고 final sidecar를 bounded 보존한다. Growing sidecar와 final copy는 각각 독립 1 MiB 물리 read budget을 가진다. crash-left intent는 다음 session lock에서 먼저 재출력한 뒤 멱등 reconcile해 누락보다 중복을 우선. Live `agent.flag`는 canonical commit 후 출력. 후보/문자/sidecar 상한과 incomplete capture 이후 bytes는 보장 밖 |
| artifact/proof evidence | 구현 | model-writable workspace artifact의 engine-managed read-only/hash-validated snapshot, tool stdout evidence와 terminal source-run 결속, proof 입력 1회 snapshot+manifest, attempt별 stdout/stderr evidence snapshot, 새 proof workdir, 반복/분포 정책과 exact candidate. snapshot/result commit 실패 시 생성된 evidence를 정리하며 OS-level immutable storage는 아님 |
| 제출 | 구현(수동만) | candidate preview, 사람이 제출한 accepted/rejected/error/dry_run 결과, contest lock 안의 중복 accepted 검사·challenge CAS·contest-wide 이력 직렬화 |
| 자동 제출 | 비목표 | CTFd adapter, credential 저장, 자동 POST 없음 |
| pause/resume | 구현 | `PAUSED`에 이전 상태를 `resume_status`로 보존, `NEEDS_HUMAN → ACTIVE` 허용 |
| 8시간 예산 reset | 구현 | 상태 회계와 절대 deadline 초기화. 이후 발급되는 Live/Batch/tool/proof 작업의 불변 monotonic `D`와 capability TTL을 남은 시간으로 clamp한다. Batch wave는 context 준비 전 공통 `D`, Live는 `Popen` 전 `D`, tool/proof는 evidence와 locked success eligibility까지 같은 `D`를 유지한다. Reset은 이미 발급된 `D`를 연장·단축·취소하지 않는다 |
| stall/recovery governor | 구현 | 최근 N개의 반복 명령·동일 failure·새 증거 부재·artifact churn을 bounded 판정해 `ACTIVE → STALLED`; 복구 사다리의 제안 하나만 기록하고 자동 실행하지 않음 |
| 카테고리 adapter | 구현(명시 실행) | guidance, progress/failure labels, proof policy와 deterministic initial observation 등록. seed는 사람이/model이 명시 선택할 때만 실행하며 자동 stage scheduler는 두지 않음 |
| 지식 retrieval | 구현(운영자 주입) | 논문 전문·공식 사양·GitHub 소스의 immutable bounded copy, SHA-256, query-aware context excerpt와 Live read-only `knowledge.search`/64 KiB `knowledge.read`. 모든 접근에서 hash/size 재검증. 엔진의 임의 다운로드나 credential URL은 없음 |
| 평가 harness | 구현(읽기 전용 집계) | canonical state와 hash-validated proof만 읽어 solve@1/3, clean/false proof, 시간·반복·사용량·refusal·점수를 집계하고 근거 부재는 partial/unavailable로 표시. 모델 실행과 L2/L3 세션 개시는 사람이 함 |
| Live broker / `ctfosd` 경계 | Attached 경로 구현 | Live model은 shell 없이 required MCP만 사용하고 mailbox/capability를 보지 못함. 부모 engine이 local sandbox client를 소유하며 persistent·별도 권한 `ctfosd` 배포는 선택적 OS hardening으로 남음 |

## 4. CLI as-built

### 운영자 명령

| 명령 | 동작 |
|---|---|
| `ctfos init` | `.ctfos/engine.toml` 생성 |
| `ctfos pin-image` | 현재 tool image의 exact local image ID를 설정에 원자적으로 고정 |
| `ctfos doctor [--calibrate]` | 호스트와 정책을 읽기 전용 진단 |
| `ctfos add-challenge CONTEST CATEGORY CHALLENGE` | 입력 폴더·상태·초기 goal 생성 |
| `ctfos add-target ... TARGET` | 문제별 원격 target 등록 |
| `ctfos knowledge add/list/search ...` | 사람이 검토한 원문·소스의 immutable hash 보관과 local 검색 |
| `ctfos solve ... [PROMPT]` | Live workspace와 broker를 준비한 뒤 interactive Captain 시작 또는 thread resume. 초기화와 model 호출은 대기 가능 |
| `ctfos run-challenge ...` | deterministic Batch cycle 실행 |
| `ctfos wave ... discovery\|attack\|proof` | 세 역할 wave 한 번 실행 |
| `ctfos status [CONTEST] [--watch]` | board 조회 |
| `ctfos inspect ... SECTION [--offset N --limit N]` | 정본 상태의 bounded summary/section/page 조회 |
| `ctfos evaluate [--contest ...]` | 저장된 canonical evidence의 결정론적 성능 집계; 새 실행 없음 |
| `ctfos leases [--json]` | tool 자원과 Batch provider 대기 상태 |
| `ctfos pause/resume ...` | 문제 세션 상태 보존/복귀 |
| `ctfos budget-reset ... [--seconds N]` | 명시적 문제 예산 초기화, 기본 28,800초 |
| `ctfos prove ... --candidate ID -- COMMAND` | clean proof 실행 |
| `ctfos submit ... --candidate ID` | candidate 표시, 자동 전송 없음 |
| `ctfos submit ... --outcome ...` | 사람이 확인한 사이트 응답 기록 |
| `ctfos export ...` | canonical JSON과 Markdown summary 생성 |
| `ctfos tool run ... [--profile ...] [--kvm] -- COMMAND` | 사전 등록 후 lease와 Docker limits가 결속된 foreground sandbox command 실행 |
| `ctfos jobs ...` | 기존 scoped job 목록을 제한적으로 조회. 조회 때문에 persistent container를 만들지 않음 |

설치되는 저수준 `ctf-container`와 구형 `ctf_os.agent_tools solve`는 기존
자동화 호환 동작을 보존한다. 각각 기본 Docker bridge와 raw Codex 실행을
사용하므로 untrusted contest hot path가 아니며 대회 문제에는 사용하지
않는다. 이 문서의 보안 계약은 `ctfos` 경로에 적용된다.

### Model surface와 운영자 호환 명령

Live model의 state/challenge-execution surface는 CLI command가 아니라 required
`ctfos_live` MCP의 `agent.flag`, `agent.fact`, `agent.goal`,
`agent.hypothesis`, `agent.experiment`, `agent.evaluate`, `agent.artifact`,
`agent.progress`, `agent.transition`, `tool.run`, `jobs`, `inspect`,
`knowledge.search`, `knowledge.read`다. MCP
bridge가 immutable challenge identity와 exact
scope capability로 typed 요청을 전달하며 모델은 `state.json`을 직접
편집하지 않는다. `ctfos agent ...` 등의 기존 CLI는 사람의 terminal과 하위
호환 테스트를 위해 남아 있다.

Workspace artifact는 path와 현재 hash만 상태에 연결하지 않는다. Challenge
workspace 안의 bounded regular file을 안전하게 열어 SHA-256/size를
검증하고 read-only canonical snapshot을 만든 뒤 그 snapshot을 등록한다.

## 5. 모델 호출과 세션 계약

### 5.0 공통 model tool 격리

Live와 Batch start/resume는 strict config로 host shell과
`exec_command`/`write_stdin`을 끄고 `web_search="disabled"`를 고정한다.
Apps와 기본 app open-world/write, plugins/remote-plugin, tool suggestion,
browser/computer-use, image-generation, hooks와 user MCP도 명시적으로
끈다. `mcp_servers={}`만으로 account-managed app/web surface가 사라진다고
가정하지 않는다.

Production-model request에는 이와 별도로 `exec`, `wait`, `apply_patch`,
native collaboration, `tool_search`, `view_image`, plan/user-input과 generic
MCP resource helper가 남는다. `exec`는 filesystem/network API가 없는 V8
orchestration이고 `apply_patch`는 challenge workspace writer다. 둘을
`exec_command`나 임의 host shell과 동일시하지 않는다. `tool_search`는
strict 구성에서 `ctfos_live`만 안내하며 app surface를 다시 열지 않는다.

Batch는 `--ignore-user-config`, `--ignore-rules`,
`agents.enabled=false`, `features.multi_agent=false`를 함께 적용한다.
Live는 문제별 세 논리 역할을 위해 `agents.enabled=true`와
`features.multi_agent=true`를 함께 고정한 뒤 required `ctfos_live`를
추가한다. 전자는 세 외부 Batch 역할 내부의 중첩 delegation과 비용 확장을
막고, 후자는 명시한 세 native worker 구성이 꺼지지 않도록 한다.

### 5.1 Batch

설정 기본값은 문제당 worker 세 개와 전역 provider 호출 네 개다.

```text
Captain 1
Discovery: Recon + Specialist + Extractor
Attack:    Builder + Falsifier + Reproducer
Proof:     Validator + Reproducer + Evidence Auditor
```

Captain과 그 문제의 worker wave는 겹치지 않는다. wave 세 역할은 먼저
논리적으로 모두 생성된 후 실제 `codex exec` 호출이
`FileFifoModelCallLimiter`의 cross-process FIFO slot을 얻는다. 상한이
작아져도 역할 목록과 wave 폭은 바뀌지 않는다. 죽은 process의 queue/holder
기록은 PID와 process start ticks로 회수한다.

Batch model은 위 공통 격리, user config/rules ignore와 두 multi-agent
false 설정 때문에 host shell·외부 tool·임의 MCP로 untrusted challenge를
실행하거나 세 외부 논리 역할 밖으로 중첩 위임하지 않고 구조화된 제안만
반환한다. Subprocess runner는
stdin을 nonblocking chunk writer로 보내면서 stdout/stderr를 동시에 drain해
양방향 pipe deadlock을 피한다. Timeout, output callback 오류,
`KeyboardInterrupt` 또는 wave 취소 시 active process group 전체를
TERM→KILL→reap하고 provider FIFO waiter와 아직 시작하지 않은 future도
취소한다.

`run-challenge`와 `wave`는 canonical state의 사람 문제풀이 프롬프트가
비어 있으면 model call 전에 실패한다. 대회/board를 훑어 다음 문제를
자동으로 여는 경로는 없다.

`CTFOS_MODEL_CONCURRENCY`는 provider 상한을 override하지만 양의 정수만
허용한다. `ctfos leases`는 현재 active/waiting과 논리 폭을 따로 보여준다.
이 상한은 운영자가 설정한 local concurrency guard다. CTF-OS가 구독 플랜의
실제 quota를 조회하거나 provider의 동적 rate limit을 자동 추론하지는
않는다.

### 5.2 Live

Live는 Captain 1 + Recon/Specialist/Falsifier 세 논리 역할,
`agents.enabled=true`, `features.multi_agent=true`와
`agents.max_concurrent_threads_per_session=4`를 Codex CLI에 전달한다. 두
enable 값을 함께 고정하므로 세 native worker 구성은 비활성화되지 않는다.
문제별 AGENTS/Live 지침은 기다리는 역할을 삭제·병합하지 않고 plausible
flag마다 즉시 `ctfos_live`의 `agent.flag`를 호출하라고 요구한다. 단순
terminal 출력만 하는 것은 허용된 완료 경로가 아니며 broker가 후보를
canonical state에 영속하고 즉시 stderr에 출력·flush한다. 자동 제출은 하지
않는다.

`ctfos solve` 부모는 TUI lifetime 동안 문제별 `session.lock`과 canonical
state/Docker 권한을 보유한다. Live start와 resume는 모두
`features.shell_tool=false`로 host shell을 끄고 `mcp_servers={}`로 user MCP를
지운 뒤, required `ctfos_live` stdio server 하나만 등록한다. Server command는
PATH basename이 아니라 현재 CTF-OS interpreter의 검증된 절대 경로이고 argv는
`-I -m ctf_os.live_mcp`다. `enabled_tools`는 다음 열네 개로 고정한다.

```text
agent.flag  agent.fact  agent.goal  agent.hypothesis
agent.experiment  agent.evaluate  agent.artifact
agent.progress  agent.transition  tool.run  jobs  inspect
knowledge.search  knowledge.read
```

이 열네 개는 `ctfos_live` MCP의 canonical state/challenge-execution
operation 수다. 위에 열거한 Codex built-in을 포함한 전체 production tool
inventory가 아니다.

이 allowlist는 명시적으로 승인되지만 `agent.transition`은 운영 상태만
노출하고 `PROVING`, `READY_TO_SUBMIT`, `SOLVED`, `NEW`를 받지 않는다.
`agent.goal`은 단일 active goal을, `agent.hypothesis`는 falsifier와 typed
evidence를, `agent.evaluate`는 실행 뒤 `AWAITING_EVALUATION`인 실험의
keep/drop/inconclusive 판정을 관리한다. Challenge data 실행은 `tool.run`이
문제별 sandbox에서만 수행한다. Command network는
`sandbox_workspace_write.network_access=false`다.

부모는 canonical runtime 아래 `live-mailboxes/session-*`에 mode `0700`의
private mailbox를 만들지만, 그 path나 capability를 model argv, prompt,
shell environment 또는 `--add-dir`에 넣지 않는다. Session marker, exact
mailbox path와 scope capability는 required MCP subprocess의 explicit
`env_vars`에만 전달한다. MCP는 함께 받은 challenge identity를 요청마다
고정한다. MCP startup이나 scope 환경이 불완전하면 Live는 실패하며
model-visible local engine/host 실행 fallback은 없다.

MCP stdin/stdout과 broker request/response는 각각 최대 1 MiB다. MCP bridge는
immutable environment identity를 붙여 열네 operation만
`LiveBrokerClient`로 전달한다. Broker 파일 쓰기는 private temporary file에
완료한 뒤 file과 directory를 `fsync`하고 같은 dirfd 안에서 `os.replace`한다.
Parent와 client 모두 directory file descriptor에 anchor하고 `O_NOFOLLOW`,
regular file, 현재 owner, `st_nlink == 1`, 읽기 전후 size/mtime과 실제 read
size의 안정성을 검사한다. 부모는 exact session capability, scope, identity와
operation allowlist를 확인한다. 일반 operation은 bounded 단일 executor
lane에서 순서대로 처리하지만 `agent.flag`는 긴 `tool.run`에 막히지 않는
fast-path로 durable state commit과 즉시 출력을 수행한다. 종료 시 active
operation이 반환될 때까지 broker thread/executor를 join한 뒤
`session.lock`을 해제한다.

`inspect summary`는 작은 고정 크기 상태 개요를 반환한다. 작은 기존 section은
raw list/dict 호환을 유지하지만 큰 state/list는 768 KiB 이전에 summary 또는
`offset`/`limit`/`total`/`next_offset` page envelope로 전환한다. page는 최대
200개이고 단일 초대형 record도 deterministic bounded stub으로 대체된다.

`knowledge.search`와 `knowledge.read`는 운영자가 미리 넣은 문제별 문서만
읽는다. Search는 provenance와 bounded excerpt를, read는 UTF-8 byte offset과
최대 64 KiB의 다음 chunk를 반환한다. 원본과 추출 text의 size/SHA-256을
매번 다시 검증하며 URL fetch나 credential 전달은 없다. Batch context도
사람 프롬프트, active goal, 열린 hypothesis/falsifier와 맞는 구간을
결정적으로 선택한다.

수락한 request ID는 세션 안에서 최대 16,384개까지 유지하므로 같은 ID의
mutating operation은 at-most-once dispatch된다. 각 string-array parameter는
최대 4,096 item, item당 64 KiB, 합계 512 KiB이며 operation timeout은 최대
28,800초다. Client wait에는 최대 180초의 종료 grace만 더한다. 개별
malformed/hostile request와 response entry 오류는 가능한 한 request별
bounded error로 격리해 watcher를 유지한다. Mailbox entry가 4,096개를
초과하거나 request failure도 안전하게 게시하지 못하면 server status를
terminal error로 바꾸고 client가 명시적으로 실패하므로 silent starvation이
되지 않는다.

Cleanup은 최대 scan entry까지만 재귀 없이 수행하고 model이 만든 하위
디렉터리나 잔여 entry가 있으면 private leaf를 강제 삭제하지 않는다.

`solve`, `run-challenge`, 직접 `update_prompt`와 기존 문제의
`add-challenge --prompt`가 전달받은 새 prompt는
`runtime/session.lock`을 획득한 뒤 commit한다. 이미 owner가 있어 경쟁
호출이 `SessionAlreadyRunning`으로 끝나면 기존 prompt, revision과
canonical state bytes가 그대로인 회귀를 둔다. 이 보장은 prompt update에
한정하며 target·knowledge·budget 등 operator configuration mutation 전체를
session-owned라고 주장하지 않는다.

회귀 테스트는 isolated MCP process의 initialize/tool-list와 실제
`agent.flag` call이 mailbox broker를 거쳐 parent dispatch, 즉시 출력,
state 영속과 cleanup까지 완료되는 경로를 검증한다. 이것은 typed MCP
transport의 증거지만 실제 계정의 Sol interactive TUI 전체와 native 세
worker 병렬 시작·완료 증거는 아니다.

별도 production-model mock Responses request 캡처에서 external
app/web/network, `request_plugin_install`,
`exec_command`/`write_stdin`/shell tool은 0개였다. 남은 production
built-in inventory는 §5.0과 같고, `ctfos_live`는 resources를 구현하지
않으므로 generic resource list/read는 실패한다.
`view_image`는 외부 app/web/network egress나 command 실행 경로가 아니다.
그러나 Codex 0.145 legacy `workspace-write` filesystem sandbox에서는 추측
가능한 workspace 밖 host image path를 model input으로 올릴 수 있다. 현재
user config의 `sandbox_mode`가 custom permission profile을 무시하고,
interactive에는 `--ignore-user-config`나 해당 값을 unset하는 방법이 없어
현재 command builder가 강제로 닫을 수 없다. 이는 MEDIUM challenge-scope
잔여 위험이다. 대회 전 접근 가능 경로의 민감 이미지를 정리·이동해야 한다.
별도 `CODEX_HOME` 또는 user `sandbox_mode` 제거 후 custom profile 적용은
future hardening이다. 따라서 “모델에 열네 tool만 보인다”가 아니라 “유일한
state/challenge-execution MCP가 열네 canonical operation만 제공한다”가
정확한 보장이다.

하지만 native subagent는 interactive Codex 내부에서 생성된다. CTF-OS는
각 subcall을 감싸는 local provider FIFO lease를 발급하거나 실제 동시 호출
수를 완전히 관측할 API가 없다. Native call은 실제 계정/provider 한도에서
Codex/provider가 대기시킬 수 있다. 따라서 다음을 구분해야 한다.

- **강제됨:** 같은 문제의 Live/Batch 동시 소유 금지, logical role 선언,
  max thread 설정과 workspace scope. 서로 다른 문제의 세션 수와 시작은
  사람이 결정한다.
- **강제되지 않음:** Live 내부 subcall 각각에 대한 CTF-OS local FIFO와
  역할별 실제 시작 시점, 실제 계정에서 configured model TUI가 성공한다는
  보장.

즉시 session을 요청할 수 있다는 것과 세 native worker가 즉시 동시에
시작한다는 것은 같은 보장이 아니다. Batch provider limiter의 존재를
근거로 Live까지 local FIFO로 완전 강제된다고 주장하면 안 된다.

## 6. 상태와 복구

실제 상태 구조는 category 중복 문제명을 구분하도록 09보다 한 단계 더
namespaced돼 있다.

```text
.ctfos/
  engine.toml
  runtime/
    model-calls.json
    tool-leases/
  contests/<contest>/
    contest.json
    board.md
    board.json
    submissions.jsonl
    runtime/
    challenges/<category>/<challenge>/
      state.json
      state.prev.json
      events.jsonl
      .lock
      runtime/
        session.lock
        delegation-owner.json
      context/
        current.md
        history/
      runs/<run-id>/
        request.json
        result.json
        validation.json
        raw/
      artifacts/
        workspace/
        snapshots/
      knowledge/
      proof/<candidate>/<evaluation>/
        input-manifest.json
        inputs/
        evidence/<run-id>/
      exports/
```

문제의 구조화 상태와 상태 전이 정본은 `state.json`이다. 저장은 현재
revision 확인, 참조·artifact 검증, 이전 bytes의 원자적
`state.prev.json` 보존, 새 상태의 flush/fsync와 `os.replace`, event/view
갱신 순서다. event나 Markdown 갱신 실패는 이미 교체된 state를 rollback하지
않는다. 현재 상태가 읽히지 않으면 lock 안에서 다시 확인한 뒤 온전한
previous image를 복구한다.

문제 루트 `.lock`은 이 state CAS와 복구 동안만 잡는 짧은 mutex다. 같은
문제의 Live/Batch/tool/proof owner 수명은 `runtime/session.lock`이 배제한다.
`runtime/delegation-owner.json`은 Live native owner 진단 marker이며 lock,
lease 또는 권한 정본이 아니다.

Canonical state JSON은 안정된 regular-file 읽기와 쓰기 모두 16 MiB로
제한한다. `source_inventory`, goal/fact/hypothesis/experiment/progress,
candidate/submission/artifact/run 같은 최상위 typed collection과 알려진
nested repeated-ID field는 각각 16,384개까지다. 모든 state commit은
참조된 canonical artifact의 **실제 파일 크기 합계**가
`runtime.work_tree_max_bytes` 이하인지 검사하며, digest 재검증을 생략하는
내부 commit 경로에도 이 합계 cap은 적용한다.

Hash가 등록된 artifact/proof bytes는 상태 판단의 canonical evidence이고,
contest `submissions.jsonl`은 사람이 기록한 결과와 accepted flag의 대회
전체 중복 판정에 쓰는 durable ledger다. 이 둘은 state에서 다시 만드는
Markdown/event 파생 뷰가 아니다.

Model-writable `artifacts/workspace/`의 file은 evidence reference로 바로
등록하지 않는다. Sandbox가 반환한 scope, locator, size와 SHA-256을 확인하고
symlink/special file을 거부한 뒤 `artifacts/snapshots/`에 mode `0400`의
bounded copy를 원자적으로 설치한다. 이후 workspace 원본이 바뀌어도
등록된 snapshot의 locator/hash는 workspace 원본을 따라 바뀌지 않는다.

Proof는 evaluation 시작 시 모든 input locator를 한 번만 snapshot하고
`input-manifest.json`의 path/hash를 모든 반복 run request/result와
environment에 기록한다. 각 clean container는 같은 snapshot의 size/hash를
재검증해 mount한다. Attempt별 stdout/stderr도 canonical
`evidence/<run-id>/`에 engine-managed snapshot하며, exact candidate가 durable
evidence에 있어야 재현으로 계산한다. 같은 candidate를 다시 proof해도 새
evaluation directory를 쓰므로 이전 result/evidence를 덮어쓰지 않는다.

이 문서에서 “immutable”은 mode `0400`과 저장된 size/SHA-256의 재검증으로
변조를 탐지하고 fail-closed하는 tamper-evident 보관을 뜻한다. `chattr +i`,
fs-verity나 별도 Unix principal이 같은 UID의 쓰기를 OS에서 막는다는 뜻은
아니다. 같은 UID가 mode를 바꿔 bytes를 수정할 수는 있지만 이후 검증을
통과하지 못한다.

provenance 정본은 다음 다섯 값이다.

```text
executed
tool_inferred
model_claimed
external_doc
operator
```

구버전 `tool-inferred`, `model-claimed`와 이전 필드명은 load 시 upgrade한다.
`model_claimed` fact만으로 hypothesis를 confirmed로 만들 수 없다.
Goal create/activate/complete/block/park는 한 active goal 불변식을 유지한다.
Hypothesis의 non-open 전이와 실행 뒤 experiment evaluation은 canonical
fact/artifact/run evidence chain을 다시 검증한다. 성공 exit만으로 실험을
확정하지 않고 먼저 `AWAITING_EVALUATION`에 둔다.

Governor는 최근 기본 3개 기록에서 반복 command, 동일 failure label, 새
fact/artifact/progress 부재, 동일 locator의 artifact churn을 bounded하게
검사한다. threshold에 걸리면 `ACTIVE → STALLED`와 recovery 사다리의 제안
하나만 정본에 기록한다. 제안을 실행 완료로 오인해 자동 승격하지 않고,
model/tool/scheduler/session을 자동 시작하지 않는다. Batch loop도 STALLED
이후 다음 cycle을 열지 않는다.

## 7. Sandbox와 네트워크의 정확한 보장

### 7.1 구현된 경계

- challenge identity와 host path를 한 번 고정한 scope
- 원본 `/challenge` read-only, 분석 `/work` read-write
- 다른 문제의 job/artifact reference 거부
- 기본 network `none`
- command argv, timeout, 환경변수, 출력 크기 제한
- configurable `/work` logical-size cap의 descriptor-anchored 안정된 명령
  전후 scan. symlink 비추적, sparse/hardlink 보수 회계
- Docker `no-new-privileges`, 기본 capability drop, PID/shm 제한
- tool profile의 lease vector와 같은 Docker `--cpus/--memory`
- GPU/KVM은 해당 lease를 요청하고 required host detection이 성공할 때만
  GPU flags 또는 `/dev/kvm` 추가
- foreground마다 one-shot `docker run --rm` PID 1 lifetime 감독
- Docker control timeout 때 scope fingerprint와 random nonce로 미리 만든
  exact ephemeral container name 하나만 `docker container rm --force`로
  best-effort 정리하고 실패 detail을 timeout error에 포함. glob·prefix sweep
  없음
- clean proof마다 새 temporary workdir

Batch model attempt는 stdout JSONL과 stderr pipe를 끝까지 drain한다. stdout
JSONL은 모든 chunk에서 flag pattern을 rolling scan하지만 파일 보존은
JSONL raw prefix 16 MiB, stderr prefix 1 MiB로 제한한다. structured result는
2 MiB를 넘으면 contract invalid다. attempt별 `*-capture.json`에는
total/stored/limit, truncated, oversized event/result와 drop/suppressed
count가 남는다.

Foreground `ctfwrap`도 stdout/stderr를 모두 EOF까지 drain하되 raw log에는
stream당 기본 16 MiB prefix만 저장한다. 각 stream의 실제 마지막 4 KiB를
summary tail로 유지하고 `stream-capture.json`, `result.json`, `meta.json`에
total/stored/limit, `truncation_known`, `truncated`와 `capture_complete`를
기록한다. 동시에 `runtime.flag_patterns`를 전체 drain stream에 rolling
적용하고, 후보 1,024개·총 256 KiB 문자·파일 1 MiB 상한의
`flag-candidates.jsonl`을 만든다. 호스트 tailer는 이 regular file을 raw
prefix 예산과 별도로 읽어 중간에서만 관측된 후보도 즉시 출력한다. 따라서
raw log path가 완전한 무제한 원출력을 뜻하지 않지만, 저장 truncation
자체가 flag candidate 탐지를 끊지는 않는다.

기본 `runtime.work_tree_max_bytes`는 16 GiB다. stream, artifact와 proof
개별 copy 상한도 이 값 아래로 결속된다. 이 guard는 명령 전후의 안정 scan이지
kernel project quota가 아니므로 실행 중 transient overshoot를 매 write마다
차단한다고 주장하지 않는다.

이 값과 canonical artifact 합계 cap은 challenge directory 전체의 보존량
quota가 아니다. 누적 `runs/` raw, contest `submissions.jsonl`과 전체
challenge tree에는 별도 총량 cap, retention policy나 GC가 구현돼 있지
않다. 장시간 대회에서는 운영자가 filesystem 여유를 별도로 감시해야 한다.

profile의 결속값은 다음과 같다.

| profile | leased/Docker CPU | leased/Docker memory | 추가 자원 |
|---|---:|---:|---|
| light | 1 | 2 GiB | 없음 |
| standard | 2 | 4 GiB | 없음 |
| heavy | 4 | 8 GiB | 없음 |
| gpu | 4 | 10 GiB | GPU 1 |

KVM은 profile과 별개로 `--kvm`을 명시할 때 vector에 1이 추가된다. network도
target이 있을 때만 1이 추가되며, `CommandSpec`의 network resource와
authorize된 Docker network mode가 다르면 실행을 거부한다.

Live 준비는 Codex가 workspace 파일을 쓰기 전에 network `none`의 light
lease로 image entrypoint `true`를 실행한다. 이 단계가 빈 `/work`에 원본의
exact copy와 source provenance를 만든 뒤 `SESSION.md`와 `AGENTS.md`를
작성하므로, “Live가 먼저 파일을 써서 image fresh-work 검사가 실패하는”
순서를 피한다.

### 7.2 선언형 allowlist의 fail-closed 처리

`NetworkPolicy.authorize`는 command가 요청한 target이 상태의
host/port/scheme allowlist와 일치하는지 먼저 검사한다. 그러나 Docker
`bridge`는 특정 목적지만 허용하는 방화벽이 아니므로 `declared` 모드는
metadata 보존에만 쓰고 실제 원격 command는 fail-closed로 거부한다.

`proxy`는 강제 가능한 배포 경로를 표시한다. 실제 보장은 운영자가 해당
Docker network의 egress를 제한 proxy/firewall로 고정했을 때 생긴다.
CTF-OS는 그 proxy, nftables/iptables 규칙 또는 Docker network를 자동
프로비저닝하지 않는다.

정규화된 hostname별 cross-process FIFO는 network tool/proof가 resource
lease를 얻은 뒤 실제 sandbox command를 시작하기 직전에 기본 1초 간격을
강제한다. 같은 hostname을 쓰는 문제 세션들이 이 상태를 공유하고, 죽은
waiter와 timeout/cancel ticket은 회수된다. 이것은 command-start spacing이며
HTTP request limiter가 아니다. `network` resource lease도 동시 command
수를 제한할 뿐 한 command 안의 요청 빈도나 횟수를 세지 않는다.

### 7.3 Live broker와 persistent daemon 경계

`CapabilityAuthority`, `SandboxService`와 persistent-daemon용 low-level
client/server의 1 MiB request limit은 구현되고 통합 테스트가 있다. 이
primitive는 Live transport가 아니다. 실제 Attached Live
경로는 shell-disabled Codex에 required local stdio MCP 하나를 연결하고, 그
bridge만 부모가 TUI lifetime 동안 운영하는 network-free filesystem mailbox
broker에 접근한다. Model은 mailbox path/capability를 받지 않으며 external
app/web/실행 surface와 user MCP도 제거돼 있다. `ctfos_live`는 유일한
state/challenge-execution MCP이고 bridge는 열네 canonical operation만
요청한다. 부모의
`ChallengeEngine.sandbox()`가 `LocalChallengeSandboxClient`를 사용해 Docker
작업을 수행한다.

따라서 Live model이 host shell, local fallback, state/Docker를 소유하지 않는
경계는 구현됐지만, `ctfosd`를 시작·등록·종료하는 operator service와 별도 권한
principal은 없다. capability는 문제 scope를 검증하지만 daemon 기반 OS
권한 분리 배포와 같은 말이 아니다. 특히 같은 Unix UID의 협력하지 않는
프로세스가 raw Docker socket이나 capability secret을 읽지 못하게 하는
별도 OS 경계는 현재 제공하지 않는다.

## 8. 후보, proof와 제출

Codex JSONL/final structured output과 sandbox tool output을 bounded
streaming scanner로 검사한다. chunk 경계를 넘는 문자열을 위해 source별
tail을 보존하고, scanner가 관측한 같은 값을 한 번만 다음처럼 stderr에
발견 즉시 flush한다.

```text
🚩 FLAG CANDIDATE (미제출) [source]
flag{...}
```

Batch, foreground tool과 proof stream callback은 출력 전에 mode `0600`의 bounded
`runtime/candidate-intents.json`을 원자 저장하고 file/directory를
`fsync`한다. 정상 run의 single state commit이 같은 값을 canonical
candidate로 만든 뒤 journal을 지운다. 그 사이 process가 죽으면 다음
session-lock 진입이 남은 intent를 먼저 다시 출력한 뒤 한 revision으로
reconcile한다. 이미 출력된 후보가 중복될 수 있지만 발견을 조용히 잃지
않는 쪽을 우선하며, commit 뒤 clear만 실패한 경우에는 value dedup으로
멱등 정리한다. Live `agent.flag`와 운영자 기록은 canonical state commit이
성공한 뒤 출력한다.

Batch model stdout은 raw 저장 cap을 지난 뒤에도 scan하지만 candidate는
기본 1,024개와 총 256 KiB 문자 상한을 가진다. Tool도 ctfwrap이 전체 drained
stdout/stderr에 `runtime.flag_patterns`를 적용해 후보 1,024개, 총 256 KiB
문자, sidecar 1 MiB 상한으로 기록한다. host-bind log tailer의 raw scan
budget은 `runtime.flag_scan_max_bytes` 기본 16 MiB지만 sidecar는 별도 1 MiB
budget으로 먼저 읽으므로 raw prefix 이후·summary tail 이전 후보도 실행 중
표시된다. 각 상한 이후 후보와 `capture_complete=false`가 된 뒤의 미관측
bytes는 보장하지 않는다.

Proof tailer는 일반 solver `/work` mount 밖의 challenge-private
`.proof-live` sibling과 최종 `/work/proof/clean-*`만 descriptor anchor로
bounded scan한다. Clean proof container에는 exact temporary leaf만
`/work`로 mount한다. 반환 전에 candidate intent를 fsync하고 즉시
출력하며, 임시 leaf 삭제 전에 `flag-candidates.jsonl`을 최종 proof
directory에 최대 1 MiB로 복사한다. 정상 attempt commit 뒤 intent를
지운다. Sidecar는 challenge-writable 후보 신호이므로 선택 candidate의
proof 성공 근거로 승격하지 않는다. 아래의 canonical stdout/stderr
snapshot에서 exact value가 재현돼야 한다. Growing live sidecar와 final
persisted copy는 각각 독립적인 1 MiB 물리 read budget을 예약하고, 최종
저장 sidecar 자체도 최대 1 MiB다.

candidate 발견은 `READY_TO_SUBMIT`이 아니다. proof는 다음을 별도로
검사한다.

- proof 전후 source manifest 일치
- 새 clean workdir
- evaluation 시작 시 한 번 만든 immutable proof-input snapshot/manifest와
  모든 반복의 동일 bytes/hash 재검증
- timeout과 exit code
- attempt stdout/stderr의 immutable evidence snapshot 안에서 exact candidate
  재현
- adapter별 clean/remote 반복 수
- race류의 success distribution
- proof run과 artifact reference

통과해야 candidate와 challenge가 `READY_TO_SUBMIT`으로 이동한다. 사람이
CTF 사이트에 직접 flag를 제출하고 `ctfos submit --outcome
accepted|rejected`로 결과를 기록한다. accepted/rejected는 문제 state와
대회 전체 `submissions.jsonl`에 남는다. 기록 경로는 contest-level
`submissions.lock` 안에서 기존 accepted flag 검사, challenge revision CAS,
state 갱신과 contest ledger append를 직렬화한다. 따라서 두 challenge
process가 같은 flag를 동시에 accepted로 기록하는 race는 한쪽이
명시적으로 거부된다.

코드에는 CTF 서버 URL로 POST하는 경로, 인증정보 저장소, CTFd adapter가
없다. 이 부재는 미완성이 아니라 현재 운영 계약의 의도된 경계다.

## 9. 예산과 자원

`ctfos budget-reset`의 기본값은 28,800초다. 다음 값을 초기화한다.

- `allocated_seconds`
- `spent_seconds`
- `deadline_utc`
- `no_progress_since_seconds`
- refusal history
- `budget_reset_at`

`deadline_utc`는 reset 시점부터 이후 작업에 발급할 절대 hard wall이다.
strict remaining은 절대 deadline과 `allocated_seconds - spent_seconds` 중
짧은 값이다.

- Batch wave는 invocation/context 준비 전에 한 monotonic `D`를 발급해 세
  역할이 공유한다. Provider FIFO wait, process, host normalization과
  state-lock 안의 success eligibility가 같은 `D`를 사용하며 늦은 결과는
  `challenge_budget_expired` 단일 비재시도 failure와 124로 반환된다.
- 기본 Live TUI는 `Popen` 전에 `D`를 고정한다. Spawn 중 `D`를 넘으면 exact
  process group을 TERM→KILL→reap하고 124를 반환한다.
- Tool은 발급된 command `D`를 evidence와 locked finish까지, Proof는
  attempt별 `D`를 evidence와 locked attempt commit까지 유지한다. 마지막
  attempt의 `D`는 최종 `READY_TO_SUBMIT` 승격도 막는다.
- Bounded descriptor scan/copy/evidence, exact cleanup과 `D` 전에 lock
  안에서 이미 승인된 atomic persistence는 `D` 뒤에 끝날 수 있다. Unix RPC
  응답 grace는 일반/init `D+65초`, proof `D+150초`이며 성공 승격이나 cleanup
  완료 보장이 아니다.
- Live scope capability TTL은 8시간과 남은 시간 중 짧은 값이다.

Tool elapsed는 `spent_seconds`, model token/provider wait는 run metadata에도
남아 평가 집계에 쓰인다. `budget-reset`은 이미 발급된
Live/Batch/tool/proof의 `D`나 capability를 연장하지도, 단축·취소하지도
않는다. 새 경계가 즉시 필요하면 기존 작업을 중단하고 재시작해야 한다.
Live는 세션을 닫고 `ctfos solve ... --resume-thread THREAD_ID`로 새 경계를
발급한다. 이미 실행 중인 foreground tool과 reset이 겹치면 reset 이전
구간은 새 예산에 재과금하지 않고 reset 뒤 wall-time 구간만 새
`spent_seconds`에 반영한다.

host tool resource broker는 complete bundle 요청을 원자적으로 기다린다.
partial grant API는 단일 resource kind에 명시적으로 opt-in할 때만 존재하며
Challenge Engine의 worker wave를 줄이는 데 쓰지 않는다. 모델 역할과 tool
resource를 같은 lease로 회계하지 않는다.

## 10. Background와 장기 작업

`ctf-os-image`에는 다음 primitive와 이미지 자체 테스트가 있다.

```text
ctf-bg
ctf-jobs
ctf-log
ctf-kill
```

Docker backend와 Local/Unix client interface에도 `start_job`,
`job_status`, `job_log`, `cancel_job`이 정의돼 있다. 그러나 현재 모든
실제 `start_job` 진입점은 job 전체 lifetime 동안 CPU/RAM/GPU/KVM/network
lease를 보유·회수할 supervisor가 없으므로 Docker 또는 RPC 호출 전에
`BackgroundJobUnsupported`로 거부한다. foreground 경로에서 `ctf-bg`,
detach shell과 알려진 background entrypoint를 호출하는 우회도 거부한다.

engine의 registered experiment는 one-shot `docker run --rm`의 foreground
`client.run`을 사용한다. 이 컨테이너가 자식 프로세스의 hard lifetime
boundary이며 명령 종료/timeout 때 제거된다. `ctfos jobs`는 기존 scoped
runtime의 job 목록만 조회하고, runtime이 없으면 one-shot 조회를 사용해
persistent idle container를 만들지 않는다. status/log/cancel API는 기존
유효한 job reference에만 의미가 있다.

따라서 image primitive와 조회 interface는 보존됐지만, **새 background
job 시작과 lease-supervised background orchestration은 현재 의도적으로
비활성**이다.

정상 timeout·cancel과 첫 `Ctrl-C`/`SystemExit`은 direct/wave Codex와 Live
TUI의 exact process group을 TERM→KILL→wait/reap하고 Docker daemon의 exact
generated foreground container도 정리한다. 첫 Docker cleanup 중 control
interruption은 같은 exact name으로 한 번 재시도한다. Tool experiment/run을
실패 종결하며 tool snapshot과 proof input/evidence/final result 후처리
인터럽트는 commit 전 exact uncommitted file만 지우고, 최종 state commit
뒤에는 canonical evidence와 companion environment를 보존한다.

Live `Popen` constructor는 main-thread control exception과 분리된 helper가
소유한다. CPython 3.13의 `_fork_exec` 반환과 `self.pid` STORE 사이에서
부모가 중단돼도 helper 완료를 기다린 뒤 exact process group을
TERM→KILL→reap한다. Leader가 정상 또는 nonzero로 끝난 뒤 같은 group의
background descendant가 남으면 정리하고 return code 125로 fail-closed한다.

Batch wave는 `ThreadPoolExecutor`의 내부 thread registry와 별도로 dispatch
gate를 둔다. Registry 등록 전 시작된 worker, gate close/cancel 확인,
`cancel_active`, `Future.cancel`, active drain의 첫 control interruption을
모두 session lock 안에서 처리한다. Live flag tailer도 delayed bootstrap,
stop publication, `ident`/liveness 확인과 active callback join이 끝나기 전에
scope가 풀리지 않는다.

복구 중 두 번째 독립 control signal, `SIGKILL`, 전원 단절은 이 보장 밖이다.
남을 수 있는 exact-name prefix는 `ctfos-run-`, `ctfos-init-`,
`ctfos-proof-init-`, `ctfos-proof-`이고 형식은
`<prefix><scope fingerprint 첫 12 hex>-<random 12 hex>`다. 죽은
PID-backed holder 회수 뒤 새 호출과 겹치면 설정 상한을 일시 초과할 수
있으므로 재개 전에 exact orphan을 확인·종료해야 한다.

Raw descriptor owner는 ownership을 먼저 retired/unowned로 게시하고 lock을
먼저 unlock한 뒤 close를 정확히 한 번만 시도한다. Close 결과는 descriptor
소비 여부가 모호하므로 숫자 FD를 검사·복구·재-close하지 않는다. Syscall 전
interruption이면 이미 unowned/unlocked인 FD 하나가 process exit까지 남을
수 있다. 같은 inode·같은 번호를 재사용한 peer를 잘못 닫는 위험을 피하기
위한 수용 잔여이며, 이 잔여와 두 번째 signal/SIGKILL 경계를 닫는 persistent
guardian은 과설계를 피하기 위해 범위에 넣지 않았다.

## 11. 검증 근거와 한계

저장소 회귀 suite는 다음 명령으로 실행한다.

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
```

현재 suite는 다음을 포함한다.

- 상태 원자 교체, stale revision, 손상 복구, crash 후 lock 재획득,
  state 16 MiB와 typed/repeated collection 16,384개 상한
- provenance와 참조 무결성, category namespacing
- state transition, pause/resume, proof/manual submission gate
- role output schema, configured Sol/Terra/Luna route, flag streaming
- Batch shell/MCP 차단, bidirectional pipe drain, timeout·interrupt
  process-group cancellation, provider waiter 취소, executor registry 전
  worker와 callback drain
- 논리 세 역할을 유지한 provider serialization
- tool lease FIFO, atomic bundle, process 사망 회수
- lease vector와 Docker CPU/RAM/GPU/KVM flags 결속
- sandbox scope, mount, declared-network fail-close, target allowlist contract,
  tamper-evident workspace artifact snapshot과 proof input/evidence manifest,
  모든 commit의 canonical artifact 실제-byte 합계 cap, work-tree entry
  상한+1 즉시 중단과 실패 cleanup
- contest submission transaction에서 concurrent duplicate accepted flag 거부
- Docker control timeout의 exact generated container best-effort cleanup과
  cleanup 실패 오류
- Live fresh-work 초기화 순서, one-shot foreground 감독, background 우회 거부
- 경쟁 `solve`/`run-challenge`/`add-challenge --prompt`와 직접
  `update_prompt`가 session lock 획득 전에 prompt/revision/state bytes를
  바꾸지 않는 session-owned prompt 회귀
- required `ctfos_live` MCP handshake/tool allowlist와 실제
  MCP→mailbox broker→`agent.flag` 출력·영속 integration
- 14-operation allowlist, bounded inspect pagination, hash-verified
  `knowledge.search`/UTF-8 `knowledge.read`
- response publish 직전 `ENOENT`를 정상 경합으로 재시도하고 malformed
  mailbox entry는 계속 거부하는 Live transport 회귀
- 실제 `gpt-5.6-luna`→required stdio `ctfos_live`→private mailbox
  broker→`agent.flag`의 즉시 터미널 출력, candidate 영속, `submissions=0`
- production-model mock Responses 실제 request의 external
  app/web/plugin-install/host-shell tool 0개와 `exec`/`wait`/`apply_patch`를
  포함한 남은 local/native/helper tool inventory
- context truncation, category adapter, ingest
- candidate intent의 fsync-before-print, crash 뒤 reprint-before-reconcile와
  commit-before-clear 멱등성
- session 경계의 orphan `RUNNING` run 실패 종결, tool lease
  acquire/release·flag notification 실패 종결, terminal-safe status
- tool setup/sandbox/result 후처리의 `KeyboardInterrupt`/`SystemExit`
  실패 종결, lease 1회 반납, commit 전 exact artifact cleanup과 commit 후
  canonical evidence 보존
- proof input/evidence/attempt/final result의 interrupt 전후 exact cleanup,
  bounded copy hardlink 뒤 임시 파일 제거와 commit 후 companion 보존
- direct Codex와 Live attached process의 parent-only interrupt에서 exact
  process-group descendant TERM→KILL→wait/reap, Docker exact ephemeral
  container cleanup과 원 예외 identity 보존
- Live constructor의 `_fork_exec`→PID STORE interrupt와 정상 leader가 남긴
  residual process group 정리, flag tailer의 delayed bootstrap/active
  callback scope drain
- 빈 solving prompt의 direct `run_role` 차단
- executed fact의 terminal source run·same-run artifact 결속, tool stdout
  snapshot 실패 시 fact 미발행과 artifact cleanup
- 서로 다른 challenge wave를 건드리지 않는 scoped process cancellation,
  reset 중 foreground tool의 post-reset 구간만 새 예산에 반영
- hostname별 remote command-start cross-process FIFO, dead waiter,
  hard-budget timeout, tool/proof 실제 시작 간격
- 8시간 process-group hard deadline, STALLED governor, typed
  goal/hypothesis/evaluation과 read-only 평가 집계
- CLI parser/운영 흐름의 local fixture

이 테스트의 상당수는 fake runner/backend를 사용한다. 다음을 아직
증명하지 않는다.

- 실제 계정에서 Sol/Terra/Luna 세 모델을 모두 호출한 end-to-end solve
- 실제 Live native delegation의 개별 provider 대기
- 운영자가 준비한 실제 proxy의 적대적 egress 차단
- 실제 국내 대회 서버의 rate limit 준수
- L2 held-out/L3 live solve 성능
- “세계 1등급” 성능 또는 8시간 내 solve 보장

Local process integration은 Codex가 생성할 것과 같은 stdio MCP handshake와
실제 broker tool call을 검증한다. 별도 실제 model probe는
`gpt-5.6-luna`가 required stdio `ctfos_live`와 private mailbox broker를
통해 `agent.flag("KCTF{luna_mcp_e2e}")`를 호출하는 데 성공했다. 후보는
터미널에 즉시 출력되고 canonical state에 영속됐으며 submission은 생성되지
않아 `submissions=0`이었다. 이는 Luna 단일 호출의 flag 전달 경로에 대한
증거이며 위 목록의 “세 모델 전체 solve”, Sol interactive TUI 또는 native
세 worker 병렬 E2E를 대신하지 않는다.

`ctf-os-image/tests/`는 이미지 lifecycle의 별도 suite이며 저장소 Python
unit suite를 실행했다고 자동으로 수행되지는 않는다.

2026-07-28 현재 호스트에서 별도 Docker smoke도 수행했다.

- `ctf-os:core` exact image ID
  `sha256:114da21d7258593dd7db586e210ebfdf9a9b75eaa9efa16337b0dec53ad575c7`
  를 `.ctfos/engine.toml`에 pin
- image capability contract의 manifest tool 182개와 browser readiness 확인
- Live fresh-work 초기화 뒤 후속 foreground tool 실행 성공
- GPU+KVM 요청에서 container `cpu.max=400000/100000`,
  `memory.max=10737418240`, RTX 4060 Ti 노출과 `/dev/kvm` character
  device 확인

이는 현재 호스트의 runtime 결속을 확인한 것이지 다른 호스트나 실제 대회
solve 성능을 보증하는 결과는 아니다.

최종 freeze 검증은 Python `3.13.14`만 권위 있는 gate로 사용했다.

- aggregate source hash:
  `09641f4466b30add7d18d6239a6ff73fb9afa8baccf2fb2d49b2ce5c55a8d96b`
- 전체 Python unit/integration: 679개, 83.750초, 모두 통과
  (측정 wall 81.85초)
- `compileall`, Ruff `E9/F63/F7/F82`, `uv lock --check`,
  `uv pip check`: 통과
- `ctfos doctor`: `ok=true`, warning 없음, pinned image 일치, 논리 worker
  3, manual submission, network `none`, provider max 4 확인
- image source/lifecycle 8개와 exact pinned-image capability 1개: 통과
  (`manifest_tools=182`, browser readiness, SQL tools 0)
- 계약·lifecycle·security 세 축 감사와 수정 후 독립 delta 재검토:
  미해결 P0/P1/P2 없음
- fresh Claude Code `2.1.220` Opus/max, plan/read-only 최종 검토:
  `FINAL VERDICT: PASS`, 미해결 P0/P1/P2 없음

수용된 P3 경계는 다음과 같다.

- raw syscall/descriptor ownership의 극소 interruption 창에서 FD 하나가
  process exit까지 남을 수 있으며, ABA 위험 때문에 모호한 close 뒤 숫자
  FD를 재시도하지 않는다.
- 이미 실행 중인 exact cleanup에 두 번째 독립 control signal이 들어오거나
  `SIGKILL`·전원 손실이 발생하는 경우는 crash-only다.
- leader reap 뒤 숫자 PGID는 generation-pinned handle이 아니어서 극히 드문
  PID 재사용 경합에서 replacement group을 probe/signal할 수 있다.
- Codex 0.145 `view_image`의 같은-UID 추측 가능 host path와 raw Docker
  socket 격리는 OS principal 경계가 필요하다.
- 외부 proxy, 실제 대회 rate limit, 모든 모델 native delegation 및 실제
  solve 성능은 로컬 contract 검증 범위 밖이다.
- 비정상적으로 큰 finite public wait는 CPython `OverflowError`로
  fail-closed할 수 있으나 설정/default 8시간 경로에는 영향이 없다.
- clean proof는 pinned input/environment/evidence/output 반복을 증명하지만
  사람이 고른 command의 원인성과 의도적 hardcoded flag를 일반적으로
  판별하지는 못한다.

## 12. 09 대비 의도적 변경

| 초기 09 초안의 설계 표현 | as-built 결정 |
|---|---|
| 모델 층 전역 상한 없음 | Batch provider 호출에 configurable cross-process FIFO 상한을 둠. 논리 역할 수는 그대로 |
| 세션 생성은 contest scheduler 비의존 | 사람은 다른 문제의 세션을 바로 요청할 수 있지만 same-challenge lock과 workspace-init tool lease는 local 대기/실패, Live model call은 계정/provider 대기 가능. 논리 3역할은 즉시 세 native worker 동시 시작 보장이 아님 |
| challenge ID만으로 상태 경로 | category를 경로에 포함해 동일 문제명 충돌 방지 |
| `brief.md` | 정본 파생 뷰는 `context/current.md`, Live 입력은 workspace `SESSION.md` |
| partial lease와 narrow wave | engine bundle은 원자 대기. partial은 단일 kind opt-in API뿐이며 wave를 줄이지 않음 |
| 조건부 자동 제출 | 구현하지 않음. 사람 제출과 결과 기록만 유지 |
| host별 remote budget | hostname별 command-start FIFO는 구현. command 내부 HTTP request budget은 외부 restricted proxy 책임이며 network 동시 lease와 혼동하지 않음 |
| `ctfosd`가 Docker 독점 | Live의 유일한 state/challenge-execution MCP는 shell-disabled 환경의 required `ctfos_live`이고 mailbox/capability는 MCP env에만 있음. 부모가 state/Docker를 소유하며 persistent·별도 권한 daemon 배포는 미완성 |

## 13. 남은 작업 우선순위

대회 hot path에 직접 영향을 주는 순서다.

1. 적대적 원격 문제에 필요한 제한 proxy/network를 배포하고 `proxy`
   enforcement의 egress를 실제 테스트한다.
2. 대회 정책에 맞는 command 내부 HTTP request rate/token bucket을 외부
   proxy에서 강제하고 429·우회 egress를 실제 서버와 대조한다.
3. configured Sol/Terra/Luna 전체 solve와 Sol Live TUI/native 세 worker를
   실제 계정에서 고정 예산으로 검증한다.
4. 구현된 evaluator로 L2 held-out와 L3 live fixed-budget 실험을 수행하고
   solve@1/3, consistency, clean proof와 시간·사용량을 비교한다.
5. job lifetime 전체에 resource lease를 유지하고 사망 시 회수하는
   supervisor를 먼저 구현한 뒤 background start/status/log/cancel을
   연결할지는 실제 대회에서 장기 background 수요가 확인될 때만 결정한다.
6. 부모 sandbox backend까지 별도 권한 daemon으로 분리하려면 persistent
   `ctfosd` lifecycle, registration과 권한 분리 설치를 완성한다. Attached
   Live의 shell-disabled required MCP→network-free mailbox broker 경로는
   이미 기본 경로다.

자동 제출은 이 목록에 없다. 현재 사용자 계약에서는 사람이 제출하는 것이
정본이다.
