# CTF-OS 수용성 기록

역사적 판정 기준일: 2026-07-28 (Asia/Seoul)

현재 상태 갱신: 2026-07-31 (Asia/Seoul)

> 2026-07-28 동결 상태: **당시 범위 최종 수용**
>
> 현재 source 상태: **release acceptance 대기**
>
> 아래 2026-07-28 판정은 source freeze
> `09641f4466b30add7d18d6239a6ff73fb9afa8baccf2fb2d49b2ce5c55a8d96b`
> 의 코드, Python 3.13 회귀, 정적·image gate, 독립 감사와 Claude CLI
> read-only 검토를 직접 대조한 **역사적 요구사항 판정**이다. 이후
> managed/category hot path가 변경됐으므로 그 hash, test 수와 image
> receipt를 현재 source의 승인으로 재사용하지 않는다. 현재 승격에는
> 현재 source의 전체 회귀와 exact-image all-category matrix가 새로
> 필요하다.

충돌 시 권위 순서는 현재 코드와 통과한 회귀, 이 문서의 요구사항 판정,
[10 구현 결과](10-implementation-result.md), [09 역사적 설계](09-implementation-blueprint.md)
순이다. 운영 명령은 저장소 [README](../README.md)를 따른다.

## 0. 2026-07-31 현재 수용성 delta

현재 source에는 2026-07-28 이후 다음 권위 경로가 구현돼 있습니다.

| 영역 | 현재 코드 상태 | 아직 수용하지 않는 주장 |
|---|---|---|
| Managed 연속성 | CLI managed solve/run/cycle의 생략 기본은 `captain_lane`; 같은 challenge의 Captain만 resume하고 explorer/builder/verifier/proof는 fresh context | retained reasoning이 blind/live solve를 높였다는 주장 |
| Pwn | D→V crash, runtime snapshot, address-dependency L/N/A, IP-control primitive와 one-shot 3+3 exploit-effect를 engine-owned artifact로 판정 | 실행 중 pointer capture/derive/staged send가 필요한 exploit을 typed interaction gate가 검증했다는 주장 |
| Web | 역할별 session/state, runtime timeline, differential impact, race/OOB의 실행 oracle | 실제 대회 proxy, remote portability와 source-only 추론을 impact로 인정하는 것 |
| Rev | 원본 바이너리 positive 3회와 mutated negative 3회 | 원격/argv/multi-file/non-native 범위 |
| Crypto | managed Builder보다 앞서 operator가 challenge 밖에서 hidden variant를 preissue하고 engine-private authority를 one-shot 소비하는 3+3 oracle | 현재 source와 image에 결속된 최종 Docker release receipt 및 hidden/live solve 성능 |
| Forensics | immutable index, file/offset/frame 계열 pointer, readiness와 cross-tool assertion graph | coverage가 낮거나 pointer가 없는 사건 서술 |
| Misc | modality intake, hash-bound transform DAG, negative control과 3회 replay; candidate-only | verifier 통과를 제출/solve 권한으로 취급하는 것과 현재 Docker release receipt |

실제 `zone` 한 문제에서는 bounded operator harness가 매 process의 stack/libc
주소를 다시 구해 exploit effect를 attack 3/3, matched control 0/3으로
재현했습니다. 그러나 local flag source와 active remote target이 없었고,
현재 one-shot typed effect producer가 그 interaction을 표현하지 못합니다.
따라서 genuine flag, solve, remote portability 또는 typed interaction
P/E 승격이 아닙니다. 정본 포인터는
[21-zone-solve-capable-exploit-evidence.md](21-zone-solve-capable-exploit-evidence.md)에
있습니다.

이 delta는 코드 구현 기록이지 현재 release 승인서가 아닙니다. 전체 suite와
현재 exact-image matrix가 끝나기 전에는 아래 역사적 PASS를 현재 source에
적용하지 않습니다. 그 뒤에도 동일 모델·도구 thin baseline 대비 3회 중
2회 재현, blind/live solve@1, 카테고리 floor는 별도 측정 대상입니다.
ExploitGym/CyberGym-E2E와 미지 코드베이스 CVE 발견 능력도 CTF 점수와
합치지 않습니다.

## 1. 확정 계약 수용표 — 2026-07-28 역사적 동결

| 계약 | 판정 | 코드·회귀 근거와 정확한 경계 |
|---|---|---|
| 대회 스케줄러 제외 | 수용 | CLI에는 대회 전체 challenge queue/priority/auto-switch 명령이 없다. 사람이 문제별 `solve` 또는 `run-challenge`를 호출한다. [`test_no_contest_wide_automatic_challenge_runner_is_exposed`](../tests/test_cli.py) |
| 사람이 문제 폴더·다운로드·풀이 prompt를 제공 | 수용 | `incoming/<contest>/<category>/<challenge>/`를 사람이 채우고 ingest가 regular file inventory/SHA-256을 만든다. 엔진은 임의 문제 URL을 다운로드하지 않는다. [`ChallengeEngine.add_challenge`](../ctf_os/engine/challenge.py), [`test_human_folder_prompt_status_and_budget_workflow`](../tests/test_cli.py) |
| Live와 Batch 둘 다 제공 | 수용 | `ctfos solve`는 attached Live Captain, `ctfos run-challenge`와 `wave`는 deterministic Batch 경로다. 같은 문제의 owner는 `runtime/session.lock`으로 배제한다. |
| 각 wave의 논리 역할 세 개 유지 | 수용 | Discovery/Attack/Proof의 역할 tuple은 세 개를 유지하고 provider limiter는 호출 시작만 기다리게 한다. 두 challenge의 3+3 역할, 한쪽 실패 격리와 FIFO 대기를 회귀한다. [`test_wave_keeps_three_logical_roles_while_provider_serializes_calls`](../tests/test_codex.py), [`test_two_challenges_keep_three_roles_and_isolate_failure`](../tests/test_multisession.py) |
| “세션 요청”과 “즉시 세 worker 동시 실행” 분리 | 수용 | 사람은 contest scheduler 승인 없이 다른 문제의 세션을 요청할 수 있다. 같은 문제 owner 충돌, Live workspace-init tool lease, 실제 model/provider 대기는 남는다. Live 세 native worker의 즉시 동시 시작은 보장하지 않는다. |
| 계정 한도에서 model call 대기 | 수용(관측 경계 명시) | CTF-OS가 직접 시작하는 Batch `codex exec`는 cross-process FIFO와 설정 상한을 사용한다. Live native subcall은 local FIFO 밖이며 Codex/provider가 대기시킬 수 있지만 CTF-OS가 시작 시점이나 실제 quota를 하드 강제·완전 관측하지 못한다. 구독 plan의 실제 quota도 자동 조회하지 않는다. |
| Sol/Terra/Luna 역할 routing과 Luna 사용 | routing 수용, 성능 미검증 | 기본값은 Captain/Builder/Falsifier/Validator→Sol, Recon/Specialist/Reproducer→Terra, Extractor/Evidence Auditor→Luna다. Route fixture와 이전 Luna 단일 `agent.flag` probe는 있지만 실제 계정의 세 모델 전체 solve, Sol Live TUI와 native 3-worker E2E는 미검증이다. [`test_role_routes_cover_sol_terra_luna_and_proof_separation`](../tests/test_codex.py) |
| 예상 flag 즉시 터미널 표시 | 수용(명시 상한 내) | Live `agent.flag`는 canonical commit 뒤 출력한다. Batch/tool/proof stream은 fsynced bounded intent 뒤 `FLAG CANDIDATE (미제출)`를 stderr에 즉시 flush하며, proof는 일반 `/work` 밖 private sibling의 live raw/sidecar를 clean-proof 실행 중 tail한다. 정상 attempt commit 뒤 intent를 지우고 crash-left intent는 다음 session에서 먼저 재출력·멱등 reconcile한다. Proof live prefix와 final sidecar copy는 서로 독립된 1 MiB physical-read budget을 사용하고 final copy도 최대 1 MiB다. Sidecar는 candidate 신호일 뿐 proof 성공 근거로 승격하지 않는다. 후보 수·문자·sidecar 상한 이후와 incomplete capture 이후 bytes는 보장 밖이다. [`test_flag_commit_bypasses_an_active_tool_operation`](../tests/test_live_broker.py), [`test_blocking_proof_notifies_after_durable_intent_before_return`](../tests/test_engine.py), [`test_proof_final_sidecar_survives_raw_scan_cap_and_commits_candidate`](../tests/test_engine.py) |
| 사람이 flag 제출·결과 기록 | 수용 | `ctfos submit`은 candidate를 보여 주거나 사람이 확인한 accepted/rejected/error/dry_run만 기록한다. CTF 서버 POST, CTFd adapter, 자동 재제출과 credential 저장은 없다. Contest `submissions.lock`과 `submissions.jsonl` ledger가 accepted 중복을 직렬화한다. [`test_same_flag_cannot_be_accepted_for_two_challenges_concurrently`](../tests/test_store.py) |
| 원할 때 문제풀이 세션 추가 | 수용(동시성 경계 포함) | 다른 challenge는 별도 terminal에서 명시 실행한다. 같은 challenge의 Live/Batch/tool/proof owner는 하나다. CTF-OS가 background에서 TUI를 만들거나 thread ID를 추측·재부착하지 않는다. |
| prompt와 session owner 일관성 | 수용 | `solve`/`run-challenge`/직접 `update_prompt`와 기존 문제의 `add-challenge --prompt`는 새 prompt를 `runtime/session.lock` 획득 뒤 commit한다. 경쟁 `SessionAlreadyRunning`은 기존 prompt, revision과 `state.json` bytes를 바꾸지 않는다. 이는 prompt update 보장이고 target·knowledge·budget 등 operator configuration mutation 전체에 대한 일반 보장이 아니다. [`test_live_lock_is_acquired_before_session_files_are_rewritten`](../tests/test_engine.py), [`test_competing_session_commands_do_not_replace_prompt_before_lock`](../tests/test_cli.py) |
| 국내 대회 기본 8시간 budget reset | 수용 | `budget-reset` 기본 28,800초가 절대 UTC deadline을 만든다. Wave는 context 준비 전 공통 monotonic `D`, Live는 `Popen` 전 `D`, tool/proof는 evidence·locked success 판정까지 같은 `D`를 유지하며 provider/lease wait, process와 capability TTL을 clamp한다. Reset은 이미 발급된 `D`를 연장·단축·취소하지 않고, reset과 겹친 foreground tool은 reset 뒤 구간만 새 예산에 과금한다. 새 경계가 필요하면 기존 작업 종료 뒤 resume한다. [`tests/test_budget.py`](../tests/test_budget.py) |
| typed goal/hypothesis/experiment/evaluation | 수용 | 한 active goal, falsifier, executed evidence chain과 experiment-own result run을 검증한다. Live model은 trusted provenance나 non-open hypothesis status를 직접 mint하지 못하고 `agent.evaluate` 경계를 사용한다. [`test_experiment_evaluation_requires_its_own_executed_chain`](../tests/test_engine.py), [`test_broker_reserves_operator_fact_and_abandoned_for_operator_paths`](../tests/test_live_broker.py) |
| 문제별 논문·GitHub 지식 활용 | 수용(운영자 주입만) | 사람이 검토한 bounded regular file만 hash-verified knowledge store에 넣는다. Search와 UTF-8 64 KiB read는 scope/read-only이고 URL fetch와 credential URL은 없다. [`tests/test_knowledge.py`](../tests/test_knowledge.py) |
| 과설계 금지 | 수용 | 상태는 표준 라이브러리 파일 저장소, `flock`, atomic replace와 JSON이다. DB, task queue, container SDK, service framework나 contest scheduler를 추가하지 않았다. Persistent 별도 권한 `ctfosd`는 기본 hot path가 아니다. |

## 2. Live tool surface 판정

Required `ctfos_live`는 Live의 유일한 state/challenge-execution MCP이며 다음
열네 canonical operation을 제공한다.

```text
agent.flag  agent.fact  agent.goal  agent.hypothesis
agent.experiment  agent.evaluate  agent.artifact
agent.progress  agent.transition  tool.run  jobs  inspect
knowledge.search  knowledge.read
```

이 숫자는 Codex production request의 **전체 built-in tool 수가 아니다.**
Production-model request 캡처에는 `exec`, `wait`, `apply_patch`, native
collaboration, `tool_search`, `view_image`, plan/user-input과 generic MCP
resource helper도 남는다. `exec`는 filesystem/network API가 없는 V8
orchestration이고, `apply_patch`는 challenge workspace writer다.
`exec_command`, `write_stdin`, shell, external app/web/network와
`request_plugin_install`은 노출되지 않는다.
[`test_live_codex_request_exposes_only_scoped_and_local_tools`](../tests/test_codex.py)
가 이 두 inventory를 분리해 확인한다.

`view_image`는 command나 network egress가 아니지만 Codex 0.145 legacy
workspace-write와 같은 Unix UID 조건에서는 추측 가능한 workspace 밖 host
image path를 model input으로 올릴 잔여 위험이 있다. 대회 전 같은 UID가
읽을 수 있는 민감 이미지를 정리하고, 가능한 경우 별도 `CODEX_HOME` 또는
user `sandbox_mode` 제거로 custom profile을 적용해야 한다.

## 3. Lock, state와 evidence의 권위

| 파일 | 실제 역할 |
|---|---|
| `<challenge>/.lock` | state CAS, previous-image 복구와 짧은 commit 구간 mutex |
| `<challenge>/runtime/session.lock` | 같은 challenge의 Live/Batch/tool/proof owner 수명 배제 |
| `<challenge>/runtime/delegation-owner.json` | Live native owner의 pid/시각 진단 marker. lock·lease·권한 정본이 아님 |

문제의 구조화 상태와 상태 전이 정본은 `state.json`이다. 읽기와 쓰기는
16 MiB로 제한되고, 최상위 typed collection과 알려진 nested repeated-ID
field는 각각 16,384개까지다. 모든 commit은 state가 참조한 canonical
artifact의 실제 file-size 합계가 `runtime.work_tree_max_bytes` 이하인지
검사한다. 이 검사는 artifact digest 재검증을 생략하는 내부 commit에도
적용된다. [`tests/test_models.py`](../tests/test_models.py),
[`tests/test_store.py`](../tests/test_store.py)

다음 파일은 역할이 다르다.

- `events.jsonl`, `context/current.md`, board와 export는 state에서 다시 만들
  수 있는 파생/감사 자료다.
- Hash가 등록된 artifact와 proof bytes는 fact/hypothesis/proof 판정에 쓰는
  canonical evidence다.
- Contest `submissions.jsonl`은 사람 제출 결과와 accepted flag의
  cross-challenge 중복 판정에 쓰는 durable ledger다.

문서의 “immutable”은 engine-managed mode `0400` copy와 저장된
size/SHA-256의 재검증으로 변조를 탐지하고 fail-closed한다는 뜻이다.
`chattr +i`, fs-verity 또는 별도 OS principal이 같은 Unix UID의 변경을
물리적으로 금지한다는 뜻은 아니다. 같은 UID가 mode를 바꿔 bytes를 수정할
수는 있지만 이후 hash 검증을 통과하지 못한다.

## 4. Sandbox, 자원과 운영 경계

- `incoming/`은 read-only `/challenge`, 분석 공간은 writable `/work`로
  mount한다. Challenge binary/parser/browser/remote command는 typed
  sandbox 경로로만 실행한다.
- Default network는 `none`이다. `declared` Docker bridge 원격 실행은
  fail-closed이고, `proxy`는 운영자가 실제 제한 proxy/network를 준비했을
  때만 목적지 강제 경로가 된다.
- Hostname별 FIFO는 tool/proof **command 시작**을 기본 1초 간격화한다. 한
  command 안의 HTTP request 수·속도 token bucket이 아니며 실제 대회
  egress/rate는 외부 proxy/firewall 책임이다.
- `runtime.work_tree_max_bytes`는 `/work` 명령 전후의 descriptor-anchored
  안정 scan과 copy/canonical artifact cap이다. 실행 중 매 write를 막는
  filesystem/project quota가 아니므로 transient overshoot가 가능하다.
  Entry 수는 directory 전체를 host heap에 materialize하기 전에 전역
  상한+1에서 즉시 fail-closed한다.
- Canonical artifact 합계 cap과 별개로 누적 `runs/` raw, contest
  `submissions.jsonl`과 전체 challenge tree에는 총량 quota, retention
  policy나 GC가 없다.
- Foreground는 one-shot `docker run --rm`과 resource lease로 감독한다.
  Background start는 lifetime lease supervisor가 없어 명시적으로
  비활성화돼 있다.
- 정상 timeout·cancel과 `Ctrl-C`/`SystemExit`은 direct/wave Codex와 Live
  TUI의 exact process group을 TERM→KILL→wait/reap하고 Docker exact-name
  foreground container를 정리한다. tool experiment/run을 실패 종결하며,
  tool snapshot과 proof input/evidence/final result 후처리는 commit 전
  uncommitted file만 제거하고 commit 뒤 canonical evidence와 companion을
  보존한 채 원 예외를 재전파한다. 다만 host engine 자체의 `SIGKILL`·전원
  손실은 Codex 자식 또는
  Docker daemon 소유 `ctfos-run-*` container를 남길 수 있고, 죽은 holder
  회수 뒤 새 호출과 겹쳐 설정 상한을 일시 초과할 수 있다. 비정상 종료 뒤
  재개 전 exact orphan process/container를 operator가 확인·종료해야 한다.
  정확한 자동 폐쇄에는 별도 guardian/supervisor가 필요해 현재 범위의
  명시적 crash-only 잔여 위험으로 수용한다.
- Batch는 executor registry와 별도 dispatch gate로 late/unregistered
  worker의 callback admission을 닫고 active callback을 session lock 안에서
  drain한다. Live flag tailer도 stop publication, delayed bootstrap,
  `ident`/liveness/join control interruption을 처리한 뒤 scope를 푼다.
- Live `Popen`은 main-thread control exception과 분리된 constructor owner가
  `_fork_exec` 반환→PID STORE를 끝까지 소유한다. 정상/nonzero leader가
  background descendant를 남기면 exact group을 제거하고 125로
  fail-closed한다.
- Image digest pin은 `ctfos pin-image`로 권장되고 pin된 경우 tool/workspace
  init/clean proof가 exact image ID를 검증한다. 미설정 실행 자체는 막지 않고
  `doctor`가 경고한다.
- Model/log 비노출 typed credential channel, 자동 제출, background Live
  session 생성은 없다.

## 5. 2026-07-28 검증으로 증명하지 않은 것

로컬 suite는 model API나 실제 CTF remote request를 호출하지 않는다. Fake
runner/backend와 local process integration으로 contract와 경계를 검증한다.
따라서 다음은 당시 수용 이후에도 운영/성능 미검증으로 남았다.

- 실제 계정의 Sol/Terra/Luna 세 모델 전체 end-to-end solve
- 실제 Sol interactive TUI와 세 native worker의 병렬 시작·완료
- Live native subcall별 provider 대기와 실제 동시 호출 수
- 운영자가 준비한 proxy의 적대적 egress 차단과 국내 대회 서버 rate 준수
- L2 held-out/L3 live fixed-budget solve@1/3 성능
- 8시간 안 solve 또는 특정 순위 보장

별도 실제 Luna probe는 `agent.flag` 전달, 즉시 terminal 출력, canonical
candidate 영속과 `submissions=0`만 확인했다. 전체 solve 성능 증거로
확대하지 않는다.

## 6. 2026-07-28 역사적 최종 판정 gate

다음 gate는 2026-07-28 동결에서 모두 성공했다. 현재 source의 gate 결과가
아니다.

1. Python 3.13 전체 unit/integration suite
2. source compile과 정적 import/error lint
3. `ctfos doctor`와 pinned image/GPU/KVM 정책 점검
4. 별도 image lifecycle/capability 회귀
5. 서로 독립된 frozen-source 감사에서 미해결 P0/P1/P2 없음
6. Claude CLI Opus의 최종 read-only 2차 검토에서 미해결 P0/P1/P2 없음

최종 gate 결과는 다음과 같다.

- aggregate source hash:
  `09641f4466b30add7d18d6239a6ff73fb9afa8baccf2fb2d49b2ce5c55a8d96b`
- Python `3.13.14`: 679개, 83.750초, 모두 통과
  (측정 wall 81.85초)
- compileall, Ruff `E9/F63/F7/F82`, `uv lock --check`,
  `uv pip check`: 통과
- doctor: warning 없음, pinned image/GPU/KVM과 운영 정책 일치
- image source/lifecycle 8개 + pinned-image capability 1개: 통과.
  Exact image digest는
  `sha256:114da21d7258593dd7db586e210ebfdf9a9b75eaa9efa16337b0dec53ad575c7`,
  capability는 manifest tool 182개, browser ready, SQL tool 0개였다.
- 계약·lifecycle·security 세 축 감사와 수정 후 독립 delta 재검토:
  미해결 P0/P1/P2 없음
- fresh Claude Code `2.1.220` Opus/max, plan/read-only 검토:
  `FINAL VERDICT: PASS`, 미해결 P0/P1/P2 없음
- Claude 검토 뒤 aggregate source hash 재계산: 동일

## 7. 2026-07-28 수용된 P3 잔여 위험

다음은 당시 동결의 수용을 막지 않았지만 운영자가 알아야 하는 명시적
경계다.

1. Raw syscall CALL→Python owner STORE와 ownership retire→single-close의
   극소 창에서 FD 하나가 process exit까지 남을 수 있다. 모호한 close 뒤
   숫자 FD 재시도는 peer FD를 닫는 ABA 위험 때문에 하지 않는다.
2. 이미 실행 중인 exact cleanup에 두 번째 독립 `KeyboardInterrupt` 또는
   `SystemExit`이 들어오거나 `SIGKILL`·전원 손실이 발생하는 경우는
   crash-only다.
3. POSIX 숫자 PGID는 leader reap 뒤 generation-pinned handle이 아니다.
   극히 드문 host PID 재사용 경합에서 replacement group probe/signal이
   가능하며 완전 폐쇄에는 Linux 6.9+ group pidfd, cgroup 또는 supervisor가
   필요하다.
4. Codex 0.145 `view_image`의 같은-UID 추측 가능 host path와 raw Docker
   socket을 적대적 같은-UID 프로세스에서 격리하려면 별도 OS principal
   경계가 필요하다.
5. 외부 proxy enforcement, 실제 대회 rate limit, 모든 모델의 native
   delegation 동작과 실제 solve 성능은 이 로컬 수용 gate가 보증하지 않는다.
6. 비정상적으로 큰 finite public wait는 CPython `OverflowError`로
   fail-closed할 수 있다. 설정/default 8시간 bounded 경로에는 영향이 없다.
7. Clean proof는 pinned challenge/input, clean environment, durable
   evidence와 exact output 반복을 증명한다. 사람이 고른 proof command의
   원인성이나 의도적으로 hardcode한 flag를 일반적으로 판별하지는 못한다.

현재 source의 새 전체 회귀나 all-category matrix에서 실패가 하나라도
있으면 관련 현재 표 행은 수용이 아니라 차단/조건부 상태로 둔다. 실제
same-model solve와 대회 성능은 새 local gate가 통과해도 별도 운영
검증으로 남는다.
