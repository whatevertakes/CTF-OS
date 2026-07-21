# CTF-OS

CTF-OS는 사용자가 직접 연 Sol 세션을 lead attacker로 유지하면서, 제한 시간 안에 첫 valid flag를 얻도록 서로 다른 exploit 경로를 짧게 경쟁시키는 로컬 CTF 도구입니다. Python은 model/API를 실행하지 않고 manifest, race/resource ledger, sandbox, target policy, event, artifact, receipt와 replay만 담당합니다.

불변 competition/safety 계약은 [`ctf_os/resources/agent-policy.md`](ctf_os/resources/agent-policy.md), 실제 solve 절차는 [`.codex/skills/ctf-solve/SKILL.md`](.codex/skills/ctf-solve/SKILL.md), category별 command budget은 [`ctf_os/resources/knowledge/playbooks/`](ctf_os/resources/knowledge/playbooks/)가 authoritative source입니다.

핵심 목표는 넓은 취약점 연구가 아니라 다음 실행 루프입니다.

```text
minimal observation
→ concrete exploit hypotheses (최대 3개)
→ cheapest decisive experiment
→ kill or promote
→ smallest working PoC
→ declared remote as soon as plausible
→ print the first valid flag
→ human submission
→ optional verification
```

## 준비

Official competition runtime: **WSL2 Ubuntu 또는 Kali Linux x86_64 + Docker Engine + Docker Compose v2**. 팀 운영 기준의 host는 Windows 11입니다. 저장소는 Docker build context, forensic extraction, receipt ledger와 다수 파일의 원자적 동작 성능을 위해 `/home/<user>/CTF-OS` 같은 WSL2 Linux filesystem에 두는 것을 권장합니다. `/mnt/c`, `/mnt/d` 또는 다른 drvfs 위치는 경고만 발생하며 실행을 차단하지 않습니다. Native Ubuntu 또는 Kali Linux x86_64는 compatible environment입니다.

Docker Desktop 전용 기능은 요구하지 않습니다. WSL2 Ubuntu 안에서 `docker info`, `docker compose version`, `docker build`, `docker run`이 정상 동작하는 Docker Engine이면 됩니다. Python 3.11+와 `uv`도 필요합니다. GPU는 GPU-required workload가 있는 머신에서만 NVIDIA WSL2 GPU passthrough와 NVIDIA Container Toolkit을 선택 설치합니다. 일반 `docker build`가 기준이며 Buildx는 필수가 아닙니다. macOS, ARM64, multi-architecture image, host Podman runtime은 지원 범위가 아닙니다.

```bash
git clone git@github.com:whatevertakes/CTF-OS.git
cd CTF-OS
uv sync --frozen
sandbox/build-images.sh
uv run python -m ctf_os.agent_tools doctor
```

표준 사용 흐름은 다음과 같습니다.

1. 최소 `contest.md`가 있는 대회 workspace를 선택합니다.
2. 문제 파일을 해당 contest 내부에 둡니다.
3. 현재 Sol 세션에 문제·설명·원격 정보와 함께 풀이라고 요청합니다.
4. CTF-OS가 해당 문제만 challenge-local하게 준비합니다.
5. 같은 Sol 세션이 즉시 문제 풀이를 진행합니다.

Whole-contest Intake와 Triage는 사용자가 전체 대회 inventory 또는 ranking을 명시적으로 요청할 때만 쓰는 optional legacy/admin 도구입니다. Solve의 선행 단계나 readiness source가 아니며, 현재 운영은 전체 Board·난이도·성공확률로 개별 challenge를 유도하지 않습니다.

## Low-level CLI debugging

다음 수동 호출은 session input 저장과 runtime loader를 진단하기 위한 저수준 예시이며, 정상 대회 운영에서 사용자가 수행할 단계가 아닙니다.

```bash
uv run python -m ctf_os.agent_tools prepare-challenge misc/PromptOnly \
  --contest "My CTF 2026" \
  --session-input-json '{"category":"misc","name":"PromptOnly","description":"problem text","flag_format":"CTF{...}","remotes":["nc challenge.example 31337"],"source_paths":["uploads/challenge.bin"]}'
```

`source_paths`는 선택한 대회의 `incoming/<contest>/` 아래 경로만 허용됩니다. 정규화된 packet은 해당 문제 workspace의 `SESSION-INPUT.json`에 저장되고, 이후 runtime command는 같은 challenge-local 정의와 authorized target을 다시 사용합니다.

## 실제 solve 흐름

“1번 문제 풀어”는 다음 동작을 목표로 합니다.

```text
selected challenge resolution
→ challenge-local preflight
→ deterministic challenge instance와 독립 attempt에 결합된 run 생성/선택
→ category command budget 안의 minimal recon
→ concrete exploit hypotheses 선택
→ decisive experiments 즉시 실행
→ evidence-driven native branches에서 minimal PoC 경쟁
→ exploit proximity가 오르는 첫 경로 promote
→ plausible해지는 즉시 declared remote 시도
→ exact flag와 SUBMISSION_RECOMMENDED 출력
→ 사람이 제출
→ WRONG이면 exact candidate만 refute하고 계속 풀이
→ ACCEPTED이면 branch stop·sandbox/resource cleanup·run seal
```

Race의 목적은 여러 연구 관점을 모으는 것이 아닙니다. Authoritative runtime 개념은 tier 숫자가 아니라 `sol-only`, `fixed-race`, `adaptive-race` solve mode입니다. 일반 대회 기본값인 `adaptive-race`는 Sol만 `RUNNING`, active child width 0, 60~90초 bounded observation pending 상태로 즉시 시작합니다. 이후 증거와 capacity가 뒷받침하는 서로 다른 mechanism 0~3개만 계획하며 plateau/refutation 근거가 있을 때 replacement를 최대 한 번 허용합니다. `fixed-race`는 frozen category template의 정확히 세 child intent를 사용하고 width 변경과 replacement를 금지합니다. `sol-only`는 child를 계획하거나 시작하지 않습니다.

Legacy tier는 삭제되지 않았지만 compatibility/resource envelope 또는 maximum-width hint일 뿐입니다. Tier 0은 `sol-only`, Tier 1~4는 `adaptive-race`로 결정적으로 매핑되며 tier 자체가 child 생성, active width, benchmark arm, model 또는 reasoning을 결정하지 않습니다. `--mode`와 `--tier`가 충돌하면 명령은 실패합니다. Category template는 `fixed-race`의 frozen treatment 또는 adaptive mode에서 증거가 아직 부족할 때만 쓰는 fallback입니다.

Sol은 coordinator로 대기하지 않고 core primitive reasoning, 어려운 exploit-chain 결정, minimal PoC synthesis, artifact takeover, remote execution, flag judgment을 직접 수행합니다. `independent-full-solve`도 comprehensive analysis가 아니라 가장 짧은 flag 경로를 독립적으로 달리는 lane입니다.

## Race와 checkpoint CLI

```bash
uv run python -m ctf_os.agent_tools race-plan-start 1 --contest my-ctf \
  --mode adaptive-race --branch-spec '<evidence-bound mechanisms JSON>'
uv run python -m ctf_os.agent_tools race-board 1 --contest my-ctf
uv run python -m ctf_os.agent_tools race-event-publish 1 --contest my-ctf \
  --type EXPLOIT_PRIMITIVE_CONFIRMED --summary 'byte oracle confirmed' --priority HIGH \
  --primitive-json '{"claimed_capability":"byte oracle","positive_assertion_receipt":"positive.json","negative_control_assertion_receipt":"negative.json","observed_result":"target differs from control","success_condition_satisfied":true,"kill_condition_evaluated":true,"artifact_or_command_receipt":"python3 oracle.py --control","next_poc_linking_experiment":"recover one byte"}'
uv run python -m ctf_os.agent_tools race-insight-packet 1 --contest my-ctf \
  --target-session-id race-3-independent-full-solve
```

`race-plan-start`는 current run의 append-only `RACE_LINEAGE.jsonl`에 `PLANNED` branch와 짧은 prompt packet을 기록할 뿐 child를 만들지 않습니다. `PLANNED → CAPACITY_ADMITTED → SANDBOX_READY → AWAITING_NATIVE_START → NATIVE_STARTED → RUNNING`이 모두 exact receipt로 이어져야 active width에 포함됩니다. 계획 수와 active width는 항상 별도입니다. Initial/replacement branch는 같은 lifecycle을 사용하고, started branch는 native stop/terminal 및 cleanup/resource release receipt 없이 supersede할 수 없습니다. `DELEGATION_PLAN.json`과 `STATE.branches`는 lineage projection입니다. Python은 native child를 생성하거나 종료하지 않습니다.

Milestone receipt와 `RACE_LINEAGE.jsonl`은 각각 milestone과 branch lifecycle의 authoritative source이고 progress, timing, candidate, `DELEGATION_PLAN`, `STATE.branches`, race transition, control action, scheduler 및 compatibility 파일은 재생 가능한 projection입니다. `sequence`는 표시 순서일 뿐 identity가 아닙니다. 같은 canonical material은 같은 receipt를 반환하며, 별개의 동일 실험은 다른 `--operation-id`로 구분합니다. 같은 operation ID에 다른 command·output·artifact·details를 재사용하면 conflict입니다.

## Attempt identity와 resume

`challenge_instance_id`는 challenge ID, prepared input tree, metadata, target revision, flag metadata, optional local target image, transformation seed를 포함한 snapshot의 deterministic identity입니다. `attempt_id`는 실행마다 새로 발급되는 독립 identity이고 `run_id`는 두 identity에 결합됩니다. 새 attempt는 이전 ledger, candidate, evidence/artifact/work, worker/model/sandbox/container/port/cache identity를 상속하지 않으며 read-only challenge snapshot만 공유합니다.

```bash
uv run python -m ctf_os.agent_tools attempt-start 1 --contest my-ctf --mode adaptive-race
uv run python -m ctf_os.agent_tools attempt-list 1 --contest my-ctf
uv run python -m ctf_os.agent_tools attempt-show 1 --contest my-ctf --run-id '<exact-run-id>'
uv run python -m ctf_os.agent_tools attempt-resume 1 --contest my-ctf --run-id '<exact-run-id>'
```

기존 `prepare-challenge`는 compatibility상 current attempt를 resume합니다. 독립 실행은 `attempt-start` 또는 `prepare-challenge --fresh-attempt`를 사용하고 exact prior run은 `--resume-run-id`로 지정합니다. 기존 content-derived legacy run은 이동·삭제·수정하지 않으며 reader가 deterministic legacy attempt marker와 derived challenge instance를 제공합니다. Benchmark launcher는 `ACTIVE_RUN`을 읽지 않고 schedule의 exact fresh `attempt_id`와 반환된 `run_id`만 사용합니다.

```bash
uv run python -m ctf_os.agent_tools milestone-save 1 --contest my-ctf \
  --type DECISIVE_EXPERIMENT --summary 'oracle differs from control' \
  --operation-id oracle-positive-v1 -- python3 probe.py

uv run python -m ctf_os.agent_tools repair-run 1 --contest my-ctf --run-id '<run-id>'
uv run python -m ctf_os.agent_tools repair-projections 1 --contest my-ctf --run-id '<run-id>'
```

`repair-run`은 human submission, verified remote receipt, candidate, milestone, native/terminal/resource ledger와 run manifest에서 exact run의 `STATE.json`만 재구성합니다. 손상된 원본은 `STATE.corrupt-*.json`으로 보존합니다. `repair-projections`는 authoritative receipt의 `PENDING`/`FAILED` projection만 재생하며 `APPLIED`는 반복하지 않습니다.

Checkpoint는 보고서가 아니라 현재 exploit action을 전달합니다: leading hypothesis, decisive experiment, observed result, exploit proximity, artifact, next action, kill/continue/promote. Primitive는 `CANDIDATE`, `CONFIRMED`, `REFUTED`로 분리하며 candidate는 confirmed progress가 아닙니다. Confirmed primitive와 plateau 등 high-value transition은 utility sweep, duplicate/stalled 정리 recommendation, 필수 Sol takeover packet을 자동 생성합니다. Scheduler는 long-compute opt-in이고 timeout sandbox 보존은 profile에 따릅니다. Supported fact, rejected hypothesis, decompilation, 일반 artifact의 수만 늘어나는 것은 progress가 아닙니다.

Control action의 `applied`는 일반 acknowledgement로 만들 수 없습니다. `control-action-ack`는 declined/superseded/expired만 처리하고, 실제 run-local receipt가 있는 적용만 다음 명령으로 확정합니다.

```bash
uv run python -m ctf_os.agent_tools control-action-apply 1 --contest my-ctf \
  --action-id '<action-id>' --receipt-json '<exact-proof-json>'
```

`sandbox-exec`의 canonical syntax는 `sandbox-exec --metadata workers/<branch>/sandbox.json --timeout-profile quick_probe --session-id <branch> -- <command...>`입니다. Legacy positional metadata는 읽지만, `--` 뒤의 CTF-OS control option은 container command로 넘기지 않고 실행 전에 오류로 차단합니다.

## Sandbox, service, resource

Challenge input/context는 read-only이고 worker별 `/work`, `/evidence`, `/artifacts`만 writable입니다. Pwn/rev/misc는 필요한 ptrace/GDB/core, forensic은 read-only loop mount, AI는 사용 가능한 NVIDIA GPU를 격리된 sandbox 안에서 지원합니다. Host Docker socket/root, SSH key, browser profile, 개인 cloud/kubeconfig는 mount하지 않습니다. Shared service는 Sol 전용이고 child는 자기 exact-label branch-private service만 조작합니다.

짧은 probe나 빠른 PoC 앞에서는 resource 명령을 반복하지 않습니다. Scheduler는 다음과 같은 긴 계산 전에만 계획합니다.

```text
symbolic execution / fuzzing / forensic scan / crypto or cracking / AI inference
```

긴 계산은 1800초 bounded slice로 실행하고 exploit/solver proximity 또는 필요한 compute progress가 있을 때만 계속합니다. `LONG_COMPUTE`는 sandbox/container/process identity, exact argv, branch-local artifact, completion marker, 최대 시간과 checkpoint 간격을 receipt에 결합합니다. Heartbeat caller의 boolean은 증거가 아니며 Python이 같은 process argv와 실제 artifact digest/size/mtime 변화를 직접 관찰한 경우에만 갱신됩니다. Scheduler scale-up도 유효기간 안의 이 검증 receipt가 있어야 합니다. 새 병렬 solver/harness는 고정 worker 수 대신 다음 값을 사용합니다.

```python
import os

workers = max(1, int(os.environ.get("CTF_OS_RECOMMENDED_WORKERS", "1")))
```

Scheduler는 자원을 배분할 뿐 solve progress나 native lifecycle을 소유하지 않습니다. 관리가 solver reasoning, minimal PoC, remote attempt, flag 출력보다 앞설 수 없습니다.

## Claude 구조대 브리지

`CTF-OS-main`은 Codex Solve와 exact-run 보호 상태를 소유하고, Claude 실행 구현과 workspace는 별도 `~/CTF-OS-claude`가 소유합니다. Codex에게 `Claude 구조대 준비해라`라고 요청하면 main의 얇은 브리지가 새 저장소의 런타임을 호출합니다. 생성되는 packet, MCP, hook, toolchain, writable `work/evidence/artifacts`는 모두 `~/CTF-OS-claude/runs/` 아래에 놓이고, main run에는 lifecycle ledger와 검증된 경로 포인터만 남습니다.

Claude는 자동 실행되지 않습니다. 출력된 `Path`로 이동한 뒤 출력된 `Start command`를 사용자가 별도 터미널에서 실행합니다. 완료 후 기존 Codex 세션에서 `Claude 구조대 결과 이어서 원격 플래그까지 풀어라`를 요청하면 같은 브리지를 통해 return을 검증하고 기존 protected flag 경로로 복귀합니다.

기본 설치 위치는 `~/CTF-OS-claude`이며 다른 위치를 쓸 때는 `CTF_OS_CLAUDE_HOME`을 설정합니다. 저수준 CLI 표면은 기존과 동일하고 exact `--run-id`를 반드시 요구합니다.

```bash
uv run python -m ctf_os.agent_tools rescue-prepare 1 --contest my-ctf \
  --run-id '<exact-run-id>' --mode PRIMITIVE_TO_POC --profile standard \
  --research-policy offline \
  --objective 'confirmed primitive을 executable remote PoC로 연결' \
  --current-blocker 'remote protocol framing이 아직 검증되지 않음' \
  --operation-id 'manual-rescue-poc-v1'

uv run python -m ctf_os.agent_tools rescue-show 1 --contest my-ctf \
  --run-id '<exact-run-id>' --rescue-id '<rescue-id>'

uv run python -m ctf_os.agent_tools rescue-return-validate 1 --contest my-ctf \
  --run-id '<exact-run-id>' --rescue-id '<rescue-id>'

uv run python -m ctf_os.agent_tools rescue-flag-promote 1 --contest my-ctf \
  --run-id '<exact-run-id>' --rescue-id '<rescue-id>' \
  --execution-receipt-id '<command-or-session-observation-id>' \
  --candidate 'CTF{...}' --exploit-artifact 'artifacts/solve.py'

uv run python -m ctf_os.agent_tools rescue-close 1 --contest my-ctf \
  --run-id '<exact-run-id>' --rescue-id '<rescue-id>' --outcome integrated
```

런타임 설계, 격리, interactive tool, research lane, live test 문서는 [`../CTF-OS-claude/docs/`](../CTF-OS-claude/docs/)에 있습니다. main은 Claude CLI나 모델 API를 실행·감독하지 않으며 flag 제출도 자동화하지 않습니다.

## Scope와 flag fast path

Organizer-declared public/private/VPN/IPv6 target과 tcp, udp, http(s), tls, websocket/wss, dns, ssh, grpc, custom protocol을 지원합니다. Cloud metadata, Docker gateway, undeclared LAN, unrelated host, 다른 challenge는 차단됩니다. Challenge temporary credential은 declared account/domain 안에서만 worker-private으로 사용하고 mutation을 기록합니다.

현재 challenge의 declared target에서 실제 관찰한 output, exact command receipt, pattern-matching candidate, existing exploit artifact가 있으면 `flag-receipt-save`가 즉시 다음 상태를 만듭니다.

```text
REMOTE FLAG OBTAINED
Flag: CTF{...}
Confidence: HIGH
State: SUBMISSION_RECOMMENDED
Recommendation: submit immediately
Full clean replay: not required before human submission
```

저가치 branch를 중단하고 verifier는 최대 하나만 남길 수 있습니다. CTFd 자동 제출은 없으며 사람이 제출합니다. Strict replay는 나중에 `FULLY_VERIFIED`를 만들 수 있지만 flag 공개의 gate가 아닙니다.

검증된 local PoC를 lead Sol이 declared remote에 한 번 명시적으로 연결할 때는 `working-poc-commit`을 사용합니다. 이 명령은 direct argv만 받고 sandbox ownership, fingerprint, target revision, local receipt와 artifact digest를 검증합니다. Remote executor 직전에 `EXECUTION_STARTED` intent와 attempt ID를 원자적으로 저장합니다. 완료된 operation은 재실행하지 않으며, intent 뒤 결과 저장 전에 중단된 operation은 `EXECUTION_OUTCOME_UNKNOWN`으로 고정하여 자동 재시도를 차단합니다.

```bash
uv run python -m ctf_os.agent_tools working-poc-commit 1 --contest my-ctf \
  --run-id '<run-id>' --branch '<branch-id>' \
  --metadata 'output/.../runs/<run-id>/workers/<branch-id>/sandbox.json' \
  --local-receipt-id '<receipt-id>' --exploit-artifact 'exploit/solve.py' \
  --target-index 0 --success-condition 'flag in output' \
  --kill-condition 'remote rejects exploit' --operation-id remote-poc-v1 \
  -- python3 /artifacts/solve.py '<host>' '<port>'
```

Unknown outcome은 같은 operation ID에 `--force`를 붙여 재실행하지 않습니다. 운영자가 보존된 execution receipt를 검증해 projection을 계속하거나, 기존 operation을 폐기하거나, 새 operation ID에만 retry를 승인합니다.

```bash
uv run python -m ctf_os.agent_tools working-poc-resolve-unknown 1 --contest my-ctf \
  --run-id '<run-id>' --operation-id remote-poc-v1 \
  --decision RECORD_RESULT --receipt-json '<exact-execution-receipt-json>'

uv run python -m ctf_os.agent_tools working-poc-resolve-unknown 1 --contest my-ctf \
  --run-id '<run-id>' --operation-id remote-poc-v1 \
  --decision AUTHORIZE_RETRY --new-operation-id remote-poc-v2 \
  --receipt-json '<operator-authorization-receipt-json>'
```

Docker 회귀는 선택 profile build를 그대로 지원하며 실패한 profile 뒤에도 나머지를 빌드하고 마지막 summary에 성공/실패를 남깁니다. 실제 환경에서는 다음 marker로 image operation probe, sandbox lifecycle, service isolation을 각각 실행합니다.

```bash
CTF_OS_LIVE_IMAGE_TESTS=1 uv run pytest -q tests/test_build_images_live.py
CTF_OS_LIVE_SANDBOX_TESTS=1 uv run pytest -q tests/test_sandbox_live.py
CTF_OS_LIVE_SERVICE_TESTS=1 uv run pytest -q tests/test_service_live.py
```

## 성능 검증

Unit test는 정책·회귀를 검증할 뿐 solve 성능의 증명이 아닙니다. Signed read-only lock과 독립 attempt를 사용하는 plain Sol(A), CTF-OS sol-only(B), fixed-race(C), adaptive-race(D)의 matched benchmark 및 evaluator 계약은 [`docs/SOLVER_BENCHMARK.md`](docs/SOLVER_BENCHMARK.md)에 정의되어 있습니다. 144-run 결과가 수집되기 전 plain Sol 대비 우월성은 `INCONCLUSIVE`입니다.

비-live CI는 `CTF-OS / unit-policy`, `attempt-lineage`, `benchmark-evaluator`, `compile` check로 full pytest, Second Surgery fault injection, working-PoC unknown outcome, LONG_COMPUTE proof, identity/lineage/lock/evaluator/schema migration, compileall과 repository policy를 검증합니다. Docker/WSL2 image·sandbox·service probe는 별도 manual self-hosted `CTF-OS Live` workflow입니다.
