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

공식 대회 실행 환경은 Ubuntu Linux x86_64, Docker Engine, Docker Compose v2 plugin입니다. Python 3.11+와 `uv`도 필요합니다. GPU는 GPU-required workload가 있는 머신에서만 NVIDIA Container Toolkit으로 선택 설치합니다. 일반 `docker build`가 기준이며 Buildx는 필수가 아닙니다.

```bash
git clone git@github.com:whatevertakes/CTF-OS.git
cd CTF-OS
uv sync --frozen
sandbox/build-images.sh
uv run python -m ctf_os.agent_tools doctor
uv run python -m ctf_os.agent_tools init-contest "My CTF 2026"
```

표준 사용 흐름은 다음과 같습니다.

1. 현재 문제 파일 또는 디렉터리를 `incoming/<contest>/<category>/`의 해당 challenge 위치에 둡니다.
2. 문제 설명·힌트·플래그 형식과 optional organizer-declared remote를 `incoming/<contest>/problems.txt`에 기록하거나 현재 Sol 세션에 제공합니다.
3. 사용자가 연 그 Sol 세션에서 “이 문제 풀어라”, 문제 이름, 번호, 또는 `category/name`을 요청합니다.
4. CTF-OS가 현재 문제만 challenge-local preflight로 안전하게 준비하고 즉시 exploit-first solve를 시작합니다.
5. exact flag가 출력되면 사람이 제출합니다.

문제가 아직 `problems.txt`에 없고 현재 Sol 세션에서만 전달된 경우에는 전체 manifest를 수정하지 않고 문제별 packet으로 준비할 수 있습니다.

```bash
uv run python -m ctf_os.agent_tools prepare-challenge misc/PromptOnly \
  --contest "My CTF 2026" \
  --session-input-json '{"category":"misc","name":"PromptOnly","description":"problem text","flag_format":"CTF{...}","remotes":["nc challenge.example 31337"],"source_paths":["uploads/challenge.bin"]}'
```

`source_paths`는 선택한 대회의 `incoming/<contest>/` 아래 경로만 허용됩니다. 정규화된 packet은 해당 문제 workspace의 `SESSION-INPUT.json`에 저장되고, 이후 runtime command는 같은 challenge-local 정의와 authorized target을 다시 사용합니다.

Session packet merge는 JSON 필드의 존재 여부를 보존합니다. 생략한 필드는 기존 challenge, contest default, `standard` 순으로 상속하고, optional text의 명시적 `null`은 삭제, 빈 문자열은 오류입니다. 배열 생략은 상속, `[]`는 삭제입니다. `input_profile: "standard"`는 명시적 override입니다. `flag_format`을 바꾸고 `flag_pattern`을 생략하면 새 format에서 pattern을 결정적으로 재생성하고, 명시적 `flag_pattern: null`은 pattern을 삭제합니다. 입력과 remote가 모두 없어지는 packet은 preflight에서 `BLOCKED`입니다.

Whole-contest Intake와 Triage는 사용자가 전체 대회 inventory 또는 ranking을 명시적으로 요청할 때만 쓰는 optional legacy/admin 도구입니다. Solve의 선행 단계나 readiness source가 아니며, 현재 운영은 전체 Board·난이도·성공확률로 개별 challenge를 유도하지 않습니다.

## 실제 solve 흐름

“1번 문제 풀어”는 다음 동작을 목표로 합니다.

```text
selected challenge resolution
→ challenge-local preflight
→ fingerprint·target revision에 결합된 run 생성/선택
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

Race의 목적은 여러 연구 관점을 모으는 것이 아닙니다. 서로 다른 exploit mechanism을 짧게 경쟁시키고, 새로운 정보가 생기더라도 exploit proximity가 증가하지 않는 branch를 빠르게 takeover 또는 교체하는 것입니다. Tier 1/2/3은 기본 child 2/3/4개이고, Tier 4는 stalled branch를 왜 flag에 가까워지지 못했는지 기록한 뒤 완전히 다른 mechanism으로 교체합니다. Category template는 증거가 부족할 때만 쓰는 fallback입니다.

Sol은 coordinator로 대기하지 않고 core primitive reasoning, 어려운 exploit-chain 결정, minimal PoC synthesis, artifact takeover, remote execution, flag judgment을 직접 수행합니다. `independent-full-solve`도 comprehensive analysis가 아니라 가장 짧은 flag 경로를 독립적으로 달리는 lane입니다.

## Race와 checkpoint CLI

```bash
uv run python -m ctf_os.agent_tools race-plan-start 1 --contest my-ctf --tier 2
uv run python -m ctf_os.agent_tools race-board 1 --contest my-ctf
uv run python -m ctf_os.agent_tools race-event-publish 1 --contest my-ctf \
  --type EXPLOIT_PRIMITIVE_CONFIRMED --summary 'byte oracle confirmed' --priority HIGH \
  --primitive-json '{"claimed_capability":"byte oracle","positive_assertion_receipt":"positive.json","negative_control_assertion_receipt":"negative.json","observed_result":"target differs from control","success_condition_satisfied":true,"kill_condition_evaluated":true,"artifact_or_command_receipt":"python3 oracle.py --control","next_poc_linking_experiment":"recover one byte"}'
uv run python -m ctf_os.agent_tools race-insight-packet 1 --contest my-ctf \
  --target-session-id race-3-independent-full-solve
```

`race-plan-start`는 current run에 `PLANNED` branch와 짧은 prompt packet을 기록할 뿐 child를 만들지 않습니다. Capacity admission과 sandbox/input 확인 뒤 Sol이 native delegation 및 start receipt를 기록해야만 `RUNNING` width에 포함됩니다. Admission overlap 0.95는 advisory이고 exact duplicate/repeated session ID만 거부합니다. Requested model/reasoning은 pinning 증거가 아닙니다.

Milestone receipt는 authoritative source이고 progress, timing, candidate, STATE, race transition, control action, scheduler 및 compatibility 파일은 재생 가능한 projection입니다. `sequence`는 표시 순서일 뿐 identity가 아닙니다. 같은 canonical material은 같은 receipt를 반환하며, 별개의 동일 실험은 다른 `--operation-id`로 구분합니다. 같은 operation ID에 다른 command·output·artifact·details를 재사용하면 conflict입니다.

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

검증된 local PoC를 lead Sol이 declared remote에 한 번 명시적으로 연결할 때는 `working-poc-commit`을 사용합니다. 이 명령은 direct argv만 받고 sandbox ownership, fingerprint, target revision, local receipt와 artifact digest를 검증합니다. 같은 operation ID의 완료된 command는 다시 실행하지 않습니다.

```bash
uv run python -m ctf_os.agent_tools working-poc-commit 1 --contest my-ctf \
  --run-id '<run-id>' --branch '<branch-id>' \
  --metadata 'output/.../runs/<run-id>/workers/<branch-id>/sandbox.json' \
  --local-receipt-id '<receipt-id>' --exploit-artifact 'exploit/solve.py' \
  --target-index 0 --success-condition 'flag in output' \
  --kill-condition 'remote rejects exploit' --operation-id remote-poc-v1 \
  -- python3 /artifacts/solve.py '<host>' '<port>'
```

Docker 회귀는 선택 profile build를 그대로 지원하며 실패한 profile 뒤에도 나머지를 빌드하고 마지막 summary에 성공/실패를 남깁니다. 실제 환경에서는 다음 marker로 image operation probe, sandbox lifecycle, service isolation을 각각 실행합니다.

```bash
CTF_OS_LIVE_IMAGE_TESTS=1 uv run pytest -q tests/test_build_images_live.py
CTF_OS_LIVE_SANDBOX_TESTS=1 uv run pytest -q tests/test_sandbox_live.py
CTF_OS_LIVE_SERVICE_TESTS=1 uv run pytest -q tests/test_service_live.py
```

## 성능 검증

Unit test는 정책·회귀를 검증할 뿐 solve 성능의 증명이 아닙니다. Plain Sol, Sol-only, fixed race, evidence-driven race를 비교하는 실제 benchmark 계획과 time-to-flag 지표는 [`docs/SOLVER_BENCHMARK.md`](docs/SOLVER_BENCHMARK.md)에 정의되어 있습니다.
