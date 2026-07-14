# CTF-OS

CTF-OS는 사용자가 직접 연 Sol 세션을 lead attacker로 유지하면서, 제한 시간 안에 첫 flag를 얻도록 native solver race를 지원하는 로컬 CTF 도구입니다. Python은 model/API를 실행하지 않고 manifest, race ledger, sandbox, target policy, event bus, artifact, receipt와 replay만 담당합니다.

핵심 계약은 단순합니다.

```text
Sol is the lead attacker and race coordinator.
Use native delegation aggressively.
Start multiple independent paths early.
Share confirmed insights quickly.
Replace stalled branches instead of giving up.
Surface a remote flag immediately.
Human submission is the competition oracle.
Full replay improves confidence but does not delay the flag.
```

## 준비

Python 3.11+, `uv`, 실행 중인 Docker Engine과 Compose v2가 필요합니다.

```bash
git clone git@github.com:whatevertakes/CTF-OS.git
cd CTF-OS
uv sync --frozen
sandbox/build-images.sh
uv run python -m ctf_os.agent_tools doctor
uv run python -m ctf_os.agent_tools init-contest "My CTF 2026"
```

문제 파일을 `incoming/<contest>/<category>/`에 넣고 `incoming/<contest>/problems.txt`에 문제/target을 기록합니다. 이후 Sol에게 별도 세션에서 순서대로 “intake 해”, “triage 해”, “1번 문제 풀어”라고 요청합니다. Intake는 내부 `contest.md`와 workspace를 만들고, Triage는 원본을 열거나 exploit하지 않은 채 추천 Board만 만듭니다.

## 실제 solve 흐름

“1번 문제 풀어” 한 문장으로 다음이 기본 실행됩니다.

```text
prepare-challenge
→ 60~90초 compact recon
→ race tier 결정
→ race-plan-start로 plan/admission/prompt packet 원자 생성
→ Codex runtime native child 2~4개 즉시 위임
→ child별 sandbox + Sol 자체 deep-solve lane
→ live event/insight 공유
→ plateau branch bump/교체 또는 Sol takeover
→ 첫 declared-remote flag receipt
→ SUBMISSION_RECOMMENDED와 정확한 flag 즉시 출력
→ 사람이 제출
→ 필요하면 verifier/replay로 FULLY_VERIFIED
```

Tier 1은 child 2개, Tier 2는 3개, Tier 3은 4개가 기본입니다. Tier 4는 child 수를 계속 늘리는 단계가 아니라 낮은 가치의 branch를 새 attack family로 교체하며 사용 가능한 concurrency를 유지하는 단계입니다. Sol도 coordinator로 기다리지 않고 항상 핵심 primitive, 어려운 분석, solver 결합, remote exploit 중 하나를 직접 수행합니다.

## Race와 live insight CLI

```bash
uv run python -m ctf_os.agent_tools race-plan-start 1 --contest my-ctf --tier 2
uv run python -m ctf_os.agent_tools race-board 1 --contest my-ctf
uv run python -m ctf_os.agent_tools race-event-publish 1 --contest my-ctf \
  --type EXPLOIT_PRIMITIVE --summary 'byte oracle confirmed' --priority HIGH
uv run python -m ctf_os.agent_tools race-events-show 1 --contest my-ctf
uv run python -m ctf_os.agent_tools race-insight-packet 1 --contest my-ctf \
  --target-session-id race-3-independent-full-solve
uv run python -m ctf_os.agent_tools operator-hint-save 1 --contest my-ctf \
  --summary 'libc is 2.35; switch to heap path'
```

`race-plan-start`는 fingerprint를 검사하고 이전 plan을 STALE archive로 보존하며, exact duplicate만 거부하고, 모든 branch record와 native delegation prompt packet을 한 번에 기록합니다. 이 명령은 child를 생성하지 않습니다. Sol이 packet을 사용해 native delegation을 수행합니다.

Admission overlap 기본값은 0.95이고 advisory입니다. `independent-full-solve`, parallel race, alternate role/implementation, verification, plateau escape는 중복 허용 목적입니다. Requested model/reasoning은 관측된 pinning이 아니며 evidence가 없으면 observed 필드는 `null`입니다.

Event bus는 supported/rejected fact, primitive, blocker, artifact, next experiment, flag, service crash와 operator hint를 append-only로 보존합니다. 동일 event ID는 idempotent하고 충돌 facts는 병렬 보존됩니다. `branch-utility`는 `PROGRESSING`, `NEEDS_SIBLING_INSIGHT`, `BUMP_AND_RETRY`, `REPLACE_ATTACK_FAMILY`, `SOL_TAKEOVER`, `FLAG_PATH`, `DEAD_BRANCH`, `INSUFFICIENT_DATA`를 추천하지만 native child lifecycle은 Sol만 조정합니다.

## Sandbox, service, resource

Challenge/input와 context는 read-only이고 worker별 `/work`, `/evidence`, `/artifacts`만 writable입니다. Pwn/rev/misc는 ptrace/GDB/core와 필요한 permissive seccomp를, forensic은 read-only loop mount에 필요한 capability/device를, AI는 사용 가능한 NVIDIA GPU를 자동 적용합니다. Docker socket, host root, SSH key, browser profile, 개인 cloud/kubeconfig는 절대 mount하지 않습니다.

긴 도구는 profile slice로 실행합니다.

```text
quick_probe 60s        normal_command 300s       decompile 900s
symbolic/fuzz/forensic/crypto/cracking/AI slice 1800s
```

```bash
uv run python -m ctf_os.agent_tools sandbox-exec --timeout-profile symbolic_slice \
  workers/x/sandbox.json -- python3 /work/solve.py
```

Resource admission은 profile별 고정 concurrency나 heavy 단일 실행 제한 대신 host/Docker/cgroup/user cap 중 최소 상한, 현재 CPU/RAM/storage/GPU reservation과 실측 utilization, host reserve(메모리 max(4GiB, 15%), CPU 1~2개, storage max(10GiB, 10%)), workload 가치와 progress를 사용합니다. `light`/`standard`/`heavy`/`large-forensic`는 기존 metadata 호환용이며 hard gate가 아닙니다. 지표 일부를 읽지 못하면 `observation_mode: DEGRADED`로 계속 동작합니다.

```bash
uv run python -m ctf_os.agent_tools resource-status
uv run python -m ctf_os.agent_tools resource-request 1 --contest my-ctf \
  --workload-class symbolic-execution --priority HIGH
uv run python -m ctf_os.agent_tools resource-plan 1 --contest my-ctf
uv run python -m ctf_os.agent_tools resource-sample 1 --contest my-ctf \
  --metadata output/my-ctf/rev/challenge/workers/symbolic-1/sandbox.json
uv run python -m ctf_os.agent_tools scheduler-rebalance 1 --contest my-ctf
uv run python -m ctf_os.agent_tools sandbox-resize \
  output/my-ctf/rev/challenge/workers/symbolic-1/sandbox.json --cpus 8 --memory 14g
uv run python -m ctf_os.agent_tools resource-history 1 --contest my-ctf
```

Scheduler는 CRITICAL/HIGH minimum을 먼저 보존하고 flag/exploit/Sol direct lane, progress가 확인된 symbolic/fuzz/crypto/forensic 계산을 preferred/max까지 확장합니다. 단순 CPU 포화만으로 확장하지 않으며 busy loop·반복 오류·checkpoint/artifact 정지는 `BUMP_AND_RETRY`/교체/takeover 권고로 전환합니다. 반대로 낮은 CPU와 network/IO progress가 함께 있으면 축소하지 않습니다. 완료/오류/교체/cleanup/remote flag 이후 자원은 즉시 release되고 evidence와 history는 남습니다.

새로 작성하는 병렬 solver/harness는 고정 `max_workers` 대신 다음 값을 사용합니다.

```python
import os

workers = max(1, int(os.environ.get("CTF_OS_RECOMMENDED_WORKERS", "1")))
```

모든 sandbox는 allocated CPU/RAM/workload/priority와 OpenMP/BLAS/Rayon thread 환경을 받으며, resize 뒤의 `sandbox-exec`에는 최신 값이 전달됩니다. Sol은 scheduler가 계산을 배분하는 동안 계속 직접 공격하고 native child lifecycle은 계속 Sol만 관리합니다.

Shared `challenge-service` lifecycle은 Sol 전용입니다. Crash/fuzz branch는 자기 session ID와 정확히 일치하는 `branch-service-*` instance를 build/start/restart/reset/log/inspect/stop/cleanup할 수 있으나 shared/sibling/host Docker는 조작할 수 없습니다.

## Target, OAST, Cloud/OSINT/AI

Organizer-declared public/private/VPN/IPv6 target과 tcp, udp, http, https, tls, websocket, wss, dns, ssh, grpc, custom protocol, 여러 host/port를 지원합니다. Private target은 structured declaration의 `organizer_declared: true`가 필요합니다. Cloud metadata, Docker gateway, undeclared LAN, 다른 challenge target, unrelated host exploit/scan은 계속 차단됩니다.

`oast-create`, `oast-poll`, `oast-events`는 명시적으로 승인된 HTTPS OAST provider의 blind XSS/SSRF/XXE/bot callback receipt를 challenge-local로 보존하며 cookie/token/credential을 redact합니다.

문제가 제공한 임시/가상 credential은 worker-private storage에서 사용할 수 있습니다. 선언된 cloud account/project/tenant에서는 enumeration, role assume/impersonation, object/workload/function 작업과 exploit에 필요한 IAM/RBAC mutation을 ledger에 남기고 수행할 수 있습니다. 개인/ambient credential과 scope 밖 account는 금지됩니다. AI model은 sandbox 안에서 검사하며 host pickle/joblib 역직렬화와 `trust_remote_code=True`는 금지합니다.

## Flag fast path

`flag-receipt-save`는 현재 challenge의 declared target, 실제 network observation, exact command output, flag pattern과 existing exploit artifact를 검사합니다. 조건을 만족하면 두 번 replay를 기다리지 않고 즉시 다음을 반환하고 `RESULT.md`를 갱신합니다.

```text
REMOTE FLAG OBTAINED
Flag: CTF{...}
Confidence: HIGH
State: SUBMISSION_RECOMMENDED
Recommendation: submit immediately
Full clean replay: not required before human submission
```

이때 저가치 branch 종료와 verifier 최대 1개 유지가 권고됩니다. 자동 CTFd submission은 존재하지 않습니다. 기존 strict `replay`는 더 높은 품질 상태 `FULLY_VERIFIED`를 만들지만 flag 공개나 사람 제출의 선행 gate가 아닙니다.

## 보안 경계

유지되는 경계는 challenge scope, read-only 원본, worker/challenge 격리, host SSH/browser/personal cloud 접근 금지, host Docker socket/root mount 금지, metadata/undeclared LAN/out-of-scope scan 금지, 자동 flag 제출 금지, Python model launcher/API 금지뿐입니다. 그 안에서는 실제 첫 flag 속도를 우선합니다.
