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

Python 3.11+, `uv`, 실행 중인 Docker Engine과 Compose v2가 필요합니다.

```bash
git clone git@github.com:whatevertakes/CTF-OS.git
cd CTF-OS
uv sync --frozen
sandbox/build-images.sh
uv run python -m ctf_os.agent_tools doctor
uv run python -m ctf_os.agent_tools init-contest "My CTF 2026"
```

문제 파일을 `incoming/<contest>/<category>/`에 넣고 `incoming/<contest>/problems.txt`에 문제와 organizer-declared target을 기록합니다. 별도 세션에서 “intake 해”, “triage 해”, “1번 문제 풀어” 순으로 요청합니다. Intake는 내부 context를 만들고, Triage는 원본을 exploit하지 않은 채 추천 Board만 만듭니다.

## 실제 solve 흐름

“1번 문제 풀어”는 다음 동작을 목표로 합니다.

```text
prepare
→ category command budget 안의 minimal recon
→ concrete exploit hypotheses 선택
→ decisive experiments 즉시 실행
→ evidence-driven native branches에서 minimal PoC 경쟁
→ exploit proximity가 오르는 첫 경로 promote
→ plausible해지는 즉시 declared remote 시도
→ exact flag와 SUBMISSION_RECOMMENDED 출력
→ 사람이 제출
→ 필요할 때만 verifier/replay
```

Race의 목적은 여러 연구 관점을 모으는 것이 아닙니다. 서로 다른 exploit mechanism을 짧게 경쟁시키고, 새로운 정보가 생기더라도 exploit proximity가 증가하지 않는 branch를 빠르게 takeover 또는 교체하는 것입니다. Tier 1/2/3은 기본 child 2/3/4개이고, Tier 4는 stalled branch를 왜 flag에 가까워지지 못했는지 기록한 뒤 완전히 다른 mechanism으로 교체합니다. Category template는 증거가 부족할 때만 쓰는 fallback입니다.

Sol은 coordinator로 대기하지 않고 core primitive reasoning, 어려운 exploit-chain 결정, minimal PoC synthesis, artifact takeover, remote execution, flag judgment을 직접 수행합니다. `independent-full-solve`도 comprehensive analysis가 아니라 가장 짧은 flag 경로를 독립적으로 달리는 lane입니다.

## Race와 checkpoint CLI

```bash
uv run python -m ctf_os.agent_tools race-plan-start 1 --contest my-ctf --tier 2
uv run python -m ctf_os.agent_tools race-board 1 --contest my-ctf
uv run python -m ctf_os.agent_tools race-event-publish 1 --contest my-ctf \
  --type EXPLOIT_PRIMITIVE --summary 'byte oracle confirmed' --priority HIGH
uv run python -m ctf_os.agent_tools race-insight-packet 1 --contest my-ctf \
  --target-session-id race-3-independent-full-solve
```

`race-plan-start`는 fingerprint, admission, branch record와 짧은 prompt packet을 원자적으로 기록할 뿐 child를 만들지 않습니다. Sol이 native delegation을 수행합니다. Admission overlap 0.95는 advisory이고 exact duplicate/repeated session ID만 거부합니다. Requested model/reasoning은 pinning 증거가 아닙니다.

Checkpoint는 보고서가 아니라 현재 exploit action을 전달합니다: leading hypothesis, decisive experiment, observed result, exploit proximity, artifact, next action, kill/continue/promote. `REMOTE_FLAG_OBTAINED`, `FLAG_CANDIDATE`, `WORKING_POC`, `EXPLOIT_PRIMITIVE`는 summary보다 먼저 게시합니다. Supported fact, rejected hypothesis, decompilation, 일반 artifact의 수만 늘어나는 것은 progress가 아닙니다.

## Sandbox, service, resource

Challenge input/context는 read-only이고 worker별 `/work`, `/evidence`, `/artifacts`만 writable입니다. Pwn/rev/misc는 필요한 ptrace/GDB/core, forensic은 read-only loop mount, AI는 사용 가능한 NVIDIA GPU를 격리된 sandbox 안에서 지원합니다. Host Docker socket/root, SSH key, browser profile, 개인 cloud/kubeconfig는 mount하지 않습니다. Shared service는 Sol 전용이고 child는 자기 exact-label branch-private service만 조작합니다.

짧은 probe나 빠른 PoC 앞에서는 resource 명령을 반복하지 않습니다. Scheduler는 다음과 같은 긴 계산 전에만 계획합니다.

```text
symbolic execution / fuzzing / forensic scan / crypto or cracking / AI inference
```

긴 계산은 1800초 bounded slice로 실행하고 exploit/solver proximity 또는 필요한 compute progress가 있을 때만 계속합니다. 새 병렬 solver/harness는 고정 worker 수 대신 다음 값을 사용합니다.

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

## 성능 검증

Unit test는 정책·회귀를 검증할 뿐 solve 성능의 증명이 아닙니다. Plain Sol, Sol-only, fixed race, evidence-driven race를 비교하는 실제 benchmark 계획과 time-to-flag 지표는 [`docs/SOLVER_BENCHMARK.md`](docs/SOLVER_BENCHMARK.md)에 정의되어 있습니다.
