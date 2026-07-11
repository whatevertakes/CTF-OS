# CTF-OS 설계도 v1.3 — Local-first Multi-Node CTF Agent

> 국내 CTF 우승 목표 자율 풀이 시스템  
> 기준일: 2026-07-10  
> 기반 아이디어: `verialabs/ctf-agent`의 challenge swarm / solver racing / message bus / sandbox 구조  
> 핵심 커스터마이징: CTFd 연동 제거, 중앙 executor 제거, 팀원별 로컬 노드, Codex CLI 기반 multi-strategy attempt race, TeamSync 기반 상태·플래그 공유

---

## 0. 한 줄 정의

CTF-OS는 **각 팀원이 자기 PC에서 자기 담당 카테고리를 자기 Codex CLI / GPT Pro 쿼터로 자동 풀이하고, 팀원끼리는 상태·플래그·간단한 findings만 동기화하는 Local-first CTF 자동 풀이 시스템**이다.

핵심 원칙:

```text
No central executor.
No remote worker stealing.
No shared Codex account.
No CTFd auto submit.
Each member solves locally.
Only team-local status / finding / flag synchronization.
```

---

## 1. 목표 시나리오

### 사용자가 원하는 실제 운영 그림

각 팀원은 자기 PC에서 한 번만 실행한다.

```bash
ctf-os run
```

그 뒤에는 사람이 문제 파일과 문제 정보를 넣는다.

```text
incoming/{대회명}/contest.md
incoming/{대회명}/{카테고리}/{문제명}.zip
```

그러면 각자의 로컬 노드가 자기 담당 카테고리만 자동으로 잡는다.

```text
지웅 PC
├── pwn / web / misc 문제 감지
├── Codex CLI 여러 개 병렬 실행
├── attempt별 Docker container 사용
├── 플래그 회수
└── TUI에 실시간 표시

주언 PC
├── rev / cloud 문제 감지
├── 주언 Codex CLI 여러 개 병렬 실행
├── 플래그 회수
└── TeamSync로 지웅과 상태 공유
```

즉, 서버가 팀원 PC를 통제하는 구조가 아니다.

```text
중앙 서버가 원격 워커를 부리는 구조 ❌
각자 로컬 노드가 자기 Codex를 굴리는 구조 ✅
```

---

## 2. ctf-agent에서 착안하는 부분과 제거하는 부분

### 2.1 가져올 아이디어

`verialabs/ctf-agent`에서 착안하는 핵심은 다음이다.

```text
challenge 단위 swarm
solver racing
coordinator guidance
message bus / shared findings
Docker sandbox
loop detection
operator hint
자동 산출물 기록
```

다만 원본의 “여러 API 모델을 병렬 경쟁시키는 구조”는 그대로 쓰지 않는다. 우리는 API 경쟁을 할 수 없으므로, **Codex CLI 세션 여러 개에 다른 역할과 전략을 부여해 경쟁시키는 구조**로 바꾼다.

```text
ctf-agent식 model race
        ↓
CTF-OS식 Codex CLI attempt race
```

### 2.2 제거하는 부분

```text
CTFd API polling 제거
CTFd 자동 submit 제거
중앙 executor 제거
중앙 scheduler 제거
원격 팀원 워커 제어 제거
공유 API key / 공유 Codex 계정 제거
```

최종 제출은 사람이 CTFd에 수동 제출한다.

---

## 3. 팀 구성 및 담당 카테고리

### 3.1 SCA CTF — 2팀 독립 출전

SCA는 같은 문제셋이어도 두 팀이 독립 출전한다. 따라서 `team_id`가 절대 섞이면 안 된다.

#### 지웅팀

```yaml
team_id: sca-jiwoong-team

members:
  jiwoong:
    display_name: 지웅
    categories: [pwn, web, misc]
    solvers: [codex, claude_optional]

  jueon:
    display_name: 주언
    categories: [rev, cloud]
    solvers: [codex]
```

#### 현석팀

```yaml
team_id: sca-hyunseok-team

members:
  hyunseok:
    display_name: 현석
    categories: [pwn, web, misc]
    solvers: [codex]

  howon:
    display_name: 호원
    categories: [rev, cloud]
    solvers: [codex]
```

### 3.2 KISIA — 4인 풀팀

```yaml
team_id: kisia-main

members:
  jiwoong:
    categories: [pwn, web]
    solvers: [codex, claude_optional]

  jueon:
    categories: [rev, cloud]
    solvers: [codex]

  hyunseok:
    categories: [crypto, web]
    solvers: [codex]

  howon:
    categories: [forensics, misc]
    solvers: [codex]
```

web처럼 담당자가 겹칠 수 있는 카테고리는 허용한다. 단, 같은 문제를 동시에 돌리면 TUI에서 중복 풀이 경고를 띄운다.

---

## 4. 전체 아키텍처

```text
각 팀원 PC
        ↓
[Local Watcher]
- incoming/ 폴더 감시
- contest.md 변경 감지
- zip 문제 파일 감지
        ↓
[ContestParser]
- 문제명 / 카테고리 / 점수 / 원격 / 설명 / 힌트 파싱
        ↓
[CategoryOwnership]
- member.owned_categories에 해당하는 문제만 선택
        ↓
[LocalCoordinator]
- 내 담당 문제 안에서 우선순위 결정
- 문제별 RacePlan 생성
        ↓
[LocalWorkerPool]
- 현재 PC의 Codex CLI subprocess만 실행
- 최대 5개 등 로컬 정책 적용
        ↓
[SolverEngine]
- ReAct&Plan 기반 풀이 루프
- RAG / playbook / previous findings 주입
- multi-strategy attempt race
        ↓
[DockerSandboxPool]
- image는 하나
- container는 attempt별 하나
        ↓
[FlagDetector / Verifier]
- stdout / evidence.log에서 후보 감지
- candidate와 solved 분리
        ↓
[ArtifactWriter]
- notes.md / evidence.log / exploit.py / replay.sh / writeup.md 저장
        ↓
[LocalState]
- SQLite로 상태 저장
        ↓
[Local TUI]
- 내 로컬 진행상황 + 팀 병합 상황 표시
        ↓
[TeamSync]
- sync/{team_id}/{member}.events.jsonl append-only 공유
```

---

## 5. 핵심 동작 원칙

### 5.1 Local-first

각 팀원은 독립 노드다.

```text
지웅 ctf-os는 지웅 Codex만 실행
주언 ctf-os는 주언 Codex만 실행
현석 ctf-os는 현석 Codex만 실행
호원 ctf-os는 호원 Codex만 실행
```

다른 사람의 머신, 프로세스, Docker, Codex 세션을 제어하지 않는다.

### 5.2 단일 터미널, 다중 Codex CLI

사용자는 터미널 하나에서 `ctf-os run`을 실행한다.

```text
terminal 1개
└── ctf-os run
    ├── codex exec subprocess 1: pwn/bof/recon_fast
    ├── codex exec subprocess 2: pwn/bof/exploit_main
    ├── codex exec subprocess 3: pwn/bof/exploit_alt
    ├── codex exec subprocess 4: web/sqli/exploit_fast
    └── codex exec subprocess 5: misc/stego/recon_fast
```

사용자가 Codex 창을 여러 개 직접 열 필요가 없다.

### 5.3 API 모델 경쟁이 아니라 strategy attempt race

우리는 API 기반 다중 모델 경쟁을 전제로 하지 않는다.

```text
API race ❌
- GPT API worker
- Claude API worker
- Gemini API worker
- Llama API worker

Codex CLI attempt race ✅
- 같은 Codex CLI를 여러 subprocess로 실행
- 각 subprocess에 다른 역할 / 전략 / 제약 / workdir 부여
- 먼저 플래그를 찾은 로컬 attempt가 승리
```

---

## 6. Codex CLI backend

### 6.1 기본 실행 방식

자동화에는 non-interactive 실행을 사용한다.

```bash
codex exec \
  -C /path/to/attempt/workdir \
  -m <model_name> \
  --dangerously-bypass-approvals-and-sandbox \
  "{rendered_worker_prompt}"
```

모델명은 설치된 Codex CLI와 계정에서 사용 가능한 이름으로 설정한다.

### 6.2 모델 선택 가능성

오케스트레이터가 정책에 따라 `-m <model>`을 선택할 수 있어야 한다.

```yaml
codex_models:
  default: "<default_codex_model>"
  fast: "<fast_codex_model>"
  strong: "<strong_codex_model>"
  fallback: "<fallback_codex_model>"

model_policy:
  easy:
    recon_fast: fast
    exploit_fast: default
    verifier: fast

  medium:
    recon_fast: fast
    exploit_main: strong
    exploit_alt: strong
    verifier: fast

  hard:
    recon_deep: strong
    source_deep: strong
    exploit_main: strong
    exploit_alt: strong
    fallback: fallback
    verifier: fast
```

Codex CLI가 특정 모델 선택을 지원하지 않거나 모델명이 바뀌면 config만 수정하면 된다.

### 6.3 CodexWorker 요구사항

```text
- subprocess.Popen 기반 실행
- process group 단위 실행
- stdout/stderr line-by-line streaming
- evidence.log에 전체 기록
- FlagDetector에 실시간 전달
- Token usage 파싱 가능하면 파싱
- session id / resume id 파싱 가능하면 저장
- solved 시 같은 challenge의 다른 local attempt kill
- 다른 팀원 프로세스는 절대 kill하지 않음
```

프로세스 종료는 직접 child만 죽이지 말고 process group을 죽인다.

```python
os.killpg(proc.pid, signal.SIGTERM)
# timeout 후
os.killpg(proc.pid, signal.SIGKILL)
```

---

## 7. Docker Sandbox 설계

### 7.1 정답 구조

```text
Docker image는 하나
Docker container는 attempt별 여러 개
```

```text
ctf-os-sandbox:latest
├── container for bof/recon_fast
├── container for bof/exploit_main
├── container for bof/exploit_alt
├── container for sqli/recon_fast
└── container for crackme/static_analysis
```

모든 worker가 하나의 container를 공유하면 안 된다.

```text
단일 shared container ❌
attempt별 isolated container ✅
```

### 7.2 Image

MVP에서는 fat image 하나로 간다.

```text
ctf-os-sandbox:latest
```

포함 도구:

```text
pwntools
gdb
radare2
angr
z3
RsaCtfTool
binwalk
foremost
zsteg
steghide
ffmpeg
sox
curl
nc
tshark
exiftool
python3 / pip / venv
common build tools
```

대회 전 image build가 제일 중요하다.

```bash
docker build -t ctf-os-sandbox:latest -f sandbox/Dockerfile.sandbox .
```

### 7.3 Container per attempt

각 attempt는 전용 컨테이너를 가진다.

```bash
docker run -d \
  --name ctf-os-{team_id}-{contest_slug}-{challenge_slug}-{attempt_id} \
  --memory 2g \
  --cpus 1.5 \
  --network bridge \
  --label ctf-os=true \
  --label ctf-os.team_id={team_id} \
  --label ctf-os.member={member} \
  --label ctf-os.contest={contest} \
  --label ctf-os.challenge={challenge} \
  --label ctf-os.attempt_id={attempt_id} \
  -v "{challenge_workspace}:/workspace:ro" \
  -v "{attempt_workdir}:/work:rw" \
  -v "{challenge_output}:/artifacts:rw" \
  ctf-os-sandbox:latest \
  sleep infinity
```

### 7.4 Mount 정책

```text
/workspace  → 원본 문제 파일, read-only
/work       → 이 attempt 전용 작업 디렉터리, read-write
/artifacts  → challenge output 디렉터리, read-write
```

Codex prompt에는 반드시 들어간다.

```text
Original challenge files are mounted read-only at /workspace.
Your private writable directory is /work.
Artifacts can be copied to /artifacts.
Do not write into /workspace.
Do not overwrite other attempts.
```

### 7.5 ctf-exec wrapper

Codex는 명령을 직접 호스트에서 막 실행하지 말고, 가능하면 Docker container 안에서 실행한다.

```bash
ctf-os sandbox exec {attempt_id} -- "file /workspace/chall"
```

각 attempt workdir에는 helper script를 둔다.

```bash
./ctf-exec 'file /workspace/chall'
./ctf-exec 'python3 /work/exploit.py'
./ctf-exec 'curl -i http://allowed-remote'
```

내부 구현:

```bash
docker exec -w /work {container_name} bash -lc "{command}"
```

### 7.6 Precreate 정책

컨테이너를 완전히 미리 만들어두는 것보다, 문제 queue 시 attempt별로 바로 생성하는 것이 현실적이다.

```text
문제 감지
→ workspace 압축 해제
→ RacePlan 생성
→ attempt workdir 생성
→ attempt container precreate
→ Codex worker subprocess 시작
```

### 7.7 Cleanup

solved 시 해당 challenge의 로컬 컨테이너만 제거한다.

```text
SOLVED bof
→ bof/recon_fast container stop/rm
→ bof/exploit_main container stop/rm
→ bof/exploit_alt container stop/rm
→ sqli container는 유지
→ teammate container는 건드리지 않음
```

cleanup 명령:

```bash
ctf-os sandbox cleanup
ctf-os sandbox cleanup --all
```

라벨 기반으로만 삭제한다.

---

## 8. SolverEngine — 문제풀이 시스템

문제풀이 시스템은 단순히 “Codex에게 풀어줘”가 아니다. 다음 구조를 가진다.

```text
SolverEngine
├── ChallengeContextBuilder
├── RAGRetriever
├── KnowledgeIndex
├── PlaybookSelector
├── Planner
├── ReActLoop
├── ActionObservationParser
├── LoopDetector
├── StrategyReranker
├── Verifier
└── SolverBackend
    ├── CodexCliBackend
    ├── ClaudeCliBackend optional
    └── MockBackend
```

### 8.1 핵심 루프

```text
1. Challenge Intake
   - contest.md 설명 / 점수 / 카테고리 / 원격 / 힌트 읽기
   - zip 압축 해제
   - 파일 목록 / 타입 / 권한 / 크기 확인

2. RAG Retrieval
   - 카테고리별 playbook 검색
   - 도구 사용법 검색
   - 유사 writeup 검색
   - 이전 local notes / findings 검색

3. Plan
   - 1차 풀이 계획 생성
   - 취약점 가설 후보 정리
   - 사용할 도구와 순서 결정

4. ReAct Loop
   - action 선택
   - ctf-exec로 명령 실행
   - observation 수집
   - finding 기록
   - 가설 업데이트

5. Loop Detection
   - 같은 명령 / 같은 실패 반복 감지
   - SHIFT instruction 주입

6. Exploit Build
   - exploit.py 작성
   - payload 생성
   - 원격 서비스 연결

7. Flag Detection
   - stdout / 파일 / 원격 응답에서 flag candidate 감지

8. Verification
   - replay.sh 생성
   - 오탐 제거

9. Solve Event
   - SOLVED 기록
   - TUI 표시
   - 같은 문제 local worker 종료
```

---

## 9. ReAct&Plan 설계

ReAct는 reasoning과 acting을 교차시키는 방식이다. CTF-OS에서는 private chain-of-thought를 저장하거나 노출하는 것이 아니라, **구조화된 외부 작업 기록**만 저장한다.

워커 출력 계약:

```text
[PLAN]
[HYPOTHESIS]
[ACTION]
[OBSERVATION]
[FINDING]
[FAIL]
[SHIFT]
[FLAG_CANDIDATE]
[ARTIFACT]
[TASK_DONE]
```

워커에게 요구할 동작:

```text
- 먼저 workspace를 조사한다.
- 간단한 PLAN을 만든다.
- HYPOTHESIS를 유지한다.
- 한 번에 하나의 ACTION을 실행한다.
- OBSERVATION을 기록한다.
- 사실을 알게 되면 FINDING을 남긴다.
- 실패한 접근은 FAIL로 기록한다.
- 반복되면 SHIFT로 전략을 바꾼다.
- 플래그를 만들거나 추측하지 않는다.
- placeholder flag를 출력하지 않는다.
- contest.md에 명시된 remote에만 연결한다.
```

---

## 10. RAG / Knowledge Base

RAG는 대회 중 무작위 인터넷 검색용이 아니라, **CTF 풀이 기억장치**다.

사용 목적:

```text
CTF playbook 검색
도구 cheat sheet 검색
예전 writeup 검색
카테고리별 실전 패턴 검색
실패 로그 기반 대체 전략 검색
```

### 10.1 디렉터리

```text
knowledge/
├── playbooks/
│   ├── pwn.md
│   ├── web.md
│   ├── rev.md
│   ├── crypto.md
│   ├── forensics.md
│   ├── misc.md
│   └── cloud.md
├── tools/
│   ├── pwntools.md
│   ├── gdb.md
│   ├── radare2.md
│   ├── angr.md
│   ├── z3.md
│   ├── rsa_ctf_tool.md
│   ├── binwalk.md
│   ├── steghide.md
│   ├── zsteg.md
│   ├── curl.md
│   ├── tshark.md
│   └── ffmpeg.md
├── writeups/
│   ├── pwn/
│   ├── web/
│   ├── rev/
│   ├── crypto/
│   ├── forensics/
│   ├── misc/
│   └── cloud/
└── indexes/
    ├── chunks.jsonl
    └── knowledge.sqlite
```

### 10.2 Retrieval 방식

MVP:

```text
SQLite FTS5 우선
불가능하면 plain substring / ripgrep-style fallback
```

각 chunk metadata:

```json
{
  "id": "pwn-ret2libc-001",
  "source": "knowledge/playbooks/pwn.md",
  "category": "pwn",
  "tags": ["ret2libc", "canary", "NX", "libc leak"],
  "tool": ["pwntools", "gdb", "checksec"],
  "content": "..."
}
```

Retrieval query 구성 요소:

```text
카테고리
문제 설명
점수
원격 프로토콜
파일 타입
strings/checksec/exif/binwalk 결과
이전 실패 전략
이미 발견한 findings
```

---

## 11. Category별 Playbook 방향

### 11.1 pwn

초기 명령:

```bash
file /workspace/*
checksec /workspace/chall
strings -a /workspace/chall | head -100
readelf -a /workspace/chall | head
objdump -d /workspace/chall | head
```

전략 키워드:

```text
checksec
canary
NX
PIE
RELRO
ret2win
ret2libc
format string
ROP
heap
tcache
libc leak
```

### 11.2 web

초기 명령:

```bash
curl -i "$REMOTE"
curl -s "$REMOTE" | tee /work/index.html
```

전략 키워드:

```text
SQLi
SSTI
LFI
RFI
SSRF
JWT
prototype pollution
deserialization
command injection
path traversal
auth bypass
```

### 11.3 rev

초기 명령:

```bash
file /workspace/*
strings -a /workspace/chall | head -100
ltrace /workspace/chall
strace /workspace/chall
r2 -A /workspace/chall
```

전략 키워드:

```text
strings
ltrace
strace
r2
angr
z3
packed binary
UPX
XOR
base64
license check
bruteforce
```

### 11.4 crypto

전략 키워드:

```text
RSA small e
common modulus
Wiener
Franklin-Reiter
LCG
XOR known plaintext
AES ECB
padding oracle
z3
sage
```

### 11.5 forensics / misc

초기 명령:

```bash
file /workspace/*
exiftool /workspace/*
strings -a /workspace/*
binwalk /workspace/*
```

전략 키워드:

```text
binwalk
foremost
exiftool
zsteg
steghide
tshark
volatility
zip password
audio spectrogram
pcap
archive carving
```

### 11.6 cloud

전략 키워드:

```text
bucket permission
metadata service
IAM misconfig
JWT/OIDC
config leak
logs
SSRF to metadata
public object listing
```

---

## 12. RacePlan — 워커 경쟁 정책

### 12.1 난이도별 기본 정책

쉬운 문제:

```text
score <= 200
├── recon_fast
└── exploit_fast
```

중간 문제:

```text
score <= 400
├── recon_fast
├── exploit_main
└── exploit_alt
```

어려운 문제:

```text
score >= 500
├── recon_deep
├── source_deep
├── exploit_main
├── exploit_alt
└── fallback
```

### 12.2 Attempt profile

```yaml
attempt_profiles:
  recon_fast:
    role: recon
    purpose: 빠른 파일/원격/문제 설명 분석
    max_runtime_sec: 300

  recon_deep:
    role: recon
    purpose: 깊은 초기 분석
    max_runtime_sec: 900

  exploit_fast:
    role: exploit
    purpose: 쉬운 취약점 빠른 회수
    max_runtime_sec: 600

  exploit_main:
    role: exploit
    purpose: 가장 가능성 높은 전략 구현
    max_runtime_sec: 1200

  exploit_alt:
    role: exploit
    purpose: main과 다른 전략으로 경쟁
    max_runtime_sec: 1200

  source_deep:
    role: source
    purpose: 소스/바이너리 심층 분석
    max_runtime_sec: 1500

  fallback:
    role: fallback
    purpose: 기존 가정 폐기 후 새 접근
    max_runtime_sec: 1200

  verifier:
    role: verifier
    purpose: flag candidate 검증
    max_runtime_sec: 300
```

### 12.3 전략 다양성

같은 Codex 모델이라도 prompt가 달라야 한다.

```text
exploit_main:
- recon 결과상 가장 가능성 높은 공격 시도

exploit_alt:
- 이미 실패한 접근 반복 금지
- 다른 입력 경로 / 다른 취약점 클래스 / 다른 도구 우선

fallback:
- 문제 해석 자체를 다시 함
- 이상한 edge case와 비주류 풀이도 고려
```

---

## 13. 워커 간 공유 정보

LocalEventBus는 같은 PC의 attempt들이 다음 정보를 공유한다.

```text
findings
tried_commands
failed_strategies
interesting_files
remote_observations
flag_candidates
artifact paths
working exploit hints
```

새 attempt 시작 prompt에는 기존 정보가 주입된다.

```text
Already tried:
- checksec /workspace/chall
- strings found no obvious flag
- SQLi payloads failed on /login

Known findings:
- NX enabled
- PIE disabled
- possible format string in username

Do not repeat failed commands unless you have a new reason.
Choose a different strategy from existing attempts.
```

---

## 14. 파일 / 디렉터리 구조

```text
ctf-os/
├── config.yaml
├── incoming/
│   └── {contest_name}/
│       ├── contest.md
│       ├── pwn/
│       ├── web/
│       ├── rev/
│       ├── cloud/
│       ├── crypto/
│       ├── forensics/
│       ├── misc/
│       └── workspace/
├── output/
│   └── {contest_name}/
│       ├── local_state.db
│       ├── REPORT.md
│       └── {challenge_slug}/
│           ├── notes.md
│           ├── evidence.log
│           ├── writeup.md
│           ├── final/
│           │   ├── exploit.py
│           │   └── replay.sh
│           └── attempts/
│               ├── recon_fast-{id}/
│               │   ├── work/
│               │   └── ctf-exec
│               ├── exploit_main-{id}/
│               │   ├── work/
│               │   └── ctf-exec
│               └── exploit_alt-{id}/
│                   ├── work/
│                   └── ctf-exec
├── sync/
│   └── {team_id}/
│       ├── {member}.events.jsonl
│       └── other_member.events.jsonl
├── backend/
│   ├── main.py
│   ├── models.py
│   ├── config.py
│   ├── contest_parser.py
│   ├── watcher.py
│   ├── local_state.py
│   ├── local_coordinator.py
│   ├── local_worker_pool.py
│   ├── flag_detector.py
│   ├── local_event_bus.py
│   ├── team_sync.py
│   ├── merged_team_state.py
│   ├── artifact_writer.py
│   ├── quota_monitor.py
│   ├── doctor.py
│   ├── sandbox/
│   │   ├── pool.py
│   │   ├── container.py
│   │   ├── exec.py
│   │   └── docker_cli.py
│   └── solver_engine/
│       ├── backend_base.py
│       ├── codex_cli_backend.py
│       ├── claude_cli_backend.py
│       ├── mock_backend.py
│       ├── challenge_context.py
│       ├── rag_retriever.py
│       ├── knowledge_index.py
│       ├── playbook_selector.py
│       ├── react_loop.py
│       ├── planner.py
│       ├── action_observation.py
│       ├── loop_detector.py
│       ├── verifier.py
│       ├── strategy_reranker.py
│       └── prompts.py
├── tui/
│   └── dashboard.py
├── knowledge/
├── prompts/
├── sandbox/
│   └── Dockerfile.sandbox
├── scripts/
│   └── setup.sh
├── tests/
├── pyproject.toml
├── README.md
└── .env.example
```

---

## 15. contest.md 형식

```markdown
# 대회명: SCA CTF 2026

## 대회 정보
- 날짜: 2026-07-19
- 플래그 형식: SCA{...}
- 팀: 지웅팀

## 문제 목록

### web/sqli
- 점수: 100
- 원격: http://web.sca.kr:8080
- 설명: 로그인 우회

### pwn/bof
- 점수: 300
- 원격: nc pwn.sca.kr 1234
- 설명: 스택 기반 버퍼 오버플로우
- 힌트: NX 비활성화

### rev/crackme
- 점수: 200
- 설명: 바이너리 분석 후 키 추출

### crypto/rsa
- 점수: 250
- 설명: 작은 공개 지수
```

원격 접속은 이 파일에 명시된 endpoint만 허용한다.

---

## 16. config.yaml 최종 예시

```yaml
mode: local_node
solver_mode: cli_attempt_race

contest:
  name: "SCA CTF 2026"
  team_id: "sca-jiwoong-team"
  flag_patterns:
    - "SCA\\{[^}]+\\}"
    - "FLAG\\{[^}]+\\}"
    - "[A-Z0-9_]+\\{[A-Za-z0-9_!@#$%^&*\\-+=.,?]+\\}"

member:
  name: "jiwoong"
  display_name: "지웅"
  owned_categories:
    - pwn
    - web
    - misc

coordinator:
  backend: auto
  hint_after_sec: 600
  loop_check_sec: 120

solvers:
  codex:
    enabled: true
    backend: codex_cli
    command: "codex"
    max_workers: 5
  claude:
    enabled: false
    backend: claude_cli
    command: "claude"
    max_workers: 1

codex_models:
  default: "<default_codex_model>"
  fast: "<fast_codex_model>"
  strong: "<strong_codex_model>"
  fallback: "<fallback_codex_model>"

model_policy:
  easy:
    recon_fast: fast
    exploit_fast: default
    verifier: fast
  medium:
    recon_fast: fast
    exploit_main: strong
    exploit_alt: strong
    verifier: fast
  hard:
    recon_deep: strong
    source_deep: strong
    exploit_main: strong
    exploit_alt: strong
    fallback: fallback
    verifier: fast

worker_policy:
  max_workers_total: 5
  max_workers_per_challenge: 3
  easy_score_max: 200
  medium_score_max: 400
  hard_score_min: 500
  kill_others_on_verified_flag: true
  cooldown_on_rate_limit_sec: 120
  stop_new_workers_on_quota_warning: true

race_policy:
  diversity: strategy
  same_backend_parallel_attempts: true
  api_model_race: false
  remote_worker_race: false
  kill_local_attempts_on_solved: true

sandbox:
  enabled: true
  image: "ctf-os-sandbox:latest"
  container_per_attempt: true
  precreate_on_queue: true
  max_containers: 6
  cleanup: true
  preserve_failed_attempts: false
  default_limits:
    memory: "2g"
    cpus: 1.5
  heavy_limits:
    memory: "4g"
    cpus: 2.0
  heavy_categories:
    - pwn
    - rev
    - forensics

sync:
  enabled: true
  type: file
  team_namespace: "sca-jiwoong-team"

flag_verification:
  auto_confirm_flags: false
  require_verifier_before_solved: true
  ignore_placeholders: true

tui:
  show_team_status: true
  show_team_flags: true
  show_attempts: true
  refresh_ms: 500
```

---

## 17. LocalState 상태 머신

Challenge status:

```text
DISCOVERED
QUEUED
RUNNING
STUCK
HINTING
FLAG_CANDIDATE
VERIFYING
SOLVED
FAILED
PAUSED
```

흐름:

```text
DISCOVERED
→ QUEUED
→ RUNNING
→ FLAG_CANDIDATE
→ VERIFYING
→ SOLVED
```

막힌 경우:

```text
RUNNING
→ STUCK
→ HINTING
→ RUNNING
```

수동 정지:

```text
RUNNING
→ PAUSED
```

---

## 18. SQLite schema 초안

```sql
CREATE TABLE challenges (
  id TEXT PRIMARY KEY,
  contest TEXT NOT NULL,
  category TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  score INTEGER,
  remote TEXT,
  description TEXT,
  status TEXT NOT NULL,
  assignee TEXT,
  flag TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE attempts (
  id TEXT PRIMARY KEY,
  challenge_id TEXT NOT NULL,
  profile TEXT NOT NULL,
  role TEXT NOT NULL,
  backend TEXT NOT NULL,
  model TEXT,
  pid INTEGER,
  container_name TEXT,
  workdir TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT,
  ended_at TEXT,
  token_total INTEGER DEFAULT 0,
  FOREIGN KEY(challenge_id) REFERENCES challenges(id)
);

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  challenge_id TEXT,
  attempt_id TEXT,
  type TEXT NOT NULL,
  message TEXT,
  payload_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE flag_candidates (
  id TEXT PRIMARY KEY,
  challenge_id TEXT NOT NULL,
  attempt_id TEXT,
  value TEXT NOT NULL,
  source TEXT,
  confidence REAL,
  verified INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);
```

---

## 19. TeamSync

TeamSync는 명령 서버가 아니라 append-only 공유 장부다.

```text
sync/{team_id}/
├── jiwoong.events.jsonl
├── jueon.events.jsonl
├── hyunseok.events.jsonl
└── howon.events.jsonl
```

각 노드는 자기 파일만 쓴다.

```text
내 파일 append ✅
다른 팀원 파일 수정 ❌
```

이벤트 형식:

```json
{
  "id": "uuid",
  "timestamp": "2026-07-10T12:00:00+09:00",
  "team_id": "sca-jiwoong-team",
  "member": "jiwoong",
  "contest": "SCA CTF 2026",
  "type": "SOLVED",
  "category": "pwn",
  "challenge": "bof",
  "payload": {
    "flag": "SCA{...}",
    "attempt_id": "exploit_main-a7f2"
  }
}
```

이벤트 타입:

```text
CHALLENGE_SEEN
CLAIMED
QUEUED
RUNNING
FINDING
FLAG_CANDIDATE
VERIFYING
SOLVED
FAILED
WORKER_STARTED
WORKER_STOPPED
TOKEN_USAGE
ARTIFACT_WRITTEN
SANDBOX_STARTED
SANDBOX_STOPPED
```

---

## 20. FlagDetector

### 20.1 기본 패턴

```text
SCA{...}
KISIA{...}
HACKTHEON{...}
CODEGATE{...}
SSTF{...}
HSPACE{...}
LAYER7{...}
FLAG{...}
CTF{...}
[A-Z0-9_]+{...}
```

contest.md 커스텀 패턴을 우선 적용한다.

### 20.2 오탐 방지

무조건 regex match만으로 solved 처리하지 않는다.

```text
FLAG_CANDIDATE
→ VERIFYING
→ SOLVED
```

무시할 값:

```text
SCA{...}
FLAG{...}
CTF{...}
example flag
fake flag
test flag
demo flag
placeholder
프롬프트에 들어간 예시 플래그
contest.md 설명용 placeholder
```

### 20.3 MVP 검증 정책

```text
--auto-confirm-flags false:
  FLAG_CANDIDATE까지만 기록

--auto-confirm-flags true:
  contest pattern match + placeholder 아님이면 SOLVED 처리
```

운영에서는 verifier를 거친 뒤 solved 처리하는 것이 기본이다.

---

## 21. ArtifactWriter

문제별 산출물:

```text
output/{contest}/{challenge_slug}/
├── notes.md
├── evidence.log
├── writeup.md
├── final/
│   ├── exploit.py
│   └── replay.sh
└── attempts/
```

기록 정책:

```text
evidence.log:
- raw stdout/stderr 전체

notes.md:
- PLAN / HYPOTHESIS / FINDING / FAIL / SHIFT 요약

exploit.py:
- worker가 생성한 exploit 중 성공한 것을 final로 승격

replay.sh:
- verifier가 플래그 재현 흐름 작성

writeup.md:
- solved 이후 초안 생성
```

---

## 22. TUI 요구사항

TUI는 로컬 상태와 팀 병합 상태를 동시에 보여준다.

```text
╔════════════════════════════════════════════════════════════════════╗
║ CTF-OS Local Node │ SCA CTF 2026 │ 지웅 │ sca-jiwoong-team       ║
╠══════════╪════════╪════╪════════╪════════╪══════╪═══════════════╣
║ 문제     │카테고리│점수│담당자  │상태    │워커  │플래그         ║
╠══════════╪════════╪════╪════════╪════════╪══════╪═══════════════╣
║ sqli     │ web    │100 │지웅    │✅ 완료 │0     │SCA{...}       ║
║ bof      │ pwn    │300 │지웅    │🔄 로컬 │3     │-              ║
║ crackme  │ rev    │200 │주언    │👥 팀원 │2     │-              ║
║ cloud1   │ cloud  │300 │주언    │⏳ 대기 │0     │-              ║
╠══════════╧════════╧════╧════════╧════════╧══════╧═══════════════╣
║ 내 워커: codex 4/5 │ sandbox 4/6 │ quota warning: 없음          ║
╠════════════════════════════════════════════════════════════════════╣
║ [로컬] bof/exploit_main: libc leak found                         ║
║ [팀]   주언/crackme: packed binary, trying unpack                 ║
╚════════════════════════════════════════════════════════════════════╝
```

상태 표시:

```text
⏳ 대기       아직 아무도 안 잡음
🔒 담당       내가 담당하지만 아직 안 돌림
🔄 로컬       내 노드에서 실행 중
👥 팀원       팀원이 실행 중
🟡 후보       플래그 후보 발견
✅ 완료       solved
⚠️ 중복       두 명 이상 같은 문제 실행 중
❌ 실패       현재 attempt 실패
⏸ 일시정지    수동 또는 quota 때문에 정지
```

TUI에 표시할 attempt-level 정보:

```text
active attempts per challenge
attempt profile
strategy seed
latest finding
latest fail
flag candidate
container status
model alias
runtime
```

---

## 23. CLI 명령어

### 23.1 init

```bash
ctf-os init "SCA CTF 2026"
```

동작:

```text
incoming/{contest}/contest.md 생성
output/{contest}/ 생성
sync/{team_id}/ 생성
config.yaml 없으면 생성
기존 파일은 --force 없으면 덮어쓰지 않음
```

### 23.2 doctor

```bash
ctf-os doctor
```

검사:

```text
Python version
uv
Docker daemon
ctf-os-sandbox:latest image 존재 여부
Codex CLI 설치 여부
Claude CLI 설치 여부, 없으면 warn
config.yaml validity
incoming/output/sync writable
contest.md parse 가능 여부
```

### 23.3 parse

```bash
ctf-os parse
```

동작:

```text
contest.md 파싱
category folder zip 탐색
member.owned_categories 필터링
local_state.db에 challenge upsert
```

### 23.4 run

```bash
ctf-os run
ctf-os run --once
ctf-os run --mock-worker
ctf-os run --once --mock-worker --auto-confirm-flags
```

동작:

```text
incoming 폴더 2초 polling
내 담당 문제 queue
RacePlan 생성
attempt별 sandbox 생성
Codex CLI subprocess 실행
stdout/evidence.log stream
flag detection
artifact write
TeamSync event append
TUI 상태 갱신
```

### 23.5 tui

```bash
ctf-os tui
ctf-os tui --team
ctf-os tui --readonly
```

### 23.6 sync

```bash
ctf-os sync merge
ctf-os sync watch
```

`sync watch`는 MVP에서는 file sync만 담당한다. 중앙 executor가 아니다.

### 23.7 sandbox

```bash
ctf-os sandbox exec {attempt_id} -- "file /workspace/chall"
ctf-os sandbox cleanup
ctf-os sandbox cleanup --all
```

---

## 24. Safety / 운영 제한

이 시스템은 승인된 CTF 문제에만 사용한다.

워커 prompt와 실행 정책에 반드시 포함:

```text
- This is an authorized CTF challenge only.
- Only inspect files under the challenge workspace.
- Only connect to remotes explicitly listed in contest.md.
- Do not scan unrelated networks.
- Do not access credentials, SSH keys, browser data, API keys, or personal files.
- Do not modify host system configuration.
- Do not write outside /work and /artifacts.
- Do not invent flags.
- Do not print placeholder flags.
```

호스트 보호:

```text
ctf-os 전용 WSL user 권장
sudo 권한 제한
Codex cwd는 attempt workdir로 고정
문제 명령은 ctf-exec 통해 Docker 안에서 실행
workspace read-only
attempt별 container 격리
process group kill
Docker label 기반 cleanup
```

---

## 25. 구현 우선순위

### Phase 1 — SCA MVP 뼈대

```text
pyproject.toml
config loader
contest parser
local_state SQLite
event bus
team sync merge
flag detector
artifact writer
mock worker
CLI init/doctor/parse/run/tui
```

성공 기준:

```bash
uv run ctf-os doctor
uv run ctf-os init "SCA CTF 2026"
uv run ctf-os parse
uv run ctf-os run --once --mock-worker --auto-confirm-flags
uv run ctf-os sync merge
uv run pytest
```

### Phase 2 — Codex CLI subprocess

```text
CodexCliBackend
codex exec 호출
process group kill
stdout streaming
token usage parse
session id parse optional
rate limit detection
```

### Phase 3 — DockerSandboxPool

```text
image check
attempt container create
ctf-exec wrapper
resource limits
precreate_on_queue
cleanup
```

### Phase 4 — SolverEngine

```text
ChallengeContextBuilder
RAGRetriever
PlaybookSelector
ReAct&Plan prompt
LoopDetector
Verifier
StrategyReranker
```

### Phase 5 — TUI polish

```text
attempt-level display
team merged display
duplicate solving warning
flag candidate vs solved
quota/sandbox status
```

---

## 26. 테스트 요구사항

pytest 테스트:

```text
config loading
contest.md parsing
category filtering
flag detection
placeholder flag ignore
JSONL event append/read
merged team state
duplicate solving warning
SQLite challenge upsert
mock worker flag detection
race plan easy/medium/hard selection
max_workers_per_challenge respected
attempt workdir creation
exploit_alt prompt differs from exploit_main
existing findings injected into new attempt prompt
sandbox container name generation
docker run command construction
label construction
ctf-exec command construction
cleanup filter construction
solved kills only same-challenge local attempts
knowledge indexing
retrieval by category and keyword
playbook selection
ReAct tag parsing
loop detection
verifier candidate vs solved behavior
artifact note updates
```

---

## 27. 최종 구현 프롬프트 — Codex에 줄 첫 프롬프트

아래 프롬프트는 Codex CLI에 그대로 넣기 위한 구현 지시다.

```text
You are a senior Python systems engineer building CTF-OS v1.3.

Implement a Local-first Multi-Node CTF Agent.

Product direction:
- No central executor.
- No remote worker stealing.
- No shared Codex account.
- No CTFd auto-submit.
- Each member runs a local node on their own PC.
- Each local node solves only member.owned_categories.
- TeamSync only shares append-only JSONL events: status, findings, flags.
- Default solver backend is Codex CLI.
- Racing means multiple local Codex CLI attempts with different roles and strategies, not API model racing.
- Docker image is one prebuilt CTF image, but containers are per attempt.

Implement MVP first:
1. pyproject.toml and CLI entrypoint.
2. config.yaml loader.
3. contest.md parser.
4. local SQLite state.
5. JSONL local event bus.
6. TeamSync merge.
7. FlagDetector with placeholder filtering.
8. ArtifactWriter.
9. MockBackend.
10. RacePlan for easy/medium/hard challenges.
11. LocalWorkerPool.
12. DockerSandboxPool command construction and mock-safe behavior.
13. CodexCliBackend using codex exec subprocess.
14. Rich/Textual TUI fallback.
15. pytest tests.
16. README examples for SCA and KISIA.

Required commands:
- uv run ctf-os doctor
- uv run ctf-os init "SCA CTF 2026"
- uv run ctf-os parse
- uv run ctf-os run --once --mock-worker --auto-confirm-flags
- uv run ctf-os sync merge
- uv run ctf-os sandbox cleanup
- uv run pytest

Worker prompt contract:
Use structured tags:
[PLAN]
[HYPOTHESIS]
[ACTION]
[OBSERVATION]
[FINDING]
[FAIL]
[SHIFT]
[FLAG_CANDIDATE]
[ARTIFACT]
[TASK_DONE]

Safety:
- Authorized CTF only.
- Only connect to remotes listed in contest.md.
- Do not scan unrelated networks.
- Do not access credentials, SSH keys, browser data, or host personal files.
- Run challenge commands through ctf-exec inside the attempt Docker container.
- Do not invent flags or print placeholder flags.

Acceptance criteria:
- mock run detects a mock flag and writes evidence.log, notes.md, local_state.db, and SOLVED event.
- TeamSync merge shows solved state.
- TUI displays challenge status and flag.
- All tests pass.
- No CTFd integration exists.
- No central executor exists.
- No remote worker control exists.
```

---

## 28. 참고 자료

- verialabs/ctf-agent: https://github.com/verialabs/ctf-agent
- OpenAI Codex CLI non-interactive mode: https://developers.openai.com/codex/noninteractive
- OpenAI Codex CLI command reference: https://developers.openai.com/codex/cli/reference
- ReAct paper: https://arxiv.org/abs/2210.03629
- RAG paper: https://arxiv.org/abs/2005.11401
- Hacking CTFs with Plain Agents: https://arxiv.org/abs/2412.02776

---

## 29. 최종 결론

CTF-OS v1.3은 다음 구조로 고정한다.

```text
각자 로컬 PC에서 ctf-os run
→ 자기 담당 카테고리만 감지
→ 문제 들어오면 RacePlan 생성
→ Codex CLI 여러 subprocess 병렬 실행
→ attempt별 Docker container 격리
→ ReAct&Plan + RAG playbook 기반 풀이
→ FlagDetector / Verifier로 플래그 확인
→ TUI에서 실시간 상태와 플래그 확인
→ TeamSync로 팀원과 solved/status/finding/flag 공유
→ 사람이 CTFd에 수동 제출
```

핵심은 이것이다.

```text
Codex CLI를 사람이 여러 창에서 직접 여는 것이 아니라,
CTF-OS가 Codex CLI를 여러 개 자동 호출하고,
각 호출에 다른 전략을 부여해 문제를 경쟁적으로 풀게 만드는 시스템.
```
