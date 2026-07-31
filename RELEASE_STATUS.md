# CTF-OS release authority

이 문서는 현재 릴리스 판정의 정본 인덱스다. 과거 보고서의 PASS나 개별
category gate는 현재 checkout의 릴리스 승인을 대신하지 않는다.

## 판정 이름

- `ENGINE_RELEASE_GO`: 동일한 clean source commit과 exact local image ID가
  full source suite, 무경고 `ctfos doctor`, all-category 7-gate/6-category
  matrix를 모두 통과했다.
- `COMPETITION_PERFORMANCE_STATUS`: thin scaffold 대비 실제 풀이 성능에 대한
  별도 판정이다. 동일 모델·effort·image·input·budget의 blind/live 3회 대
  3회 cohort가 없으면 `NOT_ESTABLISHED`다.
- `EXTENDED_SCOPE_STATUS`: 인증 secret, adversarial DNS, kernel/container
  escape, first-class AI/ML처럼 기본 userspace 범위 밖의 안전성 판정이다.
  해당 경계를 별도 검증하지 않았으면 기본 GO에 포함하지 않는다.

이 세 판정을 하나의 PASS로 합치지 않는다.

## 기계 판정 정본

`ENGINE_RELEASE_GO`는 다음 명령이 출력한 **exact receipt 경로와 SHA-256**를
운영자가 선택하고, 그 local unsigned receipt의 `ok`가 정확히 `true`이며 현재
HEAD/pin/image와 일치할 때만 성립한다. 디렉터리 이름만 보고 “최신”을 추정하지
않는다.

```sh
uv run python scripts/check-release-acceptance.py \
  --image-digest "$(docker image inspect --format '{{.Id}}' ctf-os:core)"
```

receipt는 ignored runtime tree인
`.ctfos/release-acceptance/run-*/receipt.json`에 생성된다. tracked Markdown에
commit, image ID 또는 실행 결과를 사후 기입하지 않는다. 그렇게 하면 검증한
source를 다시 변경해 자기참조 영수증이 되기 때문이다. 이 receipt는 같은 OS
계정이 수정할 수 있는 local evidence이며 signature나 CI attestation이 아니다.

유효한 receipt는 최소한 다음을 같은 실행에 결속해야 한다.

- 시작과 종료 시 동일한 clean Git `HEAD`와 worktree 상태
- `.ctfos/engine.toml`의 configured pin과 동일한 exact local Docker image ID
- 동일한 Python interpreter hash/version과 tracked `pyproject.toml`/`uv.lock` hash
- clean worktree에서 `scripts/check-fresh-clone.sh` 성공. 파일명은 역사적이며
  별도 clone을 만들지는 않는다.
- `ctfos doctor`의 `ok: true`와 빈 warnings
- all-category matrix의 `ok: true`, 7개 gate, 6개 category
- matrix report pointer와 SHA-256, 각 단계의 bounded stdout/stderr pointer와
  SHA-256, exit code, duration
- 종료 시 source, inspected image, configured pin의 무변경 재검사

운영자가 exact 출력 경로/hash를 보존하지 않았거나, receipt가 현재
`HEAD`/pin/image/runtime과 다르거나, 어느 단계든 실패·경고·
drift가 있으면 상태는 GO가 아니라 `UNVERIFIED` 또는 `NO-GO`다.

## 기본 GO 범위

기본 engine release 판정은 사람이 선택한 한 문제를 대상으로 하는 공개 또는
비인증 userspace CTF 운영 범위다. 문제 입력은 불변·비신뢰 데이터이며 실행은
challenge sandbox, 기본 network deny, explicit target allowlist, exact image
pin을 통과해야 한다. flag처럼 보이는 문자열은 후보일 뿐 자동 제출하지 않는다.

다음은 engine release GO와 별개인 현재 제한이다.

- thin scaffold 대비 solve@1, pass²/₃, 시간, category floor 우월성은 실제
  blind/live cohort 전에는 입증되지 않는다.
- typed secret injection channel이 없으므로 raw cookie, token, private key가
  필요한 인증 흐름은 지원 범위가 아니다.
- builtin egress는 exact host/port allowlist와 token bucket을 제공하지만 DNS
  A/AAAA commit, actual connection IP receipt, private/link-local/metadata range
  재검증은 아직 없다.
- Docker daemon과 host kernel을 신뢰한다. managed challenge sandbox는 Pwn/Rev
  category에만 `SYS_PTRACE`와 `seccomp=unconfined`를 주고 다른 category에서는
  빼지만, 최소 syscall seccomp profile은 아직 없다. 호환 `ctf-container`의
  standalone 기본 ptrace 동작은 보존된다. kernel/container-escape 또는
  의도적으로 악성인 handout은 별도 VM에서 실행한다.
- prompt의 untrusted-data framing은 있지만 malicious challenge/web-page 모델
  benchmark는 없다.
- 실행 image는 exact local ID로 고정되지만 rebuild는 아직 hermetic하지 않고
  SBOM, signature, SLSA/CI-backed release attestation도 없다.
- foreground managed action wave의 aggregate storage admission capability는 exact
  challenge·experiment와 현재 process/session 수명에 결속되며 durable background
  lease가 아니다. foreground container는 one-shot supervisor 경로를 따르고,
  process 중단 뒤 남은 실제 byte는 다음 bounded inventory가 다시 계산한다.
- local Pwn/Web gate는 remote libc, WAF/CDN/TLS, latency와 reliability를
  증명하지 않는다.
- first-class managed category는 Web, Pwn, Rev, Crypto, Forensic, Misc다. AI/ML,
  kernel/V8/race, 복잡 인증 Web, APK/DEX, interactive/formal Crypto, 대규모
  autonomous DFIR, modality-specific Misc는 별도 범위다.

background supervisor, builtin egress와 challenge storage quota/GC는 현재
구현돼 있으므로 미구현 목록에 다시 넣지 않는다. `rev-prove-runtime`의 typed
runtime 선택 계약도 구현돼 있지만 현재 formal matrix가 exact-image로 수용하는
Rev 범위는 legacy original-binary accepted-input 3+3이다. PE/JVM/.NET/WASM/QEMU
전 runtime의 exact-image end-to-end release 증거는 별도 미검증이다.

대회 시작 절차와 중단 기준은
[contest start runbook](docs/contest-start-runbook.md)을 따른다.
