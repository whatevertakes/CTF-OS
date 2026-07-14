# CTF-OS

CTF-OS는 사람이 연 Sol/Luna 세션을 위한 로컬 CTF 분석 도구입니다. 사람은 문제 파일과 `problems.txt`만 준비하고, Intake가 내부 `contest.md` manifest 생성·검증·workspace 준비를 처리합니다.

## 시작

1. 저장소를 clone합니다.

   ```bash
   git clone git@github.com:whatevertakes/CTF-OS.git
   cd CTF-OS
   ```

2. 의존성을 설치합니다. Python 3.11 이상, `uv`, Docker Engine(실행 중)과 Docker Compose v2가 필요합니다.

   ```bash
   uv sync --frozen
   ```

3. 대회 전에 10개 sandbox 이미지를 빌드하고 환경을 확인합니다.

   ```bash
   sandbox/build-images.sh
   uv run python -m ctf_os.agent_tools doctor
   ```

   `uv sync --frozen`은 CTF-OS의 Python 의존성만 설치하며 Docker 이미지를 만들지 않습니다. 모든 profile build와 doctor가 PASS한 상태에서 대회를 시작합니다. 특정 이미지만 다시 만들 때는 `sandbox/build-images.sh pwn` 또는 `sandbox/build-images.sh osint ai cloud`를 사용합니다.

4. 대회 폴더를 만듭니다.

   ```bash
   uv run python -m ctf_os.agent_tools init-contest "My CTF 2026"
   ```

6. 문제 파일을 `incoming/<contest>/<category>/` 아래에 넣습니다.

7. `incoming/<contest>/problems.txt`에 문제 정보와 원격을 붙여 넣습니다. 생성된 파일의 주석 예시를 참고합니다.

8. Sol에게 **“intake 해”**라고 요청합니다.

Intake는 `problems.txt`를 읽고 실제 파일을 확인한 뒤 `contest.md`를 생성 또는 갱신하고, parser 검증·intake·workspace 준비를 완료합니다. `contest.md`는 내부 manifest이며 사람이 수정하지 않습니다.

9. 새 Sol 세션에서 **“triage 해”**라고 요청합니다.

Challenge Triage는 Intake가 만든 inventory·ELF·archive·runtime·remote 메타데이터만 사용해 `output/<contest>/TRIAGE.md` Board와 `triage.json`을 만듭니다. 이 단계는 exploit, brute force, fuzzing, symbolic execution, solver 실행이나 remote 접속을 하지 않습니다. Board에서 추천 순서를 확인한 뒤 새 Sol 세션에서 **“1번 문제 풀어”**처럼 번호를 선택합니다.

## Worker orchestration

Solve 세션은 `DELEGATION_PLAN.json`에 tier, branch 가설, 범위, 예산, admission 결과와 requested/observed runtime 정보를 원자적으로 기록합니다. `delegation-template-show`는 카테고리별 Tier 1–4 후보를 추천할 뿐 branch를 만들지 않습니다. `branch-admit`는 외부 모델 없이 가설군·정규화 토큰·scope·tool·artifact·role의 가중 overlap을 계산하며 기본 0.70 이상 중복을 거부합니다.

`delegation-branch-add` 역시 child를 생성하지 않습니다. Sol이 Codex runtime native delegation으로 child를 만든 뒤 `sandbox-create`로 그 worker의 격리 실행 환경을 만듭니다. Worker는 자기 디렉터리에만 checkpoint/result를 저장하고, Sol만 전체 merge/show, shared finding, service lifecycle, utility 판단, 최종 replay를 수행합니다. Requested model role은 pinning 증명이 아니며 관측 근거가 없으면 observed 필드는 `null`입니다.

권장 순서는 다음과 같습니다.

```text
prepare-challenge → delegation-plan-init → delegation-template-show → branch-admit
→ delegation-branch-add → native child delegation → RUNNING → sandbox-create
→ worker-checkpoint-save → worker-checkpoints-merge → branch-utility
→ worker-result-save → worker-results-merge → record-finding
→ optional clean-room verifier → REPRODUCE.json → replay → manual submission
```

Clean-room verifier는 overlap 예외가 가능하지만 최종 artifact, `REPRODUCE.json`, fingerprint, expected observable behavior만 기본 입력으로 받습니다. 성공 자체는 제출 가능 판정이 아니며 Sol의 clean replay가 계속 필요합니다. Cloud는 read-only allowlist, AI는 host pickle/joblib 역직렬화 금지, OSINT는 비인가 계정·credential·개인정보 수집 금지 정책을 그대로 유지합니다.
