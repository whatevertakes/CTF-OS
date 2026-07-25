# CTF-OS

허가된 CTF 문제 하나를 준비해 sandbox에서 푸는 도구다. 플래그 제출은 사람이 직접 한다.

이 브랜치는 주최측 원격 요청을 참가자만 실행해야 하는 대회를 위해
`human-relay` 모드를 제공한다. 그런 대회에서는 에이전트가 주최측 호스트에
직접 접속하면 안 된다. 아래 §3의 `--remote-execution human-relay`를 반드시
사용한다. CLI는 사고를 막기 위해 실행 모드 생략을 허용하지 않는다.

## 1. 클론 직후 준비와 검사

준비물:

- **OS/아키텍처**: Linux `x86_64` (Ubuntu·Kali·Debian 계열에서 검증). 이미지는 `linux/amd64` 전용이라 ARM(Apple Silicon 등)에서는 빌드되지 않는다. WSL2는 리눅스 파일시스템(`/home/...`) 아래에 클론한다(Windows 드라이브 `/mnt/c` 금지).
- **Docker Engine** + **Docker Compose v2 플러그인(>=2.24)**. Compose는 이미지 빌드에는 필요 없지만 `doctor`와 대회용 로컬 서비스 기동에 필요하다.
- **`uv`** (Python 3.11+ 관리).
- **디스크**: 프로필 하나당 수 GB. 열 개 전체 빌드는 40–60 GiB, 수 시간 소요. 빌드 스크립트는 선택 빌드에 최소 20 GiB(프로필당 6 GiB로 증가), 전체 10개 빌드에 60 GiB의 여유 공간을 사전 요구한다.
- **GPU는 선택**: 없으면 자동으로 CPU로 동작한다(`ai`/`crypto`/`rev`의 GPU 경로만 비활성). 현재 고정된 CUDA 12.6 도구는 compute capability 9.0까지 허용하며, RTX 50 계열(sm_120)처럼 더 새로운 GPU는 커널 오류를 내기 전에 CPU로 자동 전환한다.

이 팀 브랜치의 이번 대회 배포 대상은 `web`, `pwn`, `rev`, `crypto`,
`osint`, `misc`, `ai` 일곱 카테고리다. 클론한 팀원은 아래처럼 정확히
같은 프로필 집합을 빌드하고 `doctor`에 넘긴다. `base`는 각 이미지의
공통 부모 레이어로 빌드 과정에서 자동 준비되므로 별도 태그가 필요 없다.

```bash
uv sync --frozen
sandbox/build-images.sh web pwn rev crypto osint misc ai
uv run python -m ctf_os.agent_tools doctor \
  --profiles web pwn rev crypto osint misc ai
uv run pytest -q -W error
```

빌드가 성공하면 스크립트도 정확히 일치하는 `doctor --profiles ...` 후속
명령을 출력한다. 선택한 이미지의 설치·스모크 단계는 이미지 빌드 중
실행되고, `doctor`는 호스트·Docker·Compose·선택 이미지의 고정 해시와
플랫폼, 가능한 경우 GPU 경로를 검사한다. 선택하지 않은 이미지가 없다는
이유로 이 검사가 실패하지 않는다.

APT 저장소 시점은 `sandbox/apt-snapshot.lock`, Python 전이 의존성과
배포 파일 해시는 `sandbox/requirements-lock/`에 고정된다. 직접 의존성을
바꾼 뒤에는 아래 명령으로 Python 잠금을 함께 갱신하고 변경된 잠금 파일을
커밋한다.

```bash
sandbox/lock-python-requirements.sh
```

대회 전체 카테고리를 미리 준비해야 하는 공유 머신에서만 전체 빌드와
기본 `doctor`를 사용한다.

```bash
sandbox/build-images.sh
uv run python -m ctf_os.agent_tools doctor
```

## 2. 대회와 문제 폴더 만들기

아래 명령이 `contest.md`와 지정한 문제 폴더를 함께 만든다.

```bash
uv run python -m ctf_os.agent_tools init-contest \
  'Demo CTF' --challenge 'web/Example'
```

생성 위치:

```text
incoming/Demo CTF/
├── contest.md
└── web/
    └── Example/
```

문제 파일은 `incoming/Demo CTF/web/Example/`에 넣고, `contest.md`에
설명·원격 주소·플래그 패턴을 채운다. `init-contest`가 만드는 플래그
패턴은 의도적으로 빈 필수 항목이다. 이를 채우지 않거나 정규식이 잘못되면
`race-prepare`는 run을 만들기 전에 오류로 종료하므로 자동 플래그 탐지가
조용히 비활성화되지 않는다.

```markdown
# 대회명: Demo CTF
- 플래그 패턴: \ACTF\{[^}\r\n]+\}\Z

### web/Example
- 설명: Example challenge
- 원격: https://replace-me.example.com/   # ← 실제 주최측 호스트로 반드시 교체
```

`원격` 처리 규칙은 실행 모드에 따라 다르다.

- `agent`: 에이전트 sandbox의 허용 대상을 만들기 위해 호스트가 실제로
  DNS 해석되어야 한다. 자리표시자면 실제 주소로 교체한다.
- `human-relay`: CTF-OS가 주최측 호스트를 해석하거나 접속하지 않는 것이
  정상이다. `example.invalid`처럼 이 머신에서 해석되지 않는 주최측 주소도
  선언 대상으로 유지한다. 이 줄을 지우면 정확한 relay 명령의 대상
  identity가 사라진다.
- 원격이 전혀 없고 로컬 입력·서비스만 있는 문제에서만 빈 `원격` 줄을
  지운다.

## 3. 원격 실행 모드를 명시하고 준비 시작

주최측 규칙상 모든 원격 요청을 참가자가 실행해야 한다면 다음 명령을
사용한다. 이 모드에서 에이전트는 로컬 sandbox 분석만 하고, 원격 시도가
필요하면 정확한 작업 디렉터리·argv·timeout·전체 출력 캡처 명령이 포함된
`HUMAN_REMOTE_ACTION`을 반환한다. 참가자가 실행해 돌려준
`HUMAN_REMOTE_RESULT`는 자동 winner나 검증된 receipt가 되지 않는다.

```bash
uv run python -m ctf_os.agent_tools race-prepare \
  'web/Example' --contest 'Demo CTF' \
  --remote-execution human-relay \
  --root-model-profile sol-ultra --service-isolation per-lane
```

에이전트가 선언된 주최측 원격에 직접 접속해도 되는 대회에서만
`--remote-execution agent`를 명시한다.

```bash
uv run python -m ctf_os.agent_tools race-prepare \
  'web/Example' --contest 'Demo CTF' \
  --remote-execution agent \
  --root-model-profile sol-ultra --service-isolation per-lane
```

`--remote-execution`을 생략하면 CLI가 즉시 실패한다. 결과에서
`attack_ready: true`, 요청한 `remote_execution`, 그리고
`root_sandbox.status: READY`를 확인한 뒤 반환된 `next_root_action`으로
바로 풀이를 시작한다.

## 4. 이미지와 도구 확인

전체 이미지의 현재 도구 잠금 해시·전체 sandbox 빌드 입력 해시·
프로필·플랫폼과 GPU passthrough, CUDA 실행 상태는 다음 명령으로
다시 확인한다. CPU 이미지 항목은
구조적 신원 검사이며, 실제 도구 실행은 이미지 빌드 스모크와 라이브
통합 테스트가 담당한다.

```bash
uv run python -m ctf_os.agent_tools doctor
```

준비된 sandbox 메타데이터 경로를 사용해 카테고리별 도구 카탈로그와
개별 사용법·버전을 확인한다.

```bash
uv run python -m ctf_os.agent_tools list-tools --metadata '<run>/workers/root/sandbox.json'
uv run python -m ctf_os.agent_tools tool-help --metadata '<run>/workers/root/sandbox.json' pwndbg
uv run python -m ctf_os.agent_tools tool-version --metadata '<run>/workers/root/sandbox.json' pwndbg
```

현재 추가 도구는 다음과 같다.

- pwn: pwndbg, pwninit, angrop
- forensic: StegSeek
- misc, crypto: Ares
- web: SSTImap
- osint: Sherlock, Maigret, Holehe, theHarvester

전체 이미지 구성과 보안 제약은 `sandbox/sandbox-tools.txt`, 정확한 고정
버전과 커밋은 `sandbox/tool-versions.lock`이 기준이다.
