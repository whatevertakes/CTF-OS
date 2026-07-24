# CTF-OS

허가된 CTF 문제 하나를 준비해 sandbox에서 푸는 도구다. 플래그 제출은 사람이 직접 한다.

## 1. 대회 전 준비

준비물:

- **OS/아키텍처**: Linux `x86_64` (Ubuntu·Kali·Debian 계열에서 검증). 이미지는 `linux/amd64` 전용이라 ARM(Apple Silicon 등)에서는 빌드되지 않는다. WSL2는 리눅스 파일시스템(`/home/...`) 아래에 클론한다(Windows 드라이브 `/mnt/c` 금지).
- **Docker Engine** + **Docker Compose v2 플러그인(>=2.24)**. Compose는 이미지 빌드에는 필요 없지만 `doctor`와 대회용 로컬 서비스 기동에 필요하다.
- **`uv`** (Python 3.11+ 관리).
- **디스크**: 프로필 하나당 수 GB. 열 개 전체 빌드는 40–60 GiB, 수 시간 소요.
- **GPU는 선택**: 없으면 자동으로 CPU로 동작한다(`ai`/`crypto`/`rev`의 GPU 경로만 비활성).

Docker와 `uv`가 설치된 환경에서 한 번 실행한다.

```bash
uv sync --frozen
sandbox/build-images.sh            # 전체 10개 프로필 빌드 (수 시간, 40–60 GiB)
uv run python -m ctf_os.agent_tools doctor
```

필요한 카테고리만 빠르게 빌드하려면 프로필을 인자로 준다(권장, 개인 머신).

```bash
sandbox/build-images.sh base web pwn   # 예: base + web + pwn 만 빌드
```

이때 `doctor`의 `category-images`는 열 개가 모두 있어야 초록이 되지만, 특정 문제 풀이는
해당 카테고리 이미지(또는 `base`)만 있으면 `race-prepare`가 진행된다.

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

문제 파일은 `incoming/Demo CTF/web/Example/`에 넣고, `contest.md`에 설명·원격 주소·플래그 패턴을 채운다.

```markdown
# 대회명: Demo CTF
- 플래그 패턴: \ACTF\{[^}\r\n]+\}\Z

### web/Example
- 설명: Example challenge
- 원격: https://replace-me.example.com/   # ← 실제 주최측 호스트로 반드시 교체
```

> ⚠️ `원격`은 **실제로 DNS 해석되는 호스트**여야 한다. `example.invalid` 같은 미해석
> 주소를 그대로 두면 `race-prepare`가 대상 해석 실패(`cannot resolve authorized target`)로
> 준비되지 않는다. 원격이 없는(로컬 서비스만 있는) 문제라면 이 줄을 지운다.

## 3. 문제 준비 시작

```bash
uv run python -m ctf_os.agent_tools race-prepare \
  'web/Example' --contest 'Demo CTF'
```

결과에서 `attack_ready: true`와 `root_sandbox.status: READY`를 확인한 뒤, 반환된 `next_root_action`으로 바로 풀이를 시작한다.

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
