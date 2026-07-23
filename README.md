# CTF-OS

허가된 CTF 문제 하나를 준비해 sandbox에서 푸는 도구다. 플래그 제출은 사람이 직접 한다.

## 1. 대회 전 준비

Docker와 `uv`가 설치된 환경에서 한 번 실행한다.

```bash
uv sync --frozen
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

문제 파일은 `incoming/Demo CTF/web/Example/`에 넣고, `contest.md`에 설명·원격 주소·플래그 패턴을 채운다.

```markdown
# 대회명: Demo CTF
- 플래그 패턴: \ACTF\{[^}\r\n]+\}\Z

### web/Example
- 설명: Example challenge
- 원격: https://example.invalid/
```

## 3. 문제 준비 시작

```bash
uv run python -m ctf_os.agent_tools race-prepare \
  'web/Example' --contest 'Demo CTF'
```

결과에서 `attack_ready: true`와 `root_sandbox.status: READY`를 확인한 뒤, 반환된 `next_root_action`으로 바로 풀이를 시작한다.

## 4. 이미지와 도구 확인

전체 이미지, GPU passthrough, CUDA 실행 상태는 다음 명령으로 다시 확인한다.

```bash
uv run python -m ctf_os.agent_tools doctor
```

준비된 sandbox의 카테고리별 도구 카탈로그는 `list-tools`, 개별 사용법과
버전은 `tool-help`, `tool-version`으로 확인한다. 현재 추가 도구는 다음과
같다.

- pwn: pwninit, angrop
- forensic: StegSeek
- misc, crypto: Ares
- web: SSTImap
- osint: Sherlock, Maigret, Holehe, theHarvester

전체 이미지 구성과 보안 제약은 `sandbox/sandbox-tools.txt`, 정확한 고정
버전과 커밋은 `sandbox/tool-versions.lock`이 기준이다.
