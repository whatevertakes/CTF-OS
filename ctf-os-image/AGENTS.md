# CTF-OS 샌드박스 이미지

## 목적

자동화된 CTF 풀이 시스템(CTF-OS)이 사용하는 도구 컨테이너 이미지.
verialabs/ctf-agent 의 sandbox 와 같은 역할을 한다.

**LLM 은 호스트에서 실행되고, 이 컨테이너는 도구 실행 전용이다.**
컨테이너 안에 codex/claude CLI, API 키, CTFd 토큰을 절대 넣지 않는다.
호스트 에이전트가 `docker exec` 로 명령을 실행하는 구조다.

## 확정된 설계 결정 (변경 금지)

- 베이스: Ubuntu 24.04. SageMath 는 24.04 아카이브에 없으므로 micromamba + conda-forge 로 설치
- **단일 이미지.** CPU/CUDA 를 나누지 않는다. PyTorch 는 CUDA 휠을 쓰고 GPU 없는 머신에서는 CPU 로 폴백된다
- hashcat 은 OpenCL 백엔드. nvidia/cuda 베이스 이미지와 nvcc 는 쓰지 않는다
- 카테고리: web / pwn / rev / crypto / forensic / misc + 한글 자산. 그 외(모바일, 블록체인, 클라우드, SDR, OSINT)는 넣지 않는다
- 파이썬은 3계층: `/opt/venvs/main`(기본) / 도구별 격리 venv / `/opt/mamba/envs/sage`
- `/challenge` 는 읽기 전용, `/work` 가 작업 공간이자 WORKDIR

## 사용자는 사람이 아니라 LLM 에이전트다

- **어떤 명령도 stdin 없이 실행했을 때 멈추면 안 된다.** 페이저, TUI, 확인 프롬프트 금지
- 긴 출력은 파일로 저장하고 stdout 에는 요약만 낸다
- 장시간 도구(hashcat, john, cado-nfs, angr, stegseek)는 백그라운드 잡으로 돌린다
- 사람 편의 도구(zsh, tmux, fzf, vim 플러그인)는 넣지 않는다

## 비목표

- GUI, noVNC, 데스크톱 환경
- TensorFlow, JAX
- Android 에뮬레이터
- 이미지 안에서의 LLM 실행

## 작업 원칙

- 버전 문자열을 추측하지 말 것. GitHub API 나 릴리스 페이지를 실제로 조회해서 확인한다
- 확인 불가능한 항목은 임의로 채우지 말고 보고한다
- Dockerfile 에 없는 도구를 임의로 추가하지 않는다
- 각 스크립트는 `set -euo pipefail` 로 시작하고 인자 없이 실행하면 사용법을 출력하고 즉시 종료한다
