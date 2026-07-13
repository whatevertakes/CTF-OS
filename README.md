# CTF-OS

CTF-OS는 사용자가 직접 연 Sol 세션을 위한 로컬 CTF 분석 도구입니다. Python은 `contest.md` 파싱, 안전한 문제 준비, sandbox/service lifecycle, evidence, replay, flag 검증과 내부 eval만 담당하며 Codex나 다른 모델을 실행하지 않습니다.

## 시작 전 준비 (특히 Docker 오류 방지)

아래를 먼저 맞춘 뒤 clone과 설치를 진행하세요. CTF-OS는 **실행 중인 Docker daemon**, **Docker Compose v2**, 외부 공개 이미지 다운로드 권한을 사용합니다. Docker-in-Docker는 사용하지 않습니다.

- **운영체제/가상화:** Linux를 권장합니다. Windows는 Docker Desktop을 설치하고 WSL 2 backend와 사용하는 WSL 배포판 integration을 켭니다. macOS/Windows에서는 Docker Desktop이 실행 중이어야 합니다. BIOS/UEFI에서 가상화가 꺼져 있으면 WSL2·Docker가 정상 동작하지 않습니다.
- **Docker 권한:** Linux에서는 현재 사용자가 Docker socket에 접근할 수 있어야 합니다. `docker info`가 `permission denied`라면 Docker를 설치·기동한 뒤 `sudo usermod -aG docker "$USER"`를 실행하고, 로그아웃/로그인(또는 새 셸 세션) 후 다시 확인합니다. 매 명령에 `sudo docker`를 붙이는 방식은 피하세요.
- **필수 도구:** `git`, Python 3.11 이상, `uv`, Docker Engine 또는 Docker Desktop, Docker Compose v2(`docker compose`)를 준비합니다. 예전 독립형 `docker-compose` 명령만 있는 환경은 지원하지 않습니다.
- **자원:** 이미지와 분석 산출물을 위해 디스크 여유 공간 **최소 10GiB**, Docker에 할당된 사용 가능 메모리 **최소 2GiB**가 필요합니다. forensic/rev/여러 sandbox를 함께 쓸 계획이면 더 넉넉한 메모리를 권장합니다.
- **네트워크/회사 프록시:** 최초 이미지 빌드에는 Docker Hub 등 공개 base image registry로 HTTPS(443) 연결이 필요합니다. 프록시·방화벽 환경이라면 Docker daemon/Desktop에도 프록시와 인증서를 설정해야 합니다. 브라우저나 셸의 프록시 설정만으로는 충분하지 않을 수 있습니다.

clone하기 전에 아래 명령이 모두 성공하는지 확인합니다. 마지막 명령은 공개 image pull과 컨테이너 실행이 가능한지 확인하며, 종료 후 자동으로 삭제됩니다.

```bash
git --version
python3 --version
uv --version
docker info
docker compose version
docker run --rm hello-world
```

`Cannot connect to the Docker daemon`은 Docker Engine/Desktop이 꺼진 상태이고, `permission denied while trying to connect to the Docker daemon socket`은 Linux Docker 권한 문제입니다. `docker compose: command not found`는 Compose v2 설치 또는 Docker Desktop/Engine 업데이트가 필요합니다. `no space left on device`가 나오면 Docker Desktop의 disk image 또는 호스트 디스크 공간을 먼저 확보하세요.

## 처음 시작하기

이 저장소는 SSH 키가 이 private repository에 연결되어 있다는 전제입니다. HTTPS 주소 대신 아래 SSH 주소로 clone합니다.

```bash
git clone git@github.com:whatevertakes/CTF-OS.git
cd CTF-OS
```

- `git clone ...` — CTF-OS 소스와 설정 파일을 현재 위치에 내려받습니다. 최초 한 번만 실행합니다.
- `cd CTF-OS` — 내려받은 저장소 폴더로 이동합니다. 이후 명령은 모두 이 폴더에서 실행합니다.

의존성과 sandbox 이미지를 준비한 다음, Codex에서 이 폴더를 열어 Sol 세션을 시작합니다.

```bash
uv sync --frozen
sandbox/build-images.sh
uv run python -m ctf_os.agent_tools doctor
```

- `uv sync --frozen` — lockfile에 고정된 Python 의존성을 설치합니다. lockfile과 달라지는 임의 업데이트는 하지 않습니다.
- `sandbox/build-images.sh` — 문제 유형별 격리 Docker 이미지를 로컬에 미리 빌드합니다. 처음에는 다소 오래 걸릴 수 있습니다.
- `uv run python -m ctf_os.agent_tools doctor` — Python, Docker, 이미지 등 CTF-OS 실행 환경이 준비됐는지 점검합니다. 오류가 있으면 대회를 시작하기 전에 해결합니다.

`sandbox/build-images.sh`는 공개 base image를 받는 동안 임시 빈 Docker 인증 설정을 자동으로 사용합니다. 따라서 Docker Desktop/WSL의 credential helper 세션이 끊겨 있어도 호스트의 `~/.docker/config.json`을 수정하지 않고 빌드하며, 임시 설정은 종료할 때 삭제합니다. 별도의 Docker 설정이 꼭 필요하면 `DOCKER_CONFIG=/path/to/config sandbox/build-images.sh`처럼 명시하면 그 설정을 그대로 사용합니다.

그래도 일반 `docker pull`에서 `error getting credentials` 또는 `A specified logon session does not exist`가 발생하면 Docker Desktop을 재시작하거나 Docker Hub 로그인을 다시 설정합니다. 이 조치는 CTF-OS 빌드가 아니라 호스트 Docker의 credential helper 세션을 복구하기 위한 것입니다.

준비가 끝나면 아래 한 줄로 `incoming/<contest>/` 아래에 기본 카테고리 폴더(`pwn`, `rev`, `web`, `forensic`, `misc`, `crypto`)와 `contest.md`를 생성합니다. 기존 `contest.md`는 명령을 다시 실행해도 덮어쓰지 않습니다.

```bash
uv run python -m ctf_os.agent_tools init-contest "My CTF 2026"
```

마지막 인자인 `"My CTF 2026"`만 실제 대회명으로 바꾸면 해당 이름으로 폴더와 manifest 제목이 만들어집니다. 생성된 카테고리 폴더에 문제 파일을 넣고 `contest.md`를 작성합니다. 이어서 Sol 세션에 **“intake 해라”**라고 요청해 전체 문제 목록을 준비하고, 새 Sol 세션에서 **“N번 문제 풀어라”**라고 요청해 한 문제씩 풉니다.

```text
문제 파일과 contest.md 작성
→ Sol 세션에서 intake 해라
→ 새 Sol 세션에서 N번 문제 풀어라
→ 검증된 flag 후보 확인
→ 사람이 제출
```

사용자 설정은 `incoming/<contest>/contest.md` 하나뿐입니다. `pwn`, `web`, `rev`, `crypto`, `forensic`, `misc`, `cloud` 외에 `mobile`, `osint`, `hardware`, `blockchain`, `jail`, `windows`, `ai`도 안전한 generic playbook으로 intake됩니다.

```markdown
# 대회명: My CTF 2026
- 날짜: 2026-07-19
- 플래그 형식: MYCTF{...}
- 입력 프로필: standard

### pwn/NBB
- 설명: 문제 원문 설명
- 원격: nc challenge.example 31337
```

입력 프로필은 `standard`, `large`, `large-forensic`만 허용합니다. 큰 프로필도 traversal, link, special-file 방어를 유지합니다. 알 수 없는 필드는 intake warning으로 나오며 `Remtoe` 같은 핵심 오타는 강한 suggestion을 냅니다.

`sandbox/build-images.sh`는 단일 Dockerfile에서 다음 태그를 미리 빌드합니다.

```text
ctf-os-sandbox:base      common CLI/build/Python tools
ctf-os-sandbox:pwn       gdb, qemu-user, patchelf, pwntools
ctf-os-sandbox:web       Node/npm, PHP, SQLite, Flask/FastAPI/JWT
ctf-os-sandbox:rev       radare2, Java, qemu-user, angr
ctf-os-sandbox:crypto    PARI/GP, gmpy2, fpylll, z3, pycryptodome
ctf-os-sandbox:forensic  binwalk, exiftool, sleuthkit, tshark, Volatility3, media/OCR
```

Ubuntu 24.04에서 full SageMath는 기본 패키지로 제공되지 않아 crypto image에 넣지 않았습니다. Sage 전용 문제가 확인된 경우에만 승인된 별도 image를 사용합니다. 모든 tag의 기본 probe 예시는 다음과 같습니다.

```bash
docker run --rm --network none ctf-os-sandbox:base python3 --version
docker run --rm --network none ctf-os-sandbox:pwn gdb --version
docker run --rm --network none ctf-os-sandbox:web node --version
docker run --rm --network none ctf-os-sandbox:rev python3 -c 'import angr; print(angr.__version__)'
docker run --rm --network none ctf-os-sandbox:crypto python3 -c 'import gmpy2,fpylll,z3,Crypto'
docker run --rm --network none ctf-os-sandbox:forensic binwalk --help
```

## 내부 실행 계약

Intake는 중요 파일만 `CONTEXT.md`에 넣고 full inventory는 on-demand JSON으로 분리합니다. category image와 `light`, `standard`, `heavy`, `large-forensic` resource profile을 추천합니다. Admission control은 light 3개, standard 2개, heavy 계열 1개와 host memory budget을 강제합니다.

Dockerfile/Compose 문제는 Docker-in-Docker 없이 host sibling service로 실행됩니다. 각 문제의 label-scoped container와 `ctf-os-net-*` internal network만 만들며 host port와 egress를 제거합니다. privileged, Docker socket, host namespace/device/root 또는 repository 밖 bind, broad capability 등은 `NEEDS_REVIEW`로 차단합니다. 관련 JSON tool은 `service-plan/build/start/status/stop/cleanup`입니다.

Sandbox command는 `/artifacts` 전체를 매번 복사하지 않습니다. `sandbox-export`가 명시적으로 내보내고 cleanup이 최종 export를 수행합니다. `sandbox-status`와 `sandbox-gc`는 active/stale 상태를 확인하고 label-scoped resource만 정리합니다.

최종 solver는 `exploit/`와 구조화된 `REPRODUCE.json`에 저장합니다. `replay`가 current fingerprint를 확인하고 깨끗한 sandbox 두 개에서 독립 실행하며, remote 문제는 별도의 allowlisted sandbox와 firewall counter observation을 요구합니다. 생성되는 `reproduce.sh`는 이 내부 replay만 호출하고 host에서 exploit를 직접 실행하지 않습니다. 제출은 항상 사람이 합니다.

## 내부 평가

`eval/run_eval.py`는 사람이 연 Sol session에서 기록한 `solo`/`adaptive` receipt를 비교합니다. 모델을 시작하지 않으며 paired evidence가 solve rate, median time 또는 agent efficiency 개선을 보일 때만 개선으로 표시합니다.

```bash
uv run python eval/run_eval.py eval/results/*.json --output eval/summary.json
```

공유 IP의 다른 HTTP virtual host를 IP firewall만으로 완전히 분리할 수는 없습니다. HTTPS는 TLS SNI/인증서 검증을 solver가 유지해야 하며, organizer remote가 없는 환경에서는 remote replay 성능을 주장하지 않습니다.
