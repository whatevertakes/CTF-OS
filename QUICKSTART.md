# CTF-OS 팀 quickstart

팀원 머신에서 CTF-OS를 돌리기까지의 최단 경로입니다.
운영 매뉴얼 전체는 [README](README.md), 릴리스 판정은
[RELEASE_STATUS](RELEASE_STATUS.md)에 있습니다. **이 문서만 보고 시작해도 됩니다.**

## 핵심 규칙 하나

**`ctf-os-image/Dockerfile`을 직접 빌드하지 마십시오.**

베이스가 digest가 아닌 `ubuntu:24.04` 태그이고, `apt-get install` 10개 블록에
버전 핀이 하나도 없고, `pip install` 26줄 중 22줄이 무핀입니다. 그래서 각자
빌드하면 image ID뿐 아니라 **안에 든 도구 버전이 서로 달라집니다.**
`ctfos doctor`는 capability 35개의 존재만 확인하고 버전은 보지 않으므로,
서로 다른 시스템을 돌리면서 **양쪽 다 초록불**을 봅니다.

이미지는 운영자 한 명이 만들어 배포하고, 나머지는 그걸 그대로 씁니다.

---

## 팀원: 클론부터 실행까지

운영자에게 **이미지 tarball**과 **exact image ID**를 받으세요.

```sh
git clone https://github.com/whatevertakes/CTF-OS.git ~/CTF-OS
cd ~/CTF-OS

scripts/team-setup.sh \
  --tar ~/ctf-os-dist/image/ctf-os-core-4183b4cd.tar.gz \
  --expect sha256:<운영자가 알려준 image ID>
```

tarball 옆에 `<파일명>.sha256`이 있으면 스크립트가 **로드 전에** 아카이브 해시를
자동 검사합니다. 12 GB 전송이 깨졌는지를 `docker load`에 10분을 쓰기 전에
잡습니다. 사이드카가 없으면 `--tar-sha256 sha256:<해시>`로 직접 주세요.

레지스트리를 쓰는 경우에는 `--tar` 대신 `--from <참조>`를 씁니다.

스크립트가 하는 일 — 사전 요구 확인 → `uv sync --frozen` → `ctfos` 설치 →
이미지 로드/pull → `ctfos init` → **호스트 등급 자동 판정 후 `[resources]` 설정**
→ `ctfos pin-image` → `ctfos doctor`.

`준비 완료.`가 나오면 끝입니다. 걸리는 시간은 이미지 전송을 빼면 1~2분,
이미지까지 포함하면 5~15분입니다.

마지막에 `.ctfos/team-setup-report.json`이 생깁니다. **이걸 팀에 공유하세요.**
누구 머신만 왜 다른지가 바로 보입니다.

`준비 완료.` 이후에는 tarball을 지워도 됩니다. 이미지가 이미 Docker에
들어가 있으므로 12.6 GB를 그대로 둘 이유가 없습니다. 디스크는 이미지 11.8 GB
외에 문제 작업공간이 필요하고 forensics 한 문제가 15 GB를 쓴 실측이 있어
여유 60 GB를 권장합니다.

## 각자 준비할 것 (저장소에 없음)

- **Codex CLI 로그인** — credential을 저장소·프롬프트·`.ctfos/` 로그에 넣지 마십시오
- **문제 파일** — `incoming/` 아래에 사람이 직접 넣습니다
- `.ctfos/` 상태는 남의 것을 복사하지 않습니다. 재현 절차가 아닙니다

## 호스트 등급

스크립트가 CPU/RAM을 보고 자동으로 정합니다. `--tier S|M|L|XS`로 직접 지정하거나
`--tier none`으로 끌 수 있습니다.

| 등급 | RAM | 코어 | `tool_cpu_budget` | `tool_memory_gib` | release matrix |
|---|---|---|---|---|---|
| S | 64 GB+ | 16+ | 12 | 40 | `--jobs 2` |
| M | 32 GB | 12 | 8 | 18 | `--jobs 2` |
| L | 16 GB | 8 | 4 | 8 | `--jobs 1` |
| XS | 8 GB | 4 | 2 | 4 | 불가 |

이 단계가 필요한 이유: `[resources]`는 호스트 자원과 **어디에서도 대조되지
않고**, `ctfos doctor`는 CPU/RAM/디스크 부족을 **경고하지 않습니다**
(`ctf_os/doctor.py`). 자원이 모자라면 오류가 아니라 리스 FIFO에서 기다리다
`lease_wait_timeout_s`(기본 300초)에 타임아웃합니다. 원인 없는 지연처럼 보이는 게
이것입니다. GPU가 없으면 `max_gpu_jobs`를 반드시 0으로 두어야 합니다 —
기본값 1은 GPU 유무와 무관하게 들어가 있어서 `gpu` 프로파일 요청이 Docker 실행
**전에** 실패합니다.

**XS는 `heavy` 프로파일(4c/8GiB)을 admit할 수 없습니다.** pwn interaction과
web active probe 게이트가 돌지 않으므로 풀이 전용으로만 쓰십시오.

---

## 운영자: 이미지 배포

이미지를 만든 머신에서 한 번만 합니다.

```sh
docker image inspect --format '{{.Id}}' ctf-os:core    # ← 이 값을 팀에 공유
```

**tarball + rsync.** 이 팀의 정본 경로입니다. 레지스트리는 쓰지 않습니다 —
GHCR private은 무료 플랜 quota(storage 500 MB / 전송 1 GB)를 12 GB가 즉시
초과하고, public 공개는 도구 구성이 그대로 드러납니다.

```sh
docker save ctf-os:core | gzip > ctf-os-core.tar.gz     # 약 12.6 GB
sha256sum ctf-os-core.tar.gz > ctf-os-core.tar.gz.sha256
rsync -avP --partial ctf-os-core.tar.gz{,.sha256} 팀원:~/
```

`.sha256` 사이드카를 **반드시 같이 보내십시오.** 팀원 쪽 `team-setup.sh`가
그걸 자동으로 찾아 로드 전에 검사합니다. `--partial`은 12 GB 전송이 끊겨도
이어받게 합니다.

이미 `ctf-os-dist` 배포 번들을 만들어 두었다면 그 안의
`image/ctf-os-core-*.tar.gz`와 `MANIFEST.json`의 `image.archive_sha256`을
그대로 쓰면 됩니다. 번들 전체를 넘길 때는 `verify.sh --bundle-only`가
같은 검사를 합니다.

전송 수단은 상황에 따라 고르십시오.

| 상황 | 방법 |
|---|---|
| 같은 네트워크 | `rsync -avP --partial` (끊겨도 이어받음) |
| 같은 자리 | 외장 SSD가 제일 빠름 |
| 중간 파일을 남기고 싶지 않을 때 | `docker save ctf-os:core \| gzip \| ssh 팀원 'gunzip \| docker load'` (재개 불가) |
| 3대가 상시 같은 LAN | 운영자 머신에 로컬 레지스트리(`registry:2`)를 띄우고 `--from`을 쓰는 것도 가능 (각 클라이언트에 insecure-registry 설정 필요) |

## 운영자: 역할 분리

전원이 release matrix를 돌 필요가 없습니다. `RELEASE_STATUS.md`의 모델은
운영자가 **하나의** receipt를 선택하는 것입니다.

- **검증 머신 1대 (S 또는 M):** 이미지 빌드, `pin-image`, all-category matrix,
  `scripts/check-release-acceptance.py` receipt 발급. 이 머신이 팀의 릴리스 권위입니다.
- **풀이 머신 N대 (등급 무관):** 그 이미지를 받아 `pin` 하고 문제만 풉니다.

이렇게 하면 저사양 머신이 매트릭스 최소 사양을 못 넘겨도 팀 운용이 막히지 않습니다.
