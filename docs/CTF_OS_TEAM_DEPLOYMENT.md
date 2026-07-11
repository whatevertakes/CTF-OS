# CTF-OS 팀 배포 가이드

각 팀원은 CTF-OS를 자신의 PC에서 실행합니다. `main`을 pull하면 코드만 배포됩니다. 다른 팀원의 설정, SQLite 상태, 대회 입력, 출력물, TeamSync 로그, Codex 로그인, Docker 컨테이너를 공유하거나 덮어쓰지 않습니다.

## 기존 노드 업데이트

업데이트 전, 본인이 수정한 소스 파일이 있다면 커밋하거나 stash합니다. 로컬 실행 파일은 Git에서 무시되므로 각 팀원의 PC에 그대로 남습니다.

```bash
git pull --ff-only origin main
scripts/deploy_ctf_os.sh --config config.yaml
uv run ctf-os doctor --config config.yaml --non-mock
```

배포 스크립트는 여러 번 실행해도 안전합니다. 다음 작업을 수행합니다.

- `uv sync --frozen`으로 잠긴 의존성을 설치합니다.
- 설정된 로컬 SQLite 데이터베이스를 열어 순서가 보장된 트랜잭션 마이그레이션을 실행합니다.
- `ctf-os-sandbox:latest` 이미지가 없을 때만 빌드합니다.
- 항상 sandbox smoke test를 실행합니다.

Smoke test는 설치된 CTF 도구, 공용 이미지 ID, 16 GiB 하드 메모리 제한, 메모리 예약 0, 2 vCPU 제한, CPU 고정 미사용을 확인합니다. `ctf-os run`은 이미지를 자동으로 빌드하지 않습니다.

Dockerfile 변경 뒤 기존 이미지를 의도적으로 교체하려면 다음을 사용합니다.

```bash
scripts/deploy_ctf_os.sh --config config.yaml --rebuild-image
```

Docker를 일시적으로 사용할 수 없는 PC에서는 설치와 마이그레이션만 하려면 `--skip-image`를 사용합니다. 이 상태는 실제 풀이 시도를 실행할 준비가 된 것이 아닙니다. Docker를 사용할 수 있게 된 뒤 일반 배포 명령으로 이미지를 빌드하고 검증하세요.

```bash
scripts/deploy_ctf_os.sh --config config.yaml --skip-image
```

## 최초 설치

배포 스크립트가 상태를 마이그레이션하기 전에 팀원별 로컬 설정을 만듭니다. `config.example.yaml`을 검토하고 각자의 식별자와 담당 카테고리를 입력하세요.

```bash
uv sync --frozen
uv run ctf-os init "대회 이름" --config config.yaml --team-id 팀-식별자 --member 내-이름
# config.yaml 및 incoming/대회 이름/contest.md를 검토합니다.
scripts/deploy_ctf_os.sh --config config.yaml
uv run ctf-os doctor --config config.yaml --non-mock
```

`--team-id`는 같은 팀원이 공유하고, `--member`는 각 PC에서 고유해야 합니다. 새 설정은 SQLite 상태를 `output/<team-id>/<member>/` 아래에 생성하므로, 같은 PC에서 여러 팀이나 노드를 준비해도 로컬 상태가 섞이지 않습니다.

같은 대회의 새 멤버 노드는 별도 설정 파일과 `--member` 값을 사용합니다. 이미 있는 `contest.md`는 새 설정을 초기화할 때 그대로 재사용하며 덮어쓰지 않습니다.

`config.yaml`, `incoming/`, `output/`, `sync/`, SQLite 파일, 로그, 자격 증명, 키, 플래그는 커밋하지 마세요. 배포 스크립트는 이 경로들을 삭제·초기화·복사·외부 전송하지 않습니다.

## 개별 검증 명령

각 작업은 필요할 때 다음처럼 따로 실행할 수 있습니다.

```bash
uv sync --frozen
uv run ctf-os state migrate --config config.yaml
docker build -f sandbox/Dockerfile.sandbox -t ctf-os-sandbox:latest .
scripts/verify_sandbox_image.sh ctf-os-sandbox:latest
```

명시적인 `docker build`는 노드를 한 번 준비하는 작업입니다. 챌린지나 풀이 시도 라이프사이클에서 수행하는 명령이 아닙니다.
