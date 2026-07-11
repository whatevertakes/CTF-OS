# CTF-OS

CTF-OS는 각 팀원이 자신의 PC에서 독립적으로 실행하는 로컬 우선(local-first) 멀티 노드 CTF 풀이 도구입니다. 각 노드는 자체 Codex 시도와 격리된 Docker 컨테이너를 사용합니다. TeamSync는 상태, 발견 사항, 챌린지 소유 이벤트만 append-only 방식으로 공유하며, 다른 팀원의 프로세스를 제어하거나 CTFd에 자동 제출하지 않습니다.

## 시작 전 확인

CTF-OS는 `incoming/{contest}/contest.md`에 선언한 승인된 CTF 대회와 원격 대상에서만 사용합니다. 각 팀원은 자신의 PC에서 별도의 설정, SQLite 상태, Docker 컨테이너, Codex 로그인을 사용합니다.

## 최초 설치

새 팀원은 아래 순서로 로컬 노드를 준비합니다. 예시의 `SCA CTF 2026`은 실제 대회 이름으로 바꿉니다.

```bash
git clone https://github.com/whatevertakes/CTF-OS.git
cd CTF-OS
uv sync --frozen
uv run ctf-os init "SCA CTF 2026" --config config.yaml
```

`config.yaml`에서 `contest.team_id`, `member.name`, 담당 카테고리를 설정합니다. 이어서 `incoming/SCA CTF 2026/contest.md`에 승인된 대회와 챌린지 메타데이터를 추가합니다.

공용 sandbox 이미지를 준비하고 로컬 상태를 검증합니다.

```bash
scripts/deploy_ctf_os.sh --config config.yaml
uv run ctf-os doctor --config config.yaml --non-mock
```

`ctf-os run`은 Docker 이미지를 자동으로 빌드하지 않습니다. 풀이를 시작하기 전에 배포와 진단이 모두 성공해야 합니다.

## 챌린지 실행

대회 입력을 파싱한 뒤 상시 실행 또는 한 번의 실행을 선택합니다.

```bash
uv run ctf-os parse --config config.yaml
uv run ctf-os run --config config.yaml
uv run ctf-os run --once --config config.yaml
```

상태와 현재 노드가 담당한 챌린지의 플래그 후보는 TUI에서 확인합니다.

```bash
uv run ctf-os tui --config config.yaml
uv run ctf-os tui --plain --config config.yaml
```

아래 제어 명령은 현재 PC의 현재 노드에만 적용됩니다.

```bash
uv run ctf-os pause <challenge> --config config.yaml
uv run ctf-os resume <challenge> --config config.yaml
uv run ctf-os retry <challenge> --config config.yaml
```

## 여러 팀 분리

같은 대회에 두 팀을 운영할 때는 팀마다 `team_id`, SQLite 출력 경로, TeamSync 경로와 네임스페이스를 모두 분리합니다. 다른 팀에 연결된 데이터베이스를 열지 마세요.

```yaml
# config-sca-a.yaml
contest:
  name: "SCA CTF 2026"
  team_id: "sca-team-a"
paths:
  incoming: "incoming"
  output: "output/sca-team-a"
sync:
  root: "sync/sca-team-a"
  team_namespace: "sca-team-a"
```

다른 팀에는 위 네 값 전체에 `sca-team-b`를 일관되게 사용합니다. 설정 파일을 명시해 상태를 준비하고 검증합니다.

```bash
uv run ctf-os state migrate --config config-sca-a.yaml
uv run ctf-os parse --config config-sca-a.yaml
uv run ctf-os doctor --config config-sca-a.yaml --non-mock
```

### 4인 팀 예시

한 로컬 전용 팀은 공통 `team_id`인 `sca-jiwoong-team`을 사용하고, 팀원은 각자의 노드에서 맡은 카테고리만 처리합니다.

| 팀원 | 담당 카테고리 예시 |
| --- | --- |
| jiwoong | pwn, web |
| jueon | rev, crypto |
| hyunseok | forensics, misc |
| howon | cloud, web3 |

팀원별 `member.name`, 로컬 SQLite 데이터베이스, 컨테이너, Codex 로그인은 분리됩니다. TeamSync는 챌린지 소유 이벤트만 공유하며, 다른 팀원의 로컬 프로세스를 시작하거나 중지하지 않습니다.

## 업데이트

대회 중에는 아래 순서로 코드와 로컬 환경을 업데이트합니다.

```bash
git pull --ff-only origin main
scripts/deploy_ctf_os.sh --config config.yaml
uv run ctf-os doctor --config config.yaml --non-mock
```

`config.yaml`, 대회 입력, SQLite 데이터베이스, 산출물, TeamSync 로그, 자격 증명, 키, 플래그는 커밋하지 마세요. 최초 설치와 업데이트의 자세한 절차는 [팀 배포 가이드](docs/CTF_OS_TEAM_DEPLOYMENT.md)를 참고하세요.
