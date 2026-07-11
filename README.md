# CTF-OS

CTF-OS는 각 팀원이 자신의 PC에서 독립적으로 실행하는 로컬 우선(local-first) 멀티 노드 CTF 풀이 도구입니다. 각 노드는 자체 Codex 시도와 격리된 Docker 컨테이너를 사용합니다. TeamSync는 상태·발견 사항·챌린지 소유 플래그만 append-only 방식으로 공유하며, 다른 팀원의 프로세스를 제어하거나 CTFd에 자동 제출하지 않습니다.

## 빠른 시작

아래 명령은 새 팀원이 자신의 PC에 노드를 처음 준비할 때 실행합니다.

```bash
git clone https://github.com/whatevertakes/CTF-OS.git
cd CTF-OS
uv sync --frozen
uv run ctf-os init "SCA CTF 2026" --config config.yaml
```

`config.yaml`에서 팀의 `contest.team_id`, 본인 이름, 담당 카테고리를 설정합니다. 이후 승인된 대회와 챌린지 메타데이터를 `incoming/SCA CTF 2026/contest.md`에 추가합니다.

공용 sandbox 이미지를 한 번 빌드하고 로컬 상태를 마이그레이션합니다.

```bash
scripts/deploy_ctf_os.sh --config config.yaml
uv run ctf-os doctor --config config.yaml --non-mock
```

`ctf-os run`은 Docker 이미지를 자동으로 빌드하지 않습니다. 풀이를 시작하기 전에 위 배포 명령과 진단을 성공시켜야 합니다.

## 로컬 노드 실행

대회 입력을 읽고 챌린지를 준비한 뒤 실행합니다.

```bash
uv run ctf-os parse --config config.yaml
uv run ctf-os run --config config.yaml
uv run ctf-os run --once --config config.yaml
```

상태와 본인 노드가 담당한 챌린지의 플래그 후보는 다음과 같이 확인합니다.

```bash
uv run ctf-os tui --config config.yaml
uv run ctf-os tui --plain --config config.yaml
```

아래 제어 명령은 **현재 PC의 현재 노드에만** 적용됩니다.

```bash
uv run ctf-os pause <challenge> --config config.yaml
uv run ctf-os resume <challenge> --config config.yaml
uv run ctf-os retry <challenge> --config config.yaml
```

## 같은 대회에 두 팀을 운영할 때

팀마다 `team_id`, SQLite 출력 경로, TeamSync 네임스페이스가 반드시 달라야 합니다. 다른 팀에 연결된 데이터베이스를 열지 마세요.

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

다른 팀은 네 값 모두에 `sca-team-b`를 일관되게 사용합니다. 이후 해당 설정 파일을 명시해 마이그레이션·파싱·진단을 실행합니다.

```bash
uv run ctf-os state migrate --config config-sca-a.yaml
uv run ctf-os parse --config config-sca-a.yaml
uv run ctf-os doctor --config config-sca-a.yaml --non-mock
```

### KISIA 4인 팀 예시

한 로컬 전용 팀은 공통 `team_id`인 `sca-jiwoong-team`을 사용하고, 팀원은 각자의 노드에서 맡은 카테고리만 처리합니다.

| 팀원 | 담당 예시 |
| --- | --- |
| jiwoong | pwn, web |
| jueon | rev, crypto |
| hyunseok | forensics, misc |
| howon | cloud, web3 |

팀원별로 `member.name`, 로컬 SQLite 데이터베이스, 컨테이너, Codex 로그인이 분리됩니다. TeamSync는 챌린지 소유 이벤트만 공유하며, 다른 팀원의 로컬 프로세스를 시작하거나 중지하지 않습니다.

## 팀 업데이트

대회 중 업데이트는 아래 순서로 수행합니다.

```bash
git pull --ff-only origin main
scripts/deploy_ctf_os.sh --config config.yaml
```

로컬 `config.yaml`, 대회 입력, SQLite 데이터베이스, 산출물, TeamSync 로그, 자격 증명, 키, 플래그는 절대 커밋하지 마세요. 자세한 최초 설치·업데이트 절차는 [팀 배포 가이드](docs/CTF_OS_TEAM_DEPLOYMENT.md)를 참고하세요.
