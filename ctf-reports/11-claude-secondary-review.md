# Claude CLI secondary review

검증일: 2026-07-28 (Asia/Seoul)

## 실행 조건

- CLI: Claude Code `2.1.220`
- 모델/강도: Opus 5, max effort
- 모드: plan/read-only
- 허용 도구: Read, Glob, Grep
- MCP: 빈 strict 구성
- Web/외부 쓰기/지속 메모리: 사용 안 함
- 결과: 정상 완료, 약 721초·55 turns

위 실행은 구현 중간의 최초 2차 검토다. 최종 source freeze에 대한 새 Opus
검토 결과는 이 문서 아래의 “최종 freeze 재검토”에 별도로 기록한다.

이 검증은 구현 주체와 다른 모델이 저장소를 읽고 반례를 찾는 2차
검토다. 실행 가능한 테스트와 최종 판정은 CTF-OS 회귀 suite가 담당하며,
Claude의 심각도 표시는 그대로 수용하지 않고 코드 경계와 재현 결과로
재판정했다.

## 발견 사항과 처리

| 발견 | 최초 등급 | 처리 |
|---|---:|---|
| Live mailbox watcher가 긴 `tool.run` 동안 `agent.flag`를 막음 | HIGH | 장기 작업을 bounded lane으로 분리하고 flag fast-path 추가. active tool 중 flag의 durable commit·즉시 출력 회귀 추가 |
| File FIFO cancel polling이 ticket을 매번 재등록해 FIFO를 잃음 | HIGH | ticket 1회 등록, cancellation event, dead holder 회수, 실제 3-process FIFO 회귀로 교체 |
| delegation owner가 문서에 비해 반쪽 구현 | MEDIUM | native owner 기록과 typed goal/hypothesis/evaluation lifecycle 연결 |
| 두 문제 세션 3+3 역할 E2E 부재 | MEDIUM | 두 challenge 동시 wave, provider cap 대기, 한쪽 계약 실패 격리, holder/queue 회수 회귀 추가 |
| broker transition target 방어가 MCP schema에만 의존 | MEDIUM | broker에서 enum 변환과 engine state-machine 검증을 다시 수행 |
| cumulative Live inspect가 1 MiB를 넘을 수 있음 | MEDIUM | summary와 최대 200개 page, 768 KiB response budget, oversized-record stub 추가 |
| 제출 state/ledger crash 일관성 부족 | MEDIUM | fsynced intent journal과 시작 시 reconciliation 추가 |
| candidate를 durable commit 전에 출력 | MEDIUM | Live `agent.flag`는 state commit 뒤 출력. Batch/tool/proof stream은 bounded fsynced intent 뒤 즉시 출력하고 정상 commit 후 clear. crash-left intent는 다음 session에서 먼저 재출력한 뒤 value 기준으로 멱등 reconcile해 누락보다 중복을 우선 |
| prompt가 조용히 잘림 | MEDIUM | 명시적 truncation notice, omitted count, canonical state pointer 추가 |
| session prompt가 owner lock 전 변경될 수 있음 | MEDIUM | `solve`/`run-challenge`/직접 update/기존 `add-challenge --prompt` 모두 lock 획득 뒤 commit. 경쟁 `SessionAlreadyRunning`에서 prompt/revision/canonical bytes 불변 회귀 추가. target·knowledge·budget 등 configuration mutation 전체에 대한 보장은 아님 |
| Docker `--mount`에서 쉼표 경로가 깨짐 | MEDIUM | Docker Go CSV 필드 인코더 공통화, 쉼표·따옴표 실제 Docker mount 검증 |
| `/work`·artifact/proof 디스크 증폭 | HIGH | configurable work-tree cap, 안정된 descriptor 2-pass 전후 계측, sparse/hardlink 보수 회계, stream/artifact/proof 연동. 라이브 filesystem quota는 아님 |
| proof가 선택 candidate 외 새 flag를 놓침 | MEDIUM | 일반 `/work` 밖 private sibling의 proof raw/sidecar를 실행 중 tail해 intent fsync 뒤 즉시 출력하고, final proof directory에 sidecar를 bounded copy해 raw cap 뒤 후보도 보존. 추가 후보는 attempt commit에 포함하되 sidecar만으로 proof 성공을 만들지는 않음 |
| flag tailer가 join 실패를 숨김 | LOW | bounded join 실패와 polling/final-drain 오류를 명시적으로 표면화 |

## 판정이 달랐던 항목

Claude는 production surface의 `exec`와 `apply_patch`를 host-shell HIGH로
분류했다. 실제 배포 계약에서 `exec`는 filesystem/network가 없는 V8
orchestration이고, `apply_patch`는 해당 challenge workspace에만 쓰는
typed 변경 도구다. 임의 host shell과 동일하지 않으므로 HIGH 판정은
기각했다. 다만 사용자 문서와 tool inventory에는 이 차이를 명시하고,
challenge process가 host Docker/socket/state에 직접 접근하지 못하는
경계는 계속 검증한다.

Production request에 확인된 다른 built-in은 `wait`, native collaboration,
`tool_search`, `view_image`, plan/user-input과 generic MCP resource
helper다. 열네 개는 전체 tool inventory가 아니라 required `ctfos_live`
MCP의 canonical state/challenge-execution operation 수다.

## 잔여 위험

- Codex 0.145의 built-in `view_image`는 제거할 수 없다. Legacy
  workspace-write와 같은 Unix UID 조건에서는 model이 추측 가능한
  challenge workspace 밖 host image path를 입력으로 올릴 수 있어
  정책·프롬프트와 대회 전 민감 이미지 정리가 남는다.
- work-tree cap은 command 전후 guard다. 커널 project quota처럼 실행 중
  매 write를 막지 않으므로 순간 초과 가능성이 있다.
- canonical artifact 실제-byte 합계 cap은 있지만 누적 `runs/` raw,
  contest `submissions.jsonl`과 challenge tree 전체의 총량 quota·retention·
  GC는 없다.
- 실제 대회 원격 egress/rate는 `enforcement=proxy`인 외부 제한 network가
  준비돼야 한다. 내부 hostname FIFO는 command 시작만 기본 1초 간격화하며
  command 내부 HTTP request-rate limiter라고 부르지 않는다.
- 실제 Sol/Terra/Luna 전체 solve 성능은 회귀 fixture나 Luna 단일 MCP
  probe만으로 보증하지 않는다.
- 정상 timeout·cancel과 달리 host engine 자체의 `SIGKILL`·전원 손실은 이미
  시작된 Codex 자식이나 Docker daemon 소유 foreground container를 남길 수
  있다. PID-backed holder 회수 뒤 일시적 상한 초과가 가능하므로 재개 전
  operator cleanup이 필요하다. 정확한 폐쇄에는 별도 guardian/supervisor가
  필요해 crash-only 잔여 위험으로 수용한다.

## 후속 통합 검증

Claude가 지적한 항목을 닫은 뒤 Codex `/review`에서 다음 경계도 추가했다.

- Live의 `ctfos_live` canonical state/challenge-execution surface를 14개
  typed operation으로 고정하고 운영자 주입
  지식에 read-only `knowledge.search`/64 KiB `knowledge.read`를 제공
- problem prompt·active goal·open hypothesis에 맞는 hash-verified 지식
  excerpt 선택
- 8시간 deadline을 Live/Batch/provider/tool/proof process와 wait에 hard
  clamp하고 wave context 준비 전 공통 monotonic `D`, Live `Popen` 전 `D`,
  tool/proof evidence·locked success 판정까지 같은 `D`를 유지. Reset은
  이미 발급된 `D`를 소급 변경하지 않음
- 반복 명령·동일 failure·증거 부재를 `STALLED`로 바꾸되 recovery는 제안만
  하고 자동 session/tool/model 실행은 하지 않는 governor
- canonical state와 proof bytes만 읽는 결정론적 평가 집계
- canonical state JSON 16 MiB, 최상위/known nested repeated field
  16,384개, 모든 commit의 referenced artifact 실제-byte 합계 cap
- 같은 hostname의 tool/proof command 실제 시작을 간격화하는
  cross-process FIFO
- response publish 직전 `ENOENT`가 다시 존재하게 되는 Live mailbox
  TOCTOU를 정상 재시도로 분리
- flag notification·tool lease 획득/반납·run-result 저장 실패가
  `RUNNING`을 남기지 않도록 공통 실패 종결
- session 경계에서 crash-left candidate를 먼저 재출력하고 orphan
  `RUNNING` run을 `FAILED`로 회복
- 서로 다른 challenge wave를 종료하지 않는 cancel-event scoped
  subprocess cancellation
- tool stdout snapshot과 terminal source run을 executed fact에 결속하고,
  persistence 실패 시 exact artifact를 정리
- reset과 겹친 foreground tool은 reset 뒤 구간만 새 예산에 과금
- model이 낸 잘못된 semantic ID는 해당 item만 rollback·bounded 진단하고
  같은 wave의 유효한 결과는 보존
- CLI status의 contest/name/field 전체 terminal escaping, 다중 artifact와
  proof result persistence 실패 cleanup
- tool setup·sandbox·summary scan·snapshot·artifact scan·result persistence와
  final commit 경계의 `KeyboardInterrupt`/`SystemExit`을 실패 종결하고,
  lease 1회 반납·commit 전 exact cleanup·commit 후 canonical evidence
  보존 뒤 원 예외 재전파
- proof input snapshot/등록, attempt evidence/result/commit, final
  result/environment commit 전후의 정상 interrupt exact cleanup과 canonical
  보존
- direct Codex와 Live attached process의 parent-only interrupt에서
  TERM-ignoring descendant까지 exact process-group reap하고, Docker
  foreground exact-name container를 강제 제거한 뒤 원 예외 재전파
- 공개 `run_role`도 빈 problem-solving prompt를 모델 호출 전에 거부
- CPython 3.13 executor start→registry 창과 tailer delayed bootstrap에서
  wave dispatch admission, stop publication, liveness/join과 callback drain을
  session lock 안에서 완료
- main-thread `Popen` constructor를 helper가 소유해 `_fork_exec`→PID STORE
  interrupt를 exact reap하고, 정상 leader의 residual process group도
  return code 125로 fail-closed
- work-tree entry 상한을 `scandir` 전체 materialize 전에 전역 cap+1에서
  중단

Artifact/proof의 “immutable”은 mode `0400`과 size/hash 재검증으로
tamper-evident한 engine-managed copy라는 뜻이다. 같은 Unix UID 쓰기를
OS-level로 금지하는 보장은 아니다.

최종 요구사항별 수용 증거와 남은 운영 경계는
[12 최종 수용성 기록](12-final-acceptance.md)에 정리한다.

## 최종 freeze 재검토

최종 구현 source freeze는 다음 aggregate hash로 고정했다.

```text
09641f4466b30add7d18d6239a6ff73fb9afa8baccf2fb2d49b2ce5c55a8d96b
```

이 freeze에 대해 Claude Code `2.1.220`을 새 프로세스로 다시 실행했다.
모델은 `opus`, effort는 `max`, 모드는 plan/read-only였고 허용 도구는
`Read`, `Glob`, `Grep`뿐이었다. MCP는 빈 strict 설정을 사용했고 browser,
외부 쓰기와 지속 메모리는 사용하지 않았다.

검토 범위에는 사용자 계약, hard deadline과 `timeout=0`, control exception
우선순위, CPython 3.13 thread/process bootstrap 창, 취소된 callback과
wave drain, FD/lock ordering, proof/manual submission 경계가 포함됐다.
Claude는 수용된 P3 밖의 구체적으로 재현 가능한 P0/P1/P2를 찾지 못했고
최종 출력은 다음과 같았다.

```text
Result: PASS.
FINAL VERDICT: PASS
```

검토 후 aggregate source hash를 다시 계산해 동일함을 확인했다. 따라서 이
결과는 검토 도중 source가 변한 상태에 대한 판정이 아니다. 남은 P3는
숫자 FD/PGID의 극소 ABA·generation 창, cleanup 중 두 번째 독립 signal과
crash-only 손실, 같은-UID `view_image`/Docker 경계, 외부 proxy·실계정
성능, 비정상적으로 큰 finite wait의 fail-closed, proof command 원인성과
의도적 hardcoding에 대한 operator trust다.
