# 16. Pwn crash 실행 게이트와 실패 재투입 구현 기록

**기록일:** 2026-07-30

**코드 기준:** `c3de503` (`feat: replay typed pwn gate failures`)

**판정:** Pwn D→V의 첫 실행 기반 partial oracle과 failure capsule 재투입은
구현됨. leak·primitive·exploit·impact gate와 solve 성능 향상은 미구현 또는
미측정

## 결론

현재 CTF-OS는 모델이 “크래시를 만들었다”고 서술한 것만으로 Pwn 진척을
확정하지 않는다. 모델이 열린 hypothesis와 exact payload artifact를
지정하면 엔진이 고정된 sandbox recipe로 payload 3회와 빈 control 3회를
실행하고, 실행 증거가 계약을 통과할 때만 typed verdict를 만든다.

실패한 판정도 버리지 않는다. `INCONCLUSIVE`, transport `ERROR`, setup
failure는 현재 managed cycle의 failure capsule에 들어가며 다음 Captain
context가 판정 사유와 exact run/artifact pointer를 다시 받는다. 성공한 Pwn
결과나 선택되지 않은 과거 Pwn 결과를 실패 원인으로 위조할 수 없도록
`selected_action_ids`, experiment status, verdict, reason, stage를 서로
결속했다.

이 구현으로 증명된 것은 안전한 하네스의 **취약 동작 재현 단계**다. working
exploit, flag, solve 확률 향상 또는 실제 CVE 발견 능력은 증명되지 않았다.

## 실행 계약

| 항목 | 현재 구현 |
| --- | --- |
| 입력 | 현재 source manifest에 있는 실행 가능한 ELF, non-empty payload artifact, 열린 hypothesis |
| 환경 | challenge-scoped clean sandbox, network deny, pinned image digest, capability attestation |
| 반복 | 동일 payload 3회 + 엔진이 만든 빈 control 3회 |
| positive oracle | 허용된 동일 fault signal이 payload에서 2/3회 이상 재현 |
| negative oracle | 세 control이 모두 정상 종료 |
| 실패 판정 | 의미상 미충족은 `INCONCLUSIVE`, capture/transport 계약 실패는 `ERROR`, 실행 준비 전 실패는 fixed setup failure |
| 성공의 효과 | experiment `KEPT`, 연결 hypothesis `CONFIRMED` |
| 금지된 승격 | crash만으로 Fact, exploit primitive, proof, 제출 상태를 만들지 않음 |

단순 exit code `139`는 signal crash로 세지 않는다. control crash, 서로 다른
signal의 우연한 조합, 불완전 stdout, recipe/source/payload/image binding
불일치는 성공을 막는다.

## 증거와 commit 경계

각 attempt에는 다음 정본 증거가 연결된다.

- engine-owned request와 execution contract
- run과 receipt
- stdout 및 stderr artifact의 ID, path, SHA-256, size
- artifact가 실제 capture인지 빈 placeholder인지 나타내는
  `capture_placeholder`
- source, payload, recipe, image와 capability attestation hash

엔진은 state commit 전에 request뿐 아니라 durable stdout/stderr 파일도
bounded, no-follow 방식으로 다시 연다. 메모리에 남은 bytes, artifact
metadata, receipt metadata와 실제 파일이 모두 같아야 한다. 첫 commit
guard 뒤 파일이 바뀌는 경우도 state replacement 직전 guard가 다시
차단한다.

큰 stderr처럼 bounded snapshot이 실패하면 빈 placeholder를 남기고 그
사실을 receipt와 artifact 양쪽에 결속한다. flag-looking 문자열 탐지는
bounded artifact와 별도의 전체 실행 stream detector를 사용하므로 후보는
즉시 운영자에게 보일 수 있다. 이 문자열은 candidate일 뿐이며 자동
제출되지 않는다.

프로세스가 state commit 전에 죽으면 recovery journal을 기준으로 정본에
없는 exact Pwn run/evidence만 정리한다. 정리는 challenge root의 directory
file descriptor를 기준으로 하고 symlink를 따라가지 않는다.

## failure capsule과 다음 Captain

typed Pwn non-pass가 선택된 managed action이면 checkpoint failure capsule의
reason은 gate verdict에서 결정적으로 파생된다.

- `INCONCLUSIVE`와 `ERROR`는 실제 evaluation reason 및 `attack` stage와
  일치해야 한다.
- setup 이전 실패는 raw 예외 문자열 대신
  `pwn_crash_setup_failed`만 저장한다.
- terminal typed Pwn experiment는 원래 Builder run의 managed cycle에서
  선택된 action으로 계속 남아야 한다.
- `pwn_crash_*` reason은 선택된 typed non-pass 없이 사용할 수 없다.
- `KEPT` Pwn만 있는 cycle에는 failure capsule을 붙일 수 없다. 일반 실패
  reason을 쓰려면 별도로 선택된 negative non-Pwn experiment가 있어야
  한다.

wide resume capsule은 verdict, reason, evaluation/recipe hash와 여섯
attempt의 run/receipt/stdout/stderr pointer를 제공한다. 1,536-byte compact
경로는 전체 attempt 수, verdict/reason, exact experiment ID와 가장
판별적인 한 attempt의 run/artifact pointer를 남긴다. transport 실패가
2번째 attempt에서 발생했으면 첫 attempt가 아니라 2번째를 선택한다.
일반 experiment의 다중 receipt는 여전히 거부하고, 현재 state schema의
typed Pwn terminal experiment만 정확히 여섯 receipt를 허용한다.

## 독립 평가

evaluation output schema v3에는 `pwn_crash_gate_pass_rate`가 추가됐다.
evaluator는 canonical state의 verdict를 그대로 세지 않고 다음 파일을
bounded/no-follow로 다시 읽어 gate를 재계산한다.

- nominated payload
- 여섯 stdout과 여섯 stderr
- capability attestation
- 여섯 issued request

분모는 terminal typed Pwn gate 전체다. confirmed, semantic non-pass,
transport error, setup failure, unverifiable을 분리하고 setup/unverifiable도
분모에서 빼지 않는다.

`time_to_first_primitive`는 계속 `unavailable`이다. D→V crash 확인은
exploit primitive가 아니며, 모델 progress marker는
`time_to_first_claimed_progress`에만 들어간다.

## 검증 결과

Python `3.13.14`에서 다음을 실행했다.

| 검증 | 결과 |
| --- | --- |
| 전체 저장소 회귀 | 1,010/1,010 통과, 218.286초 |
| fresh-clone source gate의 전체 회귀 | 1,010/1,010 통과, 210.227초 |
| image Pwn crash oracle | 9/9 통과 |
| image Rev inventory | 13/13 통과 |
| image Rev stdin runner | 17/17 통과 |
| capability contract / tool manifest / browser safety / shell syntax | 통과 |
| 세 방향 독립 P0/P1 재감사 | 잔여 P0/P1 없음 |

자동 테스트는 model API call과 원격 CTF request를 하지 않았다. 독립 감사가
중간에 찾은 durable stderr 미결속, 1,536-byte 초과, 실패 ordinal 오선택,
selected Pwn overflow, reason/status 단방향 결속과 selection drift는
회귀를 추가한 뒤 모두 닫았다.

## 성능 주장 경계

[15번 기록](15-nyu-pwn-current-baseline.md)은 수정하지 않는다. 당시 4개
부분 실행은 이 gate가 완성되기 전의 엔진 병목 관측이며, 이번 변경 뒤
NYU/live-like 문제를 다시 실행하지 않았다. 따라서 다음은 아직 주장할 수
없다.

- solve@1 또는 pass^2/3 향상
- median time-to-first-valid-result 단축
- 사람 개입 감소
- thin baseline 대비 성능 향상
- hidden/live Pwn 향상
- ExploitGym 또는 CyberGym-E2E 향상

## 다음 구현 우선순위

다음 Pwn 단계는 고정 선형 `leak required`가 아니라 의존성 gate로 만든다.

1. PIE/ASLR과 목표를 보고 leak을 `required` 또는 `N/A`로 판정
2. GDB 기반 register/mapping 상태와 payload 단계별 replay를 bounded
   artifact로 외부화
3. leak provenance와 deterministic partial oracle 추가
4. primitive → exploit chain → local stability → remote portability 순으로
   실행 gate 확장
5. raw failure log / structured capsule / no-memory 조건 A/B와 60/120분
   반복 평가

대회 평가와 실제 CVE 평가는 합치지 않는다. 이 Pwn gate는 NYU/live-like와
ExploitGym의 일부 단계에 기여할 수 있지만, 미지 코드의 발견→PoC→패치
능력은 CyberGym-E2E 축에서 별도로 측정해야 한다.
