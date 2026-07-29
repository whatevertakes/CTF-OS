# 14. 관리형 풀이 엔진 수술 전 근거 동결

**동결일:** 2026-07-29
**대상:** 관리형 `Captain → 3-role wave → 실행 → 평가 → checkpoint` 전환

이 문서는 구현 전에 무엇이 관측값이고 무엇이 설계 판단인지 고정한다.
성과를 소급해 유리하게 해석하지 않도록, 아래 표의 중단 조건과 표본 한계를
구현 결과와 분리해 둔다.

## 출처 등급

| 등급 | 이 문서에서의 의미 |
| --- | --- |
| **A** | `.ctfos/`의 `state.json`, run envelope, artifact, ledger에서 직접 계수한 값 |
| **B** | Codex rollout 로그에서 계수한 값 |
| **C** | 저장소 코드·계약·설계 문서에서 확인한 동작 |
| **D** | A–C에서 계산하거나 향후 실험을 위해 제안한 추정 |

학술 출처 자체의 A–D 등급은
[08-verification-log.md](08-verification-log.md)의 분류를 따른다. 이 문서의
A–D는 실전 기록의 관측 경로를 뜻하며 둘을 섞지 않는다.

## 동결한 관측

- **[측정, A]** 분석 대상 5문제에는 686 run, 688 experiment, 677 fact,
  1,371 artifact, 164 candidate가 있었다.
- **[측정, A/C]** model run은 3건뿐이었고, 논리적 3-role wave는 한 번만
  기록되었다. 기존 성과를 managed 성과로 소급 귀속하지 않는다.
- **[측정, A]** experiment 688건 중 평가가 끝난 것은 57건이었다.
- **[측정, A]** generic flag 정규식은 APT-213과 Go Through Me에서 각각
  97–99%의 미판정 후보를 만들었다. 이것을 곧바로 모든 후보의
  “오탐률”로 일반화하지 않는다.
- **[측정, A/B]** 정본 밖 raw shell 실행이 관측되었으므로 state 기반
  작업량은 하한이다. rollout 문자열 검색은 코드·설명 문자열을 포함할 수
  있으므로 상한 성격이다.
- **[측정, C]** 현재 `state.json`은 전체 파일 교체 방식이며 DB나 task
  queue는 없다. 이번 수술에서도 이 정본 모델을 유지한다.
- **[측정, A]** 현재 workspace의 7개 state를 변경하지 않고 dry-run한
  v2 migration 기준값은 Receipt 1,053, semantic Fact 9, probe 13,
  strategic 22, legacy experiment 1,061, legacy-unknown candidate 169,
  typed target 22, unproved override 4, terminal active goal 0,
  legacy spent 합계 17,330초, 복구할 model run 3이다. 이 값은 migration
  golden contract이며 managed 성과 지표가 아니다.

원 계수와 문제별 표는
[13-field-record-analysis.md](13-field-record-analysis.md)에 있다. 이 문서는
그 수치를 다시 계산하거나 정정하지 않는다.

## 동결한 해석과 가설

- **[해석]** 기존 실전 성과는 assisted/operator 경로의 성과이며 managed
  orchestration의 효과를 입증하지 않는다.
- **[해석]** provider 동시성 부족은 호출 시작을 늦출 수 있지만 논리 역할
  수를 줄일 근거가 아니다.
- **[가설]** pending evaluation을 다음 context의 첫 evidence로 올리면
  평가 누락이 줄어든다.
- **[가설]** 세 역할 결과를 all-or-nothing으로 reduce하면 stale 또는
  contract-invalid 산출물의 의미 반영을 막을 수 있다.
- **[가설]** challenge/contest exact format이 있을 때 generic 후보 탐지를
  끄면 실제 flag recall을 유지하면서 context 잡음을 줄인다.
- **[가설]** managed evaluation hard barrier가 제품 지표를 개선한다.
  이 주장은 X-22 전에는 production 기본 정책이 될 수 없다.

## 사전 등록한 실험과 중단 조건

| 실험 | 비교 | 주 지표 | 즉시 중단 조건 |
| --- | --- | --- | --- |
| X-24 | format replay 전/후 | 실제 flag recall, noisy candidate | 실제 flag miss 1건 |
| X-23 | Captain-only / 3-role wave | 유효 산출물, 사고·대기 시간 | schema validity 80% 미만 |
| X-25 | 환경 briefing on/off | 사람 개입 횟수 | 개입이 줄지 않음 |
| X-22 | observe / evaluation treatment | 첫 유효 후보 시간, run 수 | 중앙값 차이 20% 미만이면 일반 barrier 비활성 |

X-22는 난이도 matched held-out 8문제를 4/4로 나누고 같은 이미지·모델·8시간
budget을 써야 한다. `managed-observe`, `managed-X22-treatment`,
`assisted`, `operator/manual`, `legacy`, `bounded`, `unbounded` cohort는
합산하지 않는다.

## 표본 한계

- 실전 관측은 대회 2개, 분석 대상 5문제뿐이며 카테고리와 난이도가
  교란되어 있다.
- 동일 문제의 무작위 반복 배정이 아니므로 평가율과 풀이 시간의 상관을
  인과로 해석할 수 없다.
- rollout 로그와 정본의 관측 범위가 다르다.
- 실제 모델 canary는 자동 테스트가 아니며, 사람이 고른 challenge에서만
  실행할 수 있다.
- 이미지 소스의 기존 gitlink commit은 확인했지만 nested repository에
  remote가 없어 원격 출처는 검증하지 못했다. 이 사실은
  `ctf-os-image/SOURCE.json`에 그대로 기록한다.
