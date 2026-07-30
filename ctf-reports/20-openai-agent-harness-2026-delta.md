# 20. OpenAI 2026 agent harness 운용 delta

**검토일:** 2026-07-31

**범위:** 2026-07-28~29 공개된 OpenAI 공식 글 3건을 현재 CTF-OS의
모델 연속성, context archivist, prompt caching, 검증 구조에 대입한다.

**판정:** 세 글은 CTF-OS의 실행 기반 gate와 bounded context 방향을
강하게 지지한다. 새로 검증해야 할 가장 큰 차이는 **managed cycle마다
새 thread를 만드는 현재 조건과, 동일 역할의 reasoning을 유지하며
provider compaction을 쓰는 조건의 A/B**다. ARC-AGI-3의 3배 수치를 CTF에
그대로 전이하지 않으며, 측정 전 production 기본값도 바꾸지 않는다.

## 공식 글에서 확인한 것

### 외부 oracle과 단계별 피드백

[Scientific computing in the age of agentic AI](https://openai.com/index/scientific-computing-agentic-ai/)
는 8개 agent-assisted scientific software 사례를 정리한다. 사례의 공통
병목은 구현 속도보다 결과 검증이었다. 강한 방식은 exact output agreement,
기존 도구와의 parity, 통계적 거동, 답을 미리 아는 simulated data 같은
외부 acceptance target을 사용했고, 큰 변경을 여러 단계와 중간 benchmark로
나눠 feedback-driven iteration을 수행했다.

CTF-OS에 대한 함의는 역할이나 도구 수를 더 늘리는 것이 아니다.
deterministic partial oracle, original challenge verification, independent
validator, clean replay가 모델의 자신감보다 우선해야 한다. 이는 현재
구현 순서를 바꾸지 않고 오히려 2~4번 우선순위를 강화한다.

### 반복 구간의 context 비용

[How GPT-5.6 fuses frontier intelligence with frontier efficiency](https://openai.com/index/gpt-5-6-frontier-intelligence-efficiency/)
는 agent loop에서 context 준비, 전송, tool 시작 같은 작은 비용이 반복
호출 수만큼 증폭된다고 설명한다. 공개된 harness 원칙은 다음과 같다.

- 필요할 때만 tool, skill, plugin을 surface하는 deferred discovery
- 예기치 않은 context 팽창을 막는 tool output bound
- model-visible history를 append-only로 유지
- tool을 deterministic order로 제시
- 변하지 않는 prefix를 보존해 prompt cache 재사용

CTF-OS는 raw output을 bounded artifact로 외부화하고 context pack과 resume
capsule을 제한한다는 점에서 방향이 맞다. 반면 같은 60,000-character
context pack을 독립 worker마다 다시 전달하는 비용과, role별 prefix가
갈라진 뒤 같은 evidence를 넣는 구조는 실측 대상이다. worker context를
즉시 줄이지는 않는다. worker에게 빠진 evidence를 다시 발견할 도구가 없는
현재 구조에서 무측정 축소는 solve 성능을 해칠 수 있기 때문이다.

### retained reasoning과 compaction

[How enabling two settings tripled our scores on the ARC-AGI-3 benchmark](https://openai.com/index/how-two-settings-tripled-our-arc-agi-3-scores/)
는 공개 ARC-AGI-3 task set에서 generic harness의 13.3%가 retained
reasoning과 compaction을 사용한 Responses API harness에서 38.3%로
올랐고 output token은 약 6분의 1로 줄었다고 보고한다. 원인은 매 action
후 reasoning을 버리고 오래된 action을 rolling truncation하던 harness가
모델을 매번 처음부터 다시 추론하게 만든 데 있었다.

이 수치는 ARC-AGI-3, GPT-5.6 Sol, 해당 public set과 harness에 묶인
ablation이다. CTF solve 개선률로 인용하지 않는다. 그러나 같은 문제 안에서
장시간 실패 상태를 인계해야 하는 CTF-OS에는 직접 검증할 가치가 높은
harness 가설이다.

## 현재 코드와의 차이

2026-07-31 로컬 설치는 `codex-cli 0.145.0`이다. `codex features list`는
`remote_compaction_v2`를 stable/true로 표시한다.

현재 Batch runner는 JSON contract가 실패한 동일 호출의 schema retry에서만
`codex exec resume <thread_id>`를 사용한다. Captain과
Recon/Specialist/Extractor의 다음 managed cycle은 새 thread로 시작한다.
run에는 `thread_id`, context hash/path, token usage가 남지만 장기 role
continuation에는 사용하지 않는다.

최근 `zone` 한 cycle에서도 이 비용 구조가 보였다.

| 역할 | input tokens | cached input tokens | output tokens |
| --- | ---: | ---: | ---: |
| Captain | 21,001 | 0 | 11,581 |
| Recon | 68,161 | 43,520 | 20,234 |
| Specialist | 69,710 | 44,544 | 18,478 |
| Extractor | 67,302 | 42,496 | 22,978 |

이 한 표본은 prompt cache가 일부 작동한다는 관측일 뿐, thread continuation의
효과를 증명하지 않는다. solve나 semantic evaluation 전에 끝난 cycle이므로
token 수와 solve 품질의 관계도 아직 판단할 수 없다.

## 추가할 A/B

### X-26 · role reasoning continuity

| 항목 | 내용 |
| --- | --- |
| 조건 A | 현재와 같이 cycle마다 모든 managed role을 새 thread로 실행 |
| 조건 B | Captain만 같은 challenge session과 role의 직전 thread를 resume |
| 조건 C | Captain과 각 worker lane이 각각 자기 role의 직전 thread를 resume |
| 항상 새 thread | Independent Validator/Falsifier |
| 고정 조건 | 같은 GPT-5.6 Sol, reasoning effort, logical role 수 4, wave 폭 3, tool/image, 총 wall/token budget |
| 집합 | regression과 blind/live-like를 분리하고 동일 문제의 2/3 반복 |
| 주 지표 | solve@1, pass²/₃, median time-to-first-valid-result, proof 통과율 |
| 부 지표 | output/reasoning/cached-input token, provider wait, contract invalid, 사람 개입, stale-hypothesis 반복 |
| 채택 | blind/live-like 주 지표가 개선되고 proof/validator 독립성이 유지될 때만 |

thread lineage는 다음 값이 모두 같을 때만 resume할 수 있다.

- contest/category/challenge identity
- managed session
- logical role
- model ID와 reasoning effort
- source manifest SHA-256
- configuration epoch
- selected target ID와 generation

하나라도 달라지면 새 thread를 시작한다. role 간 thread 공유, 다른 challenge
thread 재사용, Validator continuation은 금지한다.

## 구현 경계

1. canonical `state.json`과 실행 artifact가 계속 증거의 정본이다.
   retained reasoning은 탐색 연속성일 뿐 fact, gate, proof 권한이 없다.
2. provider compaction은 Context Archivist를 대체하지 않는다. thread가
   유실되거나 provider가 바뀌어도 bounded state capsule로 재개돼야 한다.
3. run metadata에 continuation mode, parent thread/run, static prompt-prefix
   hash를 남겨 fresh/continued 조건을 사후 구분할 수 있어야 한다.
4. model-visible static role contract와 tool definition의 순서를 고정하고,
   동적 state/context는 뒤에 append한다. 과거 prompt를 중간 삽입으로
   재작성하지 않는다.
5. context 축소나 role-specific filtering은 missing-evidence 회귀를 먼저
   측정한 뒤 적용한다.
6. 현재 진행 중인 false-stall과 Pwn disclosure 영속화를 먼저 완료한다.
   X-26은 그 뒤 provider continuity 실험으로 구현한다.

## 최종 해석

세 공식 글이 추가한 핵심은 “더 짧은 prompt”가 아니다. 같은 강한 모델도
reasoning을 버리고 오래된 관측을 잘라내면 harness 때문에 성능이 크게
낮아질 수 있고, 반대로 history를 무한히 누적하면 비용과 주의 분산이
커진다는 점이다.

CTF-OS의 목표 조건은 따라서 다음과 같다.

> 동일 challenge와 동일 role의 reasoning 연속성은 보존하되, 증거는
> bounded canonical state로 외부화하고, provider compaction과 engine
> capsule을 함께 사용하며, 성공은 언제나 독립 실행 oracle이 판정한다.

