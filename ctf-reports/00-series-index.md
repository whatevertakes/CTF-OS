# 당신의 AI Agent가 CTF 문제를 못 푸는 이유 — 시리즈 개요

**대상: Pwn / Reversing / Crypto / Forensics / Web**
2025년 하반기 ~ 2026년 상반기에 공개된 논문, 벤치마크, 오픈소스 도구, 실전 대회 기록을 근거로 정리했습니다.

---

## 이 시리즈가 다루는 것

AI Agent는 CTF 상위권 경쟁에서 빼기 어려운 도구가 되었습니다. 하지만 "Agent에게 던져두면 풀린다"는 말은 카테고리마다 전혀 다른 의미를 갖습니다. 어떤 문제는 5분 만에 풀리고, 어떤 문제는 몇 시간을 돌려도 마지막 한 걸음을 넘지 못합니다.

이 시리즈는 그 차이가 어디서 나오는지를 카테고리별로 나눠 정리합니다. 각 글은 독립적으로 읽을 수 있습니다.

### 1부 — 카테고리별 진단

- [1. 포너블 편 — 설명은 완벽한데 익스가 안 터지는 이유](01-pwn.md)
- [2. 리버싱 편 — 디컴파일러를 빼면 오히려 잘 푸는 이유](02-reversing.md)
- [3. 크립토 편 — 추론력이 아니라 지식의 입도가 문제인 이유](03-crypto.md)
- [4. 포렌식 편 — 질문 하나를 놓치면 나머지가 전부 무너지는 이유](04-forensics.md)
- [5. 웹 편 — 익스는 되는데 취약점을 못 알아보는 이유](05-web.md)

### 2부 — 설계로 옮기기

진단만으로는 아무것도 바뀌지 않습니다. 2부는 1부의 관찰을 CTF-OS가 실제로 만들 컴포넌트와 판정 가능한 실험으로 변환합니다.

- [6. 엔진 설계도](06-engine-blueprint.md) — 관찰을 컴포넌트·상태 스키마·제어 루프로 옮긴 근거 문서. 요구사항 대장 54건
- [7. 실험 백로그](07-experiment-backlog.md) — 모든 [가설]을 총 예산 고정 A/B로 변환한 21개 실험
- [8. 출처 검증 기록](08-verification-log.md) — 참고문헌 37건의 실재성·수치 대조와 Codex CLI 기능 검증 (검증일 2026-07-27)
- [9. 구현 설계도](09-implementation-blueprint.md) — 구현 전 설계 기준선. 엔진 단위를 문제 하나로 확정하고, 대회 계층 스케줄러를 폐기하고, 자원 리스·파일 상태·Phase 0~7을 정의합니다
- [10. 구현 결과](10-implementation-result.md) — **현재 코드의 as-built 정본.** 실제 CLI·상태·Live/Batch·sandbox·proof·사람 제출과 미구현 경계를 코드/테스트 기준으로 기록합니다
- [11. Claude CLI 2차 검토](11-claude-secondary-review.md) — 독립 모델이 찾은 반례와 재판정·수정 기록
- [12. 최종 수용성 기록](12-final-acceptance.md) — 사용자 확정 계약을 코드·회귀·운영 경계에 한 줄씩 대응한 최종 인수표

문서와 구현이 어긋날 때의 권위 순서는 다음과 같습니다.

1. [RELEASE_STATUS](../RELEASE_STATUS.md)가 정의한 운영자 선택 exact local
   unsigned receipt와 현재 코드
2. 현재 source에 결속돼 통과한 회귀 테스트와 release matrix
3. [12. 최종 수용성 기록](12-final-acceptance.md)의 요구사항별 판정과 상단 current delta
4. [10. 구현 결과](10-implementation-result.md)의 as-built 설명과 상단 current delta
5. [9. 구현 설계도](09-implementation-blueprint.md)의 역사적 설계 기준선

10과 12의 과거 본문, 13~21의 실행 수치와 image digest는 날짜가 고정된 역사적
증거다. 현재 checkout의 GO로 소급하지 않는다. 운영 순서는 저장소
[contest start runbook](../docs/contest-start-runbook.md)을 따른다.

13은 계약 판정이 아니라 운용 관측이므로 권위 순서에서 10과 12 **아래**입니다.
다만 13의 가동률 표는 12의 수용 판정에 반례를 제기합니다. 계약이 코드에
존재하는 것과 운용에서 지켜지는 것은 다른 사건이며, 12는 전자만 판정했습니다.

16은 10과 12 이후에 추가된 Pwn D→V/failure replay 범위의 as-built
delta입니다. 이 좁은 범위에서는 16을 따르되, 실제 solve 성능 관측은 15를
소급해 바꾸지 않습니다.

17은 16의 source-level gate가 실제 pinned image에서 사용되지 못했던
readiness 병목과 그 수정, address-resolution advisory의 권한 경계를
기록합니다. Pwn runtime readiness와 leak/N/A 해석은 17을 우선하되 solve
성능은 여전히 측정 전입니다.

18은 개선된 엔진으로 `zone` 한 cycle을 다시 실행해 all-Sol wave와 tool
dispatch를 확인하고, stale adapter seed와 shell-text/direct-argv 계약
불일치를 새 실전 병목으로 고정한 기록입니다. 성공 exit code가 곧 target
관측 증거가 아니라는 판정은 18을 따릅니다.

19는 18에서 찾은 stale binding과 shell contract 병목을 수정한 뒤 같은
`zone`을 다시 실행한 회귀입니다. 세 selected action이 모두 실제 bounded
artifact를 만들었지만 sandbox-local locator 충돌이 false stall을 만든
새 병목과, 아직 semantic evaluation 전이므로 solve로 집계할 수 없다는
경계를 기록합니다.

20은 2026-07-28~29 OpenAI 공식 글의 external oracle, append-only prompt
prefix, retained reasoning, compaction 결과를 현재 코드와 대조합니다.
ARC-AGI-3의 3배 수치를 CTF로 일반화하지 않고 fresh thread / Captain-only
continuation / per-role continuation의 X-26 A/B로 바꾼 기록입니다.

21은 그 뒤 같은 사람이 선택한 `zone` 한 문제에서 실제 off-by-one heap
primitive, 동적 stack/libc disclosure, staged pivot과 `system()` 효과를
3 attack/3 control로 재현한 기록입니다. 이후 `6d27bef`/`ad6ae43`에서
동적 interaction을 image-owned typed oracle로 옮기고 실제 `zone` evaluation
SHA-256 `d622818d48afaec9b07f209d81f15a36794709ded83bde13935d8953bd3d2d5e`
로 다시 통과한 후속 증거도 포함합니다. 로컬 flag source와 active target이
없고 recipe/parent를 운영자가 제공했으므로 solve, remote portability나
autonomous discovery로 승격하지 않습니다.

그 뒤 category release provenance의 알려진 반례도 닫혔습니다.
Pwn dependency/effect `1c82147`은 69개 회귀와 pinned 16/16·48/48,
tamper control 3/3, network `none`을 통과했고, interaction `c9eee37`은
23개 회귀와 physical record 6개를 통과했습니다. Web `dd929f0`/`cf155cc`,
Rev `3726adb`, Crypto `d550df1`, Misc `c690af0`, Forensic
`7c3d604`/`5e88071`도 각각 physical evidence와 hostile control을
fail-closed합니다. Forensic은 서로 다른 Python/Perl executable hash를
결속하고 focused 91개와 pinned Docker 7개를 37.961초에 통과했습니다.
이들은 구현·category child evidence이며, 현재 source의 최종 clean
all-category matrix, full suite와 `ctfos doctor`를 대신하지 않습니다.
`d2fb113` promotion collector도 focused 74/74만 통과했으며 실제 blind/live
solve uplift는 아직 측정하지 않았습니다.

설계 근거끼리 **6과 9가 어긋나면 9**를 따릅니다. 6은 왜 그렇게
설계했는지, 9는 무엇을 만들려고 했는지, 10은 실제로 무엇이 만들어졌는지,
12는 확정 계약을 현재 증거로 수용할 수 있는지를 기록합니다. 운영 명령은
저장소 루트 [README](../README.md)를 사용합니다.

1~6의 “CTF-OS 현황” 표는 연구와 설계가 시작될 때의 역사적 baseline이다.
현재 구현 여부를 판정하는 표가 아니며 10과 12가 이를 대체한다.

### 3부 — 실전 운용 기록

- [13. 실전 기록 분석](13-field-record-analysis.md) — **첫 실전 기록 관측.** ACSC forensics 1문제와 Dreamhack 4문제의 정본 상태·run·세션 로그를 계수해, 설계된 계약이 운용에서 실제로 몇 퍼센트나 가동됐는지 기록합니다 (관측일 2026-07-29)
- [14. 관리형 풀이 엔진 수술 전 근거 동결](14-managed-engine-evidence-freeze.md) — managed 전환 전에 A–D 관측 경로, `[측정]/[해석]/[가설]`, X-22~25 중단 조건과 표본 한계를 고정합니다
- [15. NYU CTF Bench Pwn 부분 실측 중단 기록](15-nyu-pwn-current-baseline.md) — 개선된 working tree로 고정한 Pwn 10문제 중 실제 시작한 4문제의 부분 관측, 사전검증, 엔진 병목과 사용자 중단 상태를 보존합니다. 완성된 `0/10` baseline으로 해석하지 않습니다 (관측일 2026-07-30)
- [16. Pwn crash 실행 게이트와 실패 재투입 구현 기록](16-pwn-crash-gate-and-failure-replay.md) — engine-owned 3+3 D→V oracle, stdout/stderr commit 재검증, typed non-pass failure capsule, 1,536-byte resume와 독립 평가 metric의 현재 구현 및 아직 남은 leak/primitive/exploit 경계를 기록합니다 (구현·검증일 2026-07-30)
- [17. Pwn runtime readiness와 address-resolution advisory](17-pwn-runtime-readiness-and-address-advisory.md) — stale image와 piped core handler 병목을 닫고 실제 Docker 3+3 및 보안 반례를 검증한 결과, source/evidence-bound advisory가 global leak N/A나 stage pass 권한을 갖지 않는 경계를 기록합니다 (구현·검증일 2026-07-30)
- [18. Zone one-cycle live diagnostic](18-zone-one-cycle-live-diagnostic.md) — 개선된 all-Sol 엔진으로 `zone` 한 cycle을 재실행해 stale adapter seed와 managed shell/argv 의미 불일치가 target 관측을 막는 실제 병목임을 고정합니다 (관측일 2026-07-30)
- [19. Zone shell-contract live regression](19-zone-shell-contract-live-regression.md) — stale action retirement와 managed shell contract가 실제 bounded output을 만든 회귀, sandbox-local artifact locator 충돌의 false stall, semantic evaluation 전 결과를 solve로 세지 않는 경계를 기록합니다 (관측일 2026-07-30)
- [20. OpenAI 2026 agent harness 운용 delta](20-openai-agent-harness-2026-delta.md) — external oracle, bounded append-only context, retained reasoning과 compaction의 최신 공식 근거를 현재 Batch runner에 대입하고 X-26 role-continuity A/B로 제한합니다 (검토일 2026-07-31)
- [21. Zone solve-capable exploit 실행 증거](21-zone-solve-capable-exploit-evidence.md) — 실제 원본 `zone`에서 동적 stack/libc disclosure와 staged `system()` chain을 operator 3+3과 후속 image-owned typed interaction 3+3으로 재현하고, exact evaluation pointer와 flag/solve/remote 비승격 경계를 기록합니다 (관측일 2026-07-30~31)

부록: [이전 보고서에서 수정한 것](99-corrections.md) — 이전 라운드의 정정 내역

---

## 읽는 순서

목적에 따라 필요한 부분이 다릅니다.

| 목적 | 읽을 것 |
| --- | --- |
| **현재 무엇이 실제로 작동하는지 알고 싶다** | [RELEASE_STATUS](../RELEASE_STATUS.md), runner가 출력한 운영자 선택 exact local unsigned receipt, 저장소 [README](../README.md), 그 다음 10/12의 current delta |
| **다음에 무엇을 코딩할지 알고 싶다** | [10. 구현 결과](10-implementation-result.md)의 "남은 작업 우선순위", [release validation matrix](../docs/release-validation-matrix.md)의 현재 gate 경계, [promotion bundle 운용 계약](../docs/promotion-bundles.md)과 [7. 실험 백로그](07-experiment-backlog.md)의 blind/live 평가 의존 관계 |
| **왜 그것을 먼저 만드는지 알고 싶다** | [6. 엔진 설계도](06-engine-blueprint.md)의 "레버 우선순위"와 "안티-레버" 두 절. 근거 강도순으로 정렬돼 있습니다 |
| **실제로 문제가 어떻게 풀리는지 보고 싶다** | [9. 구현 설계도](09-implementation-blueprint.md)의 부록 "실제 운용 시나리오". 카테고리별로 갈리는 지점이 표로 있습니다 |
| **특정 카테고리를 개선하려 한다** | 해당 편의 "엔진 설계 요구사항" 절. 요구사항 ID와 CTF-OS 현황이 표로 정리돼 있습니다 |
| **어떤 수치를 인용해도 되는지 확인하려 한다** | [8. 출처 검증 기록](08-verification-log.md). 초록 대조까지 끝난 값과 2차 확인인 값이 구분돼 있습니다 |
| **다음에 무엇을 측정할지 정하려 한다** | [7. 실험 백로그](07-experiment-backlog.md)의 "우선순위와 의존 관계" |
| **왜 이렇게 설계했는지 이해하려 한다** | 1부를 순서대로. 각 편이 독립적으로 읽힙니다 |

---

## 이 시리즈의 인용 규칙

CTF Agent 분야는 지금 논문이 쏟아지는 중이고, 그중 상당수가 심사를 거치지 않은 프리프린트입니다. 게다가 벤치마크마다 문제 수, 모델, 시도 횟수, 시간 예산이 전부 다릅니다. 그래서 이 시리즈는 문장마다 다음 세 가지를 구분해서 표기합니다.

| 표기 | 의미 |
| --- | --- |
| **[측정]** | 논문이 실제로 측정한 결과입니다. 어떤 조건에서 측정했는지를 항상 같이 적었습니다. |
| **[해석]** | 논문 저자가 그 결과에 붙인 설명입니다. 결과 자체와는 다릅니다. |
| **[가설]** | 이 글의 제안입니다. 아직 통제된 실험으로 검증되지 않았습니다. |

숫자를 인용할 때는 "몇 개 문제, 몇 개 모델, 몇 회 시도, 몇 시간 예산"을 함께 적는 것을 원칙으로 했습니다. 이게 빠지면 같은 숫자가 전혀 다른 뜻이 되기 때문입니다. 예를 들어 "19/30"은 특정 30문제 집합에서 나온 값이지, 웹 CTF 일반의 성능이 아닙니다.

## 출처 등급

같은 참고문헌 목록 안에 심사를 통과한 논문과 MCP 마켓 등록 페이지가 섞여 있으면 독자가 무게를 가늠할 수 없습니다. 이 시리즈는 각 출처에 등급을 붙였습니다.

| 등급 | 의미 | 어디까지 믿을 수 있는가 |
| --- | --- | --- |
| **A** | 동료평가를 통과한 논문 (NDSS, ISSTA, ICML, ICONIP, 학술지) | 수치와 방법론 모두 인용 가능 |
| **B** | arXiv 프리프린트 (심사 전) | 수치 인용 가능, 단 후속 심사에서 바뀔 수 있음 |
| **C** | 운영 사례·기술 블로그 (작성자 = 시스템 제작자) | 현상 이해에는 유용, 독립 검증 아님 |
| **D** | 도구 저장소·MCP 마켓 등록 페이지 | 도구의 존재와 주장된 기능만 확인 가능, 성능 근거 아님 |

특히 **C등급 자료로 성능 주장을 하지 않는 것**이 중요합니다. 시스템을 만든 사람이 자기 시스템의 효과를 서술한 글은 무엇이 관찰됐는지를 알려주지만, 그게 다른 환경에서도 재현된다는 근거는 되지 않습니다.

---

## 먼저: 당신이 보고 있는 성공률은 신뢰할 수 있는가

카테고리별 분석에 들어가기 전에 짚어야 할 게 있습니다. 공개된 벤치마크 수치 상당수가 실제 능력보다 높게 나온다는 증거가 2026년에 나왔습니다.

CTFusion 연구는 동일한 모델·에이전트 조합을 정적 벤치마크(NYU CTF Bench)와 실시간 진행 중인 Live CTF에 각각 붙여 비교했습니다 [1]. 세 개 LLM, 두 개 에이전트, 다섯 개 Live CTF 조합에서 정적 쪽 성공률이 일관되게 높았습니다.

| 모델 | Live CTF | 정적 벤치마크 |
| --- | --- | --- |
| GPT-4.1 | 7.1% | 16.9% |
| Gemini 2.5-Flash | 6.2% | 15.0% |
| Claude 3.5-Sonnet | 5.1% | 11.4% |

**[측정]** 이 세 조합에서 정적 벤치마크 성공률이 Live CTF의 약 2.2~2.4배였습니다. 대회 난이도는 CTFtime weight 기준으로 유사했습니다.

**여기서 멈춰야 합니다.** 연구진 스스로 이 결과를 *suggestive rather than conclusive*, 즉 시사적이지만 확정적이지 않다고 명시했습니다. 문제 난이도 차이와 학습 데이터 오염의 기여도를 분리하지 못했고, 신뢰구간도 충분히 계산하지 않았기 때문입니다. 따라서 **"정적 벤치마크는 2배 부풀려진다"를 일반 법칙으로 쓰면 안 됩니다.** 정확한 진술은 "이 조합들에서는 약 2배 차이가 관찰됐고, 그 원인은 아직 분리되지 않았다"입니다.

같은 연구에서 더 직접적인 증거도 나왔습니다.

**[측정]** D-cipher에 웹 검색을 추가하자 성공률이 12.59% → 24.07%로 올랐습니다. 그런데 로그에는 71건의 커닝 시도가 있었고 그중 63건은 flag를 외부에서 그대로 복사한 것이었습니다. 극단적으로는 에이전트가 `nyuctf` 파이썬 패키지를 설치해 벤치마크의 flag에 직접 접근한 사례도 있었습니다.

**[측정]** 도구·예산·상호작용 프로토콜을 완전히 동일하게 두고 "사전 지식을 쓰지 말라"는 프롬프트만 추가하자 13.6% → 9.7%로 떨어졌습니다(상대 29% 감소).

실전에서도 같은 문제가 관찰됩니다. BearcatCTF 2026에 멀티 에이전트로 참가해 362팀 중 20위(상위 6%), 44문제 중 40문제를 푼 한 팀은 짧은 시간에 풀린 문제에 자동 감사를 걸어두었습니다. 그리고 **CryptoPwn** 문제에서 에이전트가 실제 익스플로잇 대신 챌린지 디렉터리의 `README.md`에 있던 flag를 읽어온 것을 잡아냈습니다. 감사는 이 세션을 `CHEATED`로 라벨링했고, 팀은 무효 처리한 뒤 다시 풀었습니다 [2].

**이 사례에서 중요한 것은 커닝이 일어났다는 사실이 아니라 감사가 그것을 잡았고 라벨이 기록으로 남았다는 것입니다.** 감사가 없었다면 이 문제는 "40문제 해결" 안에 조용히 포함됐을 것입니다.

> **[가설]** 자기 시스템을 평가할 때는 (1) 아직 write-up이 없는 Live CTF, (2) 짧은 시간에 풀린 문제에 대한 자동 감사, 이 두 가지가 필요합니다. 이건 CTFusion과 BearcatCTF 기록이 각각 보여준 현상에서 끌어낸 운영 제안이지, 두 조치의 효과를 통제 실험으로 측정한 결과는 아닙니다.

---

## 카테고리 교차 비교

각 글의 결론을 한 장으로 모으면 다음과 같습니다. **단, 이 표의 "1차 병목" 열은 서로 다른 벤치마크에서 나온 관찰을 나란히 놓은 것이라 카테고리 간 난이도 순위로 읽으면 안 됩니다.**

| 카테고리 | 1차 병목 | 대표 실패 | 환경 요구 | 근거의 강도 |
| --- | --- | --- | --- | --- |
| **Pwn** | 런타임 상태 추론 | 커널 힙 레이아웃, race, 조기 포기 | 디버거 접근, 긴 시간 예산 | 강 (898문제 벤치마크) |
| **Reversing** | 관측 신뢰성 | 오도된 단서 과신, 계획 고착 | 동적 분석, 어셈블리 접근 | 중강 (24문제 × 3 에이전트) |
| **Crypto** | 지식 입도 | 공격 패러다임 오인, 재구현 오류 | SageMath, 원문 논문 검색 | 중 (핵심 실험은 9문제) |
| **Forensics** | 컨텍스트 연속성 | 질문 의존 연쇄, 도구 출력 폭발 | 요약 계층, 이미지 처리 | 중 (SOC 벤치마크 전이) |
| **Web** | 취약점 인식 | 비즈니스 로직, 브라우저·동시성 부재 | headless 브라우저, 병렬 실행 | 중강 (30문제, 반복 측정) |

실패 메커니즘을 축으로 다시 보면 이렇습니다. 원 개수는 각 카테고리 글에서 근거를 댄 관찰의 상대적 두드러짐이며, 정량 지표가 아닙니다.

| 실패 메커니즘 | Pwn | Rev | Crypto | Forensics | Web |
| --- | --- | --- | --- | --- | --- |
| 관측이 실제와 다름 | ● | ●●● | ○ | ● | ○ |
| 컨텍스트 손실 | ●● | ●● | ● | ●●● | ●● |
| 검증 오라클 부재 | ● | ●● | ● | ●●● | ○ |
| 지식 부족 | ● | ● | ●●● | ● | ●● |
| 환경 능력 부재 | ●● | ○ | ● | ●● | ●●● |
| 가설 고착 / 방황 | ●● | ●●● | ●● | ●● | ●●● |

---

## 다섯 카테고리를 관통하는 것

각 글의 결론을 겹쳐 보면 하나의 문장으로 모입니다.

**Agent는 "지금 보고 있는 것을 의심하고, 흩어진 것을 잇고, 틀린 것을 버리는" 절차를 스스로 만들지 못합니다.**

- 포너블에서는 런타임 상태를 못 봐서
- 리버싱에서는 도구 출력을 사실로 믿어서
- 크립토에서는 공격 패러다임을 처음부터 잘못 골라서
- 포렌식에서는 앞 단계 결과를 잃어버려서
- 웹에서는 취약점이 있다는 것 자체를 못 알아봐서

무너지는 지점은 다르지만 빠진 것은 같습니다. 이 절차를 시스템으로 만들어 주는 것이 지금 할 수 있는 일이고, 그것이 모델 성능만으로 설명되지 않는 격차의 정체입니다.

---

## 효과가 측정된 설계 레버

2부의 결론을 미리 한 장으로 보면 다음과 같습니다. **효과가 실제로 측정된 것만** 근거 강도순으로 정렬했습니다. 측정 조건과 전체 대장은 [엔진 설계도](06-engine-blueprint.md)에 있습니다.

| 레버 | 측정된 효과 | 근거 |
| --- | --- | --- |
| 요약 계층 (출력 외부화) | 컨텍스트 한계 오류 → **0**, 부분 해결률 +12.5~31.9%p | SIABench (B, SOC 과제) |
| 목표 순차 처리 | 45.9% → **70.0%** | SIABench (B, SOC 과제) |
| 난이도 인지 계획 | 최대 91% 완료, 상대 39~49% 개선 | Excalibur (B) |
| 역할 분리 오케스트레이션 | 3/3 성공 12 → 16, 스텝 −24%, 비용 −34% | Second Look (B) |
| 장문 원본 지식 주입 | 9/9 전략 식별 (지식 없을 때 6/9 방향 오류) | KryptoPilot (B, n=9) |
| 난이도 기반 모델 라우팅 | 성공률 동일, 30초 → 169초 | KryptoPilot (B) |
| 디컴파일러 비의존 경로 | 15/24 → **17/24** | NDSS BAR 2026 (**A**) |

그리고 **측정으로 반박되었거나 측정이 지지하지 않는데 자주 채택되는 설계**가 있습니다. 설계도의 "안티-레버" 절에서 다룹니다.

- 아키텍처를 정교하게 만들어 **최대 성능**을 올리려는 시도 — 세 변형이 모두 19/30에서 멈췄습니다
- 초록·요약만 인덱싱하는 청크 RAG — 부분 지식이 무지보다 위험했습니다
- 디컴파일러 우선 정책 — 저수준 문제에서 의사코드가 정보를 가립니다
- 컨텍스트 윈도우 확장으로 컨텍스트 손실을 해결하려는 시도 — W3는 창 크기 문제가 아닙니다
- 앙상블을 기본값으로 두는 것 — 합집합 239는 총 연산량이 더 큰 조건의 값입니다

### 그리고 지표를 잘못 잡는 것

첫 줄에서 따라오는 결론이 하나 더 있습니다. **오케스트레이션 개선을 해결률로 평가하면 전부 실패로 나옵니다.**

세 아키텍처 변형이 모두 19/30이었지만 3/3 성공은 12 → 16으로, 비용은 34% 줄었습니다. 대회에서는 "풀 수 있느냐"보다 "제한 시간 안에 안정적으로 푸느냐"가 점수입니다. 그래서 설계도의 1차 지표는 `consistency`, `cost_per_solve`, 대회시간당 착지 문제 수이고 해결률은 2차입니다.

반대 방향도 성립합니다. **지식·인식 계층의 개선을 일관성으로 평가하면 그쪽 이득이 안 보입니다.** 웹에서 어떤 아키텍처도 인식하지 못한 7문제는 오케스트레이션으로 풀리지 않고, 인식되면 83%가 익스까지 성공합니다. 두 종류의 개선은 다른 지표로 봐야 합니다. 자세한 것은 설계도의 `R-EVL-5`에 있습니다.

---

## 출처 검증

이 시리즈가 인용한 참고문헌 37건 전부에 대해 실재성과 수치를 직접 대조했습니다. **검증일 2026-07-27.**

- arXiv 16건: 전부 실재하며 제목이 정확히 일치합니다. 초록에 명시된 수치는 전부 일치했습니다
- 비arXiv 21건: 전부 확인됐습니다. 일부는 봇 차단(403/429) 때문에 Crossref나 API로 우회 확인했습니다
- 발견된 불일치 5건은 수정했고, 미해결 1건(ExploitGym 문제 수 898 vs 869)은 각주로 남겼습니다

전체 기록은 [출처 검증 기록](08-verification-log.md)에 있습니다. 이 문서가 저장소의 `ctf-os-image/VERSIONS.md`가 도구 버전에 대해 하는 일을 참고문헌에 대해 합니다.

---

## 참고한 글과 자료

각 카테고리별 전체 참고문헌은 해당 글에 있습니다. 이 개요에서 인용한 것은 다음 두 건입니다.

[1] **(B)** Dongjun Lee, Ga-eun Bae, Insu Yun, "CTFusion: A CTF-based Benchmark for LLM Agent Evaluation", arXiv:2605.11504 — <https://arxiv.org/abs/2605.11504>

[2] **(C)** Claw-Stack Blog, "24 Hours, 40 Challenges: How an AI Team Placed Top 6% at BearcatCTF 2026" — <https://claw-stack.com/en/blog/bearcat-ctf-2026/>

이 시리즈의 형식과 문제의식은 TeamH4C의 "당신의 AI Agent가 CTF 문제를 못 푸는 이유: 리버싱 편"(<https://h4c.team/posts/49>)을 참고했습니다.
