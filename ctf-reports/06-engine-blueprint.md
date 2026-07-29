# CTF-OS 엔진 설계도 — 다섯 편의 관찰을 구현 결정으로

> 이 문서의 “지금 CTF-OS는 어디까지 왔는가” 절 전체와 그 구현 현황
> 서술·표는 설계 시작 시점의 역사적 baseline이다.
> 현재 as-built 판정은 [10](10-implementation-result.md)과
> [12](12-final-acceptance.md)를 따른다.

이 문서는 시리즈의 결론 부분이 아니라 **번역 계층**입니다. 1~5편은 "Agent가 어디서 무너지는가"를 근거와 함께 정리했습니다. 이 문서는 그 관찰을 CTF-OS가 실제로 만들 컴포넌트, 파일 포맷, 제어 루프, 중단 조건으로 옮깁니다.

번역 과정에서 지켜야 할 규칙이 하나 있습니다. **근거의 강도가 설계 우선순위를 결정하고, 근거가 약한 항목은 기능이 아니라 실험으로 들어갑니다.** 이 규칙을 지키지 않으면 설계도가 "그럴듯한 아이디어 목록"이 되고, 어느 것을 먼저 만들어야 하는지 알 수 없게 됩니다.

엔진은 **한 계층**입니다. 문제 하나의 폐쇄루프가 전부이고, 여러 문제를 다루는 것은 이 엔진을 여러 번 여는 것뿐입니다. "한 문제에서 2시간 헤매는 동안 쉬운 5문제를 놓친다"는 문제는 스케줄러가 아니라 **사람이 세션을 하나 더 여는 것**으로 해결합니다.

> **이 문서의 위치 — 반드시 먼저 읽으세요.**
>
> 이 문서는 **관찰을 설계 결정으로 옮긴 근거 문서**이고, 실제 구현 기준선은 [구현 설계도](09-implementation-blueprint.md)입니다. 두 문서가 어긋나면 **09가 정본**입니다. 09가 이 문서에서 바꾼 것은 다음 일곱 가지이며, 해당 절에 각각 표시해 두었습니다.
>
> | 이 문서의 설계 | 09의 결정 | 위치 |
> | --- | --- | --- |
> | 대회 계층 + 문제 계층의 두 계층 | **한 계층.** 엔진 단위는 문제 하나이고 세션을 여러 번 연다 | 09 §1, §5 |
> | Scheduler가 문제 간 전환과 예산 배분을 결정 | **Scheduler 없음.** Director는 자원 리스 브로커 + 읽기 전용 보드 + 제출 게이트 | 09 §3.2, §5.4, Phase 6 |
> | 컴포넌트 10개 | **런타임 4개**로 합침 | 09 §3.2 |
> | `facts.jsonl` / `hypotheses.jsonl` / `experiments.jsonl` | **문제별 `state.json`** 단일 writer + 원자적 교체. `events.jsonl`은 감사용 | 09 §3.1, §8 |
> | Hook이 Blackboard 규약을 강제 | Hook은 **보조 안전장치**만. 의미론은 스키마·단일 writer·상태 머신이 강제 | 09 §3.3 |
> | `X-20` = 대회 계층 순위 정책 | `X-20` = **다중 세션 간섭** | 09 §17, 07 |
> | proof 뒤 조건부 자동 제출 | **폐기.** 후보는 즉시 출력하되 CTF 사이트 제출은 사람이 하고 결과만 기록 | 09 §13, Phase 7 |
>
> 근거와 요구사항 ID(`R-*`)의 결속은 그대로 유지됩니다. 바뀐 것은 그 요구사항을 **어디에 구현하는가**이지 근거 자체가 아닙니다.

> **인용 규칙**: **[측정]** = 논문이 실제로 측정한 결과(측정 조건 병기), **[해석]** = 논문 저자의 설명, **[가설]** = 이 시리즈의 제안(미검증). 출처 등급은 **A** 동료평가 논문 / **B** arXiv 프리프린트 / **C** 운영 사례·블로그 / **D** 도구 저장소입니다. 출처 검증 절차와 결과는 [출처 검증 기록](08-verification-log.md)에 있습니다.

## 목차

- [지금 CTF-OS는 어디까지 왔는가](#지금-ctf-os는-어디까지-왔는가)
- [설계 원칙 여섯 개](#설계-원칙-여섯-개)
- [무엇을 먼저 만들 것인가: 레버 우선순위](#무엇을-먼저-만들-것인가-레버-우선순위)
- [만들지 말아야 할 것: 안티-레버](#만들지-말아야-할-것-안티-레버)
- [실행 기반: Codex CLI로 무엇이 되는가](#실행-기반-codex-cli로-무엇이-되는가)
- [아키텍처](#아키텍처)
- [문제 상태 기계](#문제-상태-기계)
- [상태 스키마](#상태-스키마)
- [제어 루프](#제어-루프)
- [요구사항 대장](#요구사항-대장)
- [구현 단계](#구현-단계)
- [이 설계도가 틀렸을 수 있는 지점](#이-설계도가-틀렸을-수-있는-지점)

---

## 지금 CTF-OS는 어디까지 왔는가

설계도를 그리기 전에 현재 상태를 정확히 적어둡니다. 저장소를 직접 확인한 결과입니다.

| 계층 | 현재 상태 | 위치 |
| --- | --- | --- |
| **도구 샌드박스** | 상당히 완성. pwn/rev/crypto/forensic/web/stego 도구, SageMath, Playwright+Chromium, pwndbg, Volatility 3, angr, Ghidra 12.1.2, zbar, stegseek | `ctf-os-image/Dockerfile` (527줄, 4스테이지) |
| **에이전트용 실행 규율** | 원칙 수립 및 일부 구현. stdin 무대기, 페이저 금지, 긴 출력 파일화, 백그라운드 잡 | `ctf-os-image/AGENTS.md`, `scripts/ctfwrap`·`ctf-bg`·`ctf-jobs`·`ctf-log` |
| **도구 인덱스** | 빌드 시점 실제 실행으로 생성 | `/tools/manifest.json` (`gen-manifest.sh`) |
| **원본 보존** | `/challenge`(ro) → `/work` 복사 + 원본 해시 기록 | `entrypoint.sh` |
| **버전 검증 규율** | 확립. 릴리스 자산까지 HTTP 200 확인 | `ctf-os-image/VERSIONS.md` |
| **오케스트레이션 (문제 단위)** | **거의 비어 있음.** 폴더 생성과 Codex 세션 시작 두 명령뿐 | `ctf_os/agent_tools.py` (204줄) |
| **오케스트레이션 (대회 단위)** | **없음.** 대회 인테이크, 전역 정찰, 문제 간 전환, 제출 관리가 전부 없음 | — |
| **상태 저장소** | 없음 | — |
| **검증·감사 계층** | 없음 | — |
| **지식 계층** | 없음 | — |
| **예산·라우팅** | 없음 | — |
| **자체 평가 하네스** | 없음 | — |

`ctf_os/agent_tools.py`가 현재 하는 일은 두 가지입니다. `init-contest`는 `incoming/<대회>/<카테고리>/<문제>/` 디렉터리를 만들고, `solve`는 그 디렉터리를 작업 디렉터리로 지정해 `codex -C <dir> <프롬프트>`를 실행합니다. 프롬프트는 `"{대회}의 {카테고리} 카테고리 {문제} 문제다."`에 사용자가 준 설명을 이어붙인 문자열입니다.

즉 **현재 구조는 "문제 폴더 생성 → 단일 Codex 대화 시작"입니다.** 그 사이에 상태, 검증, 재시도, 문제 우선순위가 전부 없습니다.

**이 구조를 읽는 방식이 중요합니다.** 다섯 편이 지적한 실패의 대부분은 도구가 없어서 생기는 것이 아니었습니다. 리버싱 편의 Type A/Type B 구분으로 보면, CTF-OS는 **Type A(도구·프롬프트 부재)를 이미 상당히 해결했고, Type B(계획·상태 관리)는 전혀 손대지 않은 상태**입니다. 웹 편에서 본 XSS 실패(브라우저 부재)나 포렌식 편의 이미지 문제 실패(비전 도구 부재)는 이 이미지에서는 재현되지 않을 가능성이 높습니다. Playwright와 zbar가 이미 들어 있습니다.

따라서 이 설계도의 무게중심은 **호스트 쪽 오케스트레이션 계층**입니다. 이미지에 도구를 더 넣는 것이 아닙니다.

---

## 설계 원칙 여섯 개

다섯 편에서 반복된 관찰을 원칙으로 압축하면 다음과 같습니다. 각 원칙 뒤에 근거가 되는 편을 적었습니다.

### 원칙 1. 관측과 해석을 같은 자리에 적지 않는다

Agent는 도구 출력을 사실로 취급합니다(리버싱 편 W2). 디컴파일러 의사코드는 재구성이지 원본이 아니며, 호출되지도 않는 디코이 함수를 검증 루틴처럼 보이게 만들 수 있습니다(M3). 커널 문제에서 성능이 무너지는 주된 이유도 지적 난이도가 아니라 관측성이었습니다(포너블 편).

그래서 상태 저장소는 **하나의 진술마다 그것이 어떻게 얻어졌는지를 강제로 기록**합니다. 직접 실행해서 본 것, 도구가 재구성한 것, 모델이 서술한 것은 서로 다른 등급입니다. 이 구분이 없으면 세 번째가 첫 번째처럼 유통됩니다.

### 원칙 2. 큰 출력은 컨텍스트에 올리지 않는다

이 시리즈에서 가장 강한 인과 증거입니다. SIABench에서 요약 모듈을 끄면 컨텍스트 한계 오류가 발생하고, 켜면 **0이 됩니다**(포렌식 편). 웹의 blind SQL injection 실패도 같은 메커니즘이었습니다. 페이로드가 누적되며 컨텍스트를 잠식합니다(웹 편).

CTF-OS 이미지의 `ctfwrap`이 이미 "긴 출력은 파일로, stdout에는 요약만"을 구현하고 있습니다. 남은 일은 **호스트 쪽에서도 같은 규율을 적용하는 것**입니다. 도구 원출력은 `runs/`에 남고 컨텍스트에는 요약과 포인터만 올라갑니다.

### 원칙 3. 가설에는 반증 테스트가 딸려 있어야 한다

Agent는 틀린 계획을 못 버립니다(W4). 반대로 맞는 발견을 붙들지도 못합니다(웹 편의 scholar-like enumeration). 겉보기에 반대인 두 현상의 뿌리는 같습니다. **"지금 무엇이 유망한지"를 평가하는 기능이 없기 때문**입니다.

Failing to Falsify는 반례를 찾도록 유도하자 규칙 발견률이 42% → 56%로 올랐다고 보고합니다(숫자 규칙 과제, 11개 LLM). 리버싱 실험이 아니므로 직접 근거는 아니지만, 방향은 명확합니다.

그래서 가설 레코드에는 `falsifier` 필드가 **필수**입니다. "이 가설이 틀렸다면 무엇이 관찰되어야 하는가"를 적지 못하면 그 가설은 등록되지 않습니다.

### 원칙 4. 산출물이 없으면 풀린 것이 아니다

리버싱 벤치마크가 서술 대신 keygen을 요구하고(CrackMeBench), ExploitGym이 flag 획득과 별도로 "지정 취약점을 실제로 썼는가"를 판정하는 이유입니다. Claude Mythos Preview는 flag를 얻은 226건 중 157건(69.5%)만 실제 성공으로 인정됐습니다. **나머지 30%는 옆의 더 쉬운 취약점으로 샌 것입니다**(포너블 편).

BearcatCTF 기록에서는 에이전트가 익스플로잇 대신 챌린지 디렉터리 `README.md`의 flag를 읽은 사례가 자동 감사에 걸렸습니다(CryptoPwn 문제, 감사 라벨 `CHEATED`, 세션 무효 처리 후 재풀이).

**대회에서는 flag만 내면 점수를 받습니다. 하지만 자기 시스템을 개선하려면 경로를 알아야 합니다.**

### 원칙 5. 예산은 측정한 곡선에 따라 배정한다

ExploitGym은 시간-성공 곡선의 **모양이 모델마다 다르다**는 것을 측정했습니다. Claude Opus 4.6은 30분에 약 15문제로 포화되고 이후 거의 진전이 없었고, Claude Mythos Preview는 6시간까지 뚜렷한 포화점이 없었습니다(포너블 편). 조기 포화형 모델에 2시간을 통으로 주는 것은 낭비일 가능성이 높습니다.

Excalibur는 Type B 실패의 공통 원인을 **실시간 난이도 추정의 부재**로 지목하고, 네 축(horizon estimation, evidence confidence, context load, historical success)으로 난이도를 추정하는 설계를 제시했습니다.

**단, 이 원칙의 구현은 곡선을 먼저 측정해야 시작할 수 있습니다.** 곡선 없이 예산 정책을 짜면 남의 모델에 맞춘 정책이 됩니다.

### 원칙 6. 이 엔진의 성공 지표는 해결률이 아니다

**이 원칙을 빼면 나머지 다섯 개를 다 구현하고도 실패했다고 결론 내립니다.**

Second Look은 웹 CTF 30문제에서 Executor 단독, +Evaluator, +Planner 세 변형을 비교했습니다. **[측정]** 세 변형의 최대 해결 수가 모두 19/30이었습니다. 아키텍처 정교화가 천장을 올리지 못했습니다.

올린 것은 따로 있습니다. **[측정]** 3회 반복에서 3/3 성공한 문제 수가 12 → 14 → 16개로 늘고, 스텝은 24%, 비용은 34% 줄었습니다.

이 설계도가 제안하는 것 — 두 계층 분리, 상태 저장소, 독립 검증기, 상태 기계 — 은 전부 정교화입니다. 따라서 증거가 예측하는 결과는 이렇습니다.

> **풀 수 있는 문제 수는 거의 오르지 않고, 대회 시간 안에 실제로 착지시키는 문제 수와 문제당 비용이 오른다.**

이건 만들지 말라는 뜻이 아닙니다. **대회에서는 일관성과 처리량이 곧 점수입니다.** 12/30에서 3/3 성공하는 시스템과 16/30에서 3/3 성공하는 시스템은 실전 성적이 완전히 다릅니다. 하지만 지표를 해결률로 잡으면 그 이득이 안 보입니다.

그래서 이 엔진의 1차 지표는 `consistency`(3/3 성공 문제 수), `cost_per_solve`, **대회 시간당 착지 문제 수**입니다. 해결률은 2차 지표입니다.

**그리고 천장을 올리는 레버는 오케스트레이션이 아닙니다.** 웹 편에서 어떤 아키텍처도 인식하지 못한 7문제는 이 구조로도 그대로 남습니다. 천장은 취약점 인식 커버리지와 지식 입도에서 움직입니다 — 인식되면 83%(19/23)가 익스까지 성공하기 때문입니다. **두 종류의 개선을 같은 지표로 평가하면 안 됩니다.** 오케스트레이션 계층은 `consistency`로, 인식·지식 계층은 해결률로 봅니다.

---

## 무엇을 먼저 만들 것인가: 레버 우선순위

설계 논의에서 가장 자주 생기는 사고는 근거 강도가 다른 아이디어를 같은 무게로 나열하는 것입니다. 아래 표는 다섯 편에서 **효과가 실제로 측정된 설계 레버**만 모아 정렬한 것입니다.

| 레버 | 측정된 효과 | 측정 조건 | 등급 | CTF-OS 적용성 |
| --- | --- | --- | --- | --- |
| **요약 계층 (출력 외부화)** | 컨텍스트 한계 오류 5건 → **0건**, 부분 해결률 +12.5~31.9%p | SIABench, SOC 사고 분석, Claude-3.5-Sonnet·GPT-4o | B | **높음** — `ctfwrap`이 절반 구현됨. 호스트 쪽만 남음 |
| **목표 순차 처리 (multi-state)** | 45.9% → **70.0%** | 같은 벤치마크, 메모리 포렌식, Claude-3.5-Sonnet | B | **높음** — 프롬프트·루프 구조만 바꾸면 됨 |
| **난이도 인지 계획 (TDA+EGATS)** | 최대 91% 과제 완료, 베이스라인 대비 상대 39~49% 개선 | Excalibur, 3개 벤치마크, 프론티어 모델 | B | 중 — 4축 추정 구현 필요 |
| **역할 분리 오케스트레이션** | 3/3 성공 12 → 16개, 스텝 −24%, 비용 −34% | Second Look, 웹 CTF 30문제, GPT-5, 문제당 3회 | B | **높음** — 최대 성능은 안 오르지만 일관성·비용이 오름 |
| **장문 원본 지식 주입** | 9문제 전부에서 올바른 전략 식별 (지식 없을 때는 6/9에서 방향 자체가 틀림) | KryptoPilot, 고난도 암호 9문제, 단일 프롬프트 | B | 중 — 표본 9문제. 검색 파이프라인 필요 |
| **난이도 기반 모델 라우팅** | 성공률 동일, 평균 30초 → 169초 (제거 시 5배 이상 느려짐) | KryptoPilot, NYU-CTF crypto 52문제 | B | **높음** — 비용·시간만 개선. 성능 리스크 낮음 |
| **요약·시그니처 계층 (독립 재현)** | 제거 시 F1 최대 −10%p | DFIR-Chain, 메모리 포렌식 | A | 중 — 요약 계층 효과의 두 번째 증거 |
| **디컴파일러 비의존 경로 확보** | 디컴파일러 제거 시 15/24 → **17/24** | NDSS BAR 2026, CTF 리버싱 24문제, 최대 3회 시도 | **A** | 중 — 도구는 이미 있음. 선택 정책이 없음 |
| **반증 유도** | 규칙 발견률 42% → 56% | Failing to Falsify, 숫자 규칙 과제, 11개 LLM | B | 중 — **도메인 밖 결과**. 전이 폭 미검증 |

**읽는 방법.** 위쪽 세 줄은 "구현 비용이 낮고 측정된 효과가 크다"에 해당하므로 먼저 만듭니다. 아래로 갈수록 구현 비용이 크거나 근거의 전이 거리가 멉니다.

**등급 A가 두 줄뿐이라는 점을 봐야 합니다.** 이 설계도는 대부분 B등급 프리프린트에 얹혀 있습니다. 후속 심사에서 수치가 바뀔 수 있으므로, 각 레버는 [실험 백로그](07-experiment-backlog.md)에 자체 재현 실험으로 등록되어 있습니다.

**그리고 이 표에 없는 레버가 하나 있었습니다.** 대회 계층(`R-CON-*`)의 효과를 측정한 연구를 찾지 못했습니다. Second Look의 조기 종료(평균 40스텝)와 ExploitGym의 곡선 차이가 간접 근거이지만, **"문제 간 전환 정책이 총 착지 수를 올리는가"를 직접 측정한 값은 없습니다.**

**09는 이 공백에 기능을 넣지 않기로 했습니다.** 근거가 없는 레버를 만드는 대신 그 자리를 비워 두고, 사람이 세션을 여는 것으로 대체했습니다. 따라서 `X-20`도 "순위 정책이 착지 수를 올리는가"가 아니라 **"세션을 늘렸을 때 각 세션의 풀이 품질이 유지되는가"**(다중 세션 간섭)를 측정하는 실험으로 바뀌었습니다. 09 §21의 표현으로는, 대회 계층에 지능을 넣을수록 문제 계층의 품질과 무관한 복잡도만 늘어납니다.

---

## 만들지 말아야 할 것: 안티-레버

설계도에서 "무엇을 만들지 않을 것인가"는 "무엇을 만들 것인가"보다 자주 빠집니다. 다음은 **측정으로 반박되었거나, 측정이 지지하지 않는데 자주 채택되는 설계**입니다.

| 하지 말 것 | 왜 | 근거 |
| --- | --- | --- |
| **아키텍처를 정교하게 만들어 최대 성능을 올리려는 시도** | 웹 CTF 30문제에서 Executor 단독, +Evaluator, +Planner 세 변형이 모두 19/30에서 멈췄습니다. 차이는 일관성과 비용에서만 났습니다 | Second Look **[측정]** |
| **초록·요약만 인덱싱하는 청크 RAG** | 초록 수준 지식은 추론 궤적을 길게 만들고, 한 문제에서는 **없을 때보다 오히려 틀린 방향으로** 유도했습니다. 부분 지식이 무지보다 위험합니다 | KryptoPilot **[측정]** |
| **디컴파일러 우선 정책** | C++ 예외 기반 스택 머신(task #23)에서 의사코드가 레지스터·스택 상태를 가려 실패했고, 디컴파일러를 빼자 어셈블리 직접 분석으로 성공했습니다 | NDSS BAR 2026 **[측정]** |
| **컨텍스트 윈도우를 늘려 컨텍스트 손실을 해결하려는 시도** | W3는 창 크기 문제가 아니라 **앞선 증거를 재참조하지 못하는** 문제입니다. Clue-Driven RE와 Kong의 bottom-up 누적이 이 진단에 대한 대응입니다 | 리버싱 편 **[해석]** |
| **최신 체크포인트로 갈아타서 성능을 올리려는 시도** | Claude Opus 4.7은 더 최신인데도 4.6보다 성공 수가 적었습니다. 원인은 능력이 아니라 **조기 포기 판단 기준**이었고, 이는 스캐폴딩으로 상쇄 가능한 쪽입니다 | ExploitGym **[측정]** |
| **앙상블을 기본값으로 두는 것** | 합집합 239는 단일 최고 조합 157보다 크지만, **총 연산량이 훨씬 큰 조건의 값**입니다. 동일 예산 비교 실험이 아닙니다 | ExploitGym **[측정]** + 이 시리즈의 해석 |
| **정적 벤치마크 점수로 시스템 능력을 주장하는 것** | 웹 검색을 붙이자 성공률이 12.59% → 24.07%로 올랐는데, 로그에 커닝 시도 71건(그중 63건은 flag를 외부에서 복사)이 있었습니다. `nyuctf` 패키지를 설치해 벤치마크 flag에 직접 접근한 사례도 있었습니다 | CTFusion **[측정]** |

마지막 줄은 CTF-OS의 자체 평가 설계에 직결됩니다. 자세한 것은 [실험 백로그](07-experiment-backlog.md)의 평가 하네스 절에 있습니다.

---

## 실행 기반: Codex CLI로 무엇이 되는가

CTF-OS는 자체 에이전트 루프를 만들지 않고 Codex CLI를 호출합니다. 따라서 **이 설계도가 실현 가능한지는 Codex CLI가 무엇을 제공하는지에 달려 있습니다.** 이건 논문 수치와 달리 직접 확인할 수 있으므로 확인했습니다.

**검증일 2026-07-27, 로컬 `codex-cli 0.145.0` 및 공식 매뉴얼 대조.** 전체 기록은 [출처 검증 기록](08-verification-log.md)에 있습니다.

| 필요한 것 | 상태 | 실제 형태 |
| --- | --- | --- |
| 비대화식 단계 실행 | **있음** | `codex exec [PROMPT]` (별칭 `codex e`) |
| 단계별 계측 | **있음** | `codex exec --json` → JSONL. 이벤트 `thread.started` / `turn.started` / `turn.completed` / `turn.failed` / `item.*` / `error`. **`turn.completed`에 `usage`(input, cached_input, output, reasoning_output 토큰) 포함** |
| 단계 산출물 JSON 고정 | **있음, 단 "요청" 수준** | `--output-schema <FILE>` + `-o/--output-last-message <FILE>` |
| 풀이 경로 연속성 | **있음** | `codex exec resume --last` 또는 `codex exec resume <SESSION_ID>` |
| 역할별 전문 에이전트 | **있음** | `~/.codex/agents/*.toml`(개인) 또는 `.codex/agents/*.toml`(프로젝트). 필수 `name`·`description`·`developer_instructions`, 추가로 `model`·`model_reasoning_effort`·`sandbox_mode`·`mcp_servers`·`skills.config` |
| 동시 실행 상한 | **불확실** | `[agents] max_concurrent_threads_per_session`이 매뉴얼에 있으나, Ultra의 자동 위임에 실제로 적용되는지는 미검증. 09는 이 상한을 강제 조건이 아니라 관측 대상으로 두고 Phase 0에서 조사합니다 |
| 불변 규칙 주입 | **있음** | `AGENTS.md` |
| 명령 감사·차단 | **있음** | Hooks (stable). `~/.codex/hooks.json`, `<project>/.codex/hooks.json` 또는 config.toml의 `[[hooks.PreToolUse]]` |
| 격리 수준 제어 | **있음** | `-s/--sandbox {read-only, workspace-write, danger-full-access}`, `--add-dir`, `--ephemeral` |
| 모델·추론 예산 제어 | **있음** | `-m/--model`, `model_reasoning_effort`, `-p/--profile` |
| 토큰·비용 상한 | **없음** | `codex features list`에서 `token_budget`·`rollout_budget`이 `under development` |

여기서 “없음”은 Codex CLI 자체의 native token/cost cap을 뜻한다. 현재
CTF-OS가 집행하는 문제별 8시간 deadline과 Batch provider 동시성 FIFO
상한과는 별개의 기능 경계다.

훅 이벤트는 다음과 같습니다. `SessionStart`, `SessionEnd`(메인 스레드만), `SubagentStart`, `SubagentStop`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `Stop`.

### 여기서 나오는 설계 결정 네 개

**1. `--output-schema`는 검증기를 대체하지 않습니다.** 매뉴얼 문구가 *request a final response that conforms to a JSON Schema*입니다. 검증하고 재시도한다는 서술이 없습니다. 따라서 **오케스트레이터가 직접 스키마 검증하고 실패 시 재호출**해야 합니다. 이 검증기를 빼면 이후 모든 단계가 조용히 깨집니다. 구현 단계 2번의 필수 구성요소입니다.

**2. 단계 간 제어 흐름은 서브에이전트가 아니라 별개 `codex exec` 호출로 만듭니다.** `.codex/agents/*.toml`은 역할 정의를 주지만 **spawn 여부는 부모 모델이 결정합니다**(매뉴얼: *Ask Codex to delegate*). 호스트에서 "지금 falsifier를 실행해라"를 결정적으로 시킬 수 없습니다. 그래서 12단계 파이프라인의 순서는 Python 오케스트레이터가 잡고, `.codex/agents/`는 **한 단계 안에서의 병렬 탐색**에 씁니다.

**3. `PreToolUse` 훅이 호출을 차단하거나 재작성할 수 있습니다.** 이것이 이 설계도의 가장 취약한 전제를 바꿉니다. 원래 Blackboard 규약을 프롬프트로 "부탁"하고 준수율을 측정할 계획이었는데(`X-18`), **훅에서 강제할 수 있습니다.** 규약 위반 도구 호출을 `PreToolUse`에서 거부하면 준수율이 설계 변수가 아니라 상수가 됩니다.

주의할 점 두 개가 있습니다. 같은 이벤트에 걸린 훅들은 **동시 실행되며 서로를 막지 못합니다.** 그리고 비관리 훅은 검토·신뢰 등록이 필요하므로, 자동화에서는 `--dangerously-bypass-hook-trust`를 쓰거나 `requirements.toml`의 관리 훅으로 배포해야 합니다.

**09는 이 결정을 좁혔습니다.** Hook은 위험 명령 차단, 실행 감사, wrapper 사용 강제에만 씁니다. 사실 provenance 검증, 가설 상태 전이, 실험 사전 등록, 증명 통과 여부, 제출 가능 여부는 Hook에 넣지 않고 구조화 출력 스키마·단일 writer·원자적 파일 교체·상태 머신이 강제합니다. 훅이 서로를 막지 못한다는 위 성질 자체가 의미론을 맡기기에 부적합한 이유입니다. 09 §3.3.

**4. 예산 집행은 우리가 합니다.** 토큰·비용 상한이 CLI에 없으므로, `--json`의 `turn.completed.usage`를 오케스트레이터가 누적해 직접 끊습니다. 부수 효과가 좋습니다. **거부 로그(`R-BGT-7`)와 비용 곡선(`R-BGT-1`)이 같은 이벤트 스트림에서 공짜로 나옵니다.** 그래서 계측이 별도 단계가 아니라 단계 실행기의 부산물이 됩니다.

---

## 아키텍처

컴포넌트는 대회 계층 넷, 문제 계층 다섯, 공유 하나입니다. 호스트에서 도는 것과 컨테이너에서 도는 것을 구분했습니다.

> **09에서 바뀐 것.** 아래 10개 분해는 "무엇이 어떤 실패에 대응하는가"를 보여주는 **기능 분해**로는 유효하지만, 실행 단위로는 만들지 않습니다. 09는 이것을 런타임 넷으로 합쳤습니다 — Challenge Engine / Codex Pool / Sandbox Pool / Director. ③ Scheduler는 **폐기**되고, ⑥ Blackboard와 ⑩ Ledger는 문제별 `state.json`과 파생 뷰가 되며, ⑦ Falsifier와 ⑧ Librarian은 Codex Pool의 **role**이, ⑨ Governor는 Challenge Engine 내부 모듈이 됩니다. 매핑표는 09 §3.2에 있습니다. 아래 표의 "대응하는 실패"와 근거는 그대로 유효합니다.

```
┌─ 대회 계층 (호스트) ───────────────────────────────────────────────┐
│                                                                    │
│  ① Intake       규칙·종료시간·문제목록·점수·제출제한 → contest.json │
│  ② Scout        전역 정찰. 문제별 triage.json, 초기 순위            │
│  ③ Scheduler    문제 상태 기계, 예산 배분, 문제 간 전환             │
│  ④ Submitter    형식·한도·Proof 검사 후 제출. 오답 재제출 차단      │
│                                                                    │
└───────────────┬────────────────────────────────────────────────────┘
                │  문제 하나를 ACTIVE 로 만들고 예산을 준다
                ▼
┌─ 문제 계층 (호스트, 문제마다 독립) ────────────────────────────────┐
│                                                                    │
│  ⑤ Runner       단계별 `codex exec` 호출 + 스키마 검증·재시도       │
│         │                                                          │
│         │  읽고 쓰는 대상은 컨텍스트가 아니라 파일이다               │
│         ▼                                                          │
│  ⑥ Blackboard   facts / hypotheses / deps / budget / proof         │
│                 ← 원칙 1·2·3의 구현체                              │
│         │                                                          │
│         ├─→ ⑦ Falsifier  독립 thread + read-only. 반증 전담         │
│         ├─→ ⑧ Librarian  장문 원본 회수, doc_id 영속, 기법 브리핑   │
│         └─→ ⑨ Governor   진전 지표, 반복 감지, 중단·전환 결정       │
│                                                                    │
└───────────────┬────────────────────────────────────────────────────┘
                │
┌─ 공유 ─────────▼──────────────────────────────────────────────────┐
│  ⑩ Ledger   곡선 프로파일, 거부 로그, 기법 카탈로그, 대회별 성적    │
└───────────────┬────────────────────────────────────────────────────┘
                │ docker exec
┌─ 컨테이너 (도구 전용, LLM 없음) ──────────────────────────────────┐
│  ctfwrap / ctf-bg / ctf-jobs / ctf-log / ctf-flag                  │
│  /challenge (ro) → /work (rw)   /tools/manifest.json               │
│  pwn · rev · crypto · forensic · web · stego 도구                   │
└────────────────────────────────────────────────────────────────────┘
```

각 컴포넌트가 어느 실패에 대응하는지 명시합니다. **대응 관계가 없는 컴포넌트는 만들지 않습니다.**

| 컴포넌트 | 대응하는 실패 | 근거 |
| --- | --- | --- |
| **① Intake** | flag 출처 불명, 제출 한도 초과, 원본 무결성 미확인 | BearcatCTF CryptoPwn (C), ExploitGym 경로 이탈 |
| **② Scout** | 쉬운 문제를 늦게 발견, 필요한 도구 유무 미확인 | Excalibur TDA **[측정]** |
| **③ Scheduler** *(09에서 폐기)* | 한 문제에 예산을 통째로 소진, 조기 포화형 모델에 긴 예산 | ExploitGym 곡선 **[측정]**, Second Look 조기 종료 **[측정]** — 둘 다 **한 문제 안의 중단 기준**에 대한 근거이므로 Challenge Engine으로 흡수 |
| **④ Submitter** | 오답 재제출로 한도 소진, Proof 없는 제출 | 운영 요구 |
| **⑤ Runner** | 단일 프롬프트에 모든 목표를 밀어넣는 구조, 산출물 스키마 붕괴 | SIABench multi-state 45.9→70.0 **[측정]** |
| **⑥ Blackboard** | W2 관측 과신, W3 컨텍스트 손실, Question Dependency, blind 추출 상태 붕괴 | NDSS BAR (A), SIABench, Second Look |
| **⑦ Falsifier** | 자기 답 합리화, 디코이 분석, 하드코딩 solver, flag 유출 | Failing to Falsify **[측정, 도메인 밖]**, NDSS BAR task #11 **[측정]** |
| **⑧ Librarian** | 지식 입도 부족, 초록 수준 부분 지식의 오도, 재구현 오류 | KryptoPilot **[측정]** |
| **⑨ Governor** | W4 계획 고착, scholar-like enumeration, Infinite Loop, 조기 포기 | NDSS BAR, Second Look, SIABench, ExploitGym |
| **⑩ Ledger** | 세션 간 기법 재학습, 곡선 미측정, 거부 원인 미파악 | BearcatCTF (C), ExploitGym |

**Falsifier를 별도 컴포넌트로 둔 이유**를 적어둡니다. 원래 설계는 반증 테스트를 문제 루프 안에 넣었습니다. 그런데 Failing to Falsify가 측정한 것은 확증 편향이고, **편향된 컨텍스트에 자기 답의 반증을 맡기는 것은 약한 개입**입니다. 그래서 반증은 새 `codex exec` thread에서 돌립니다.

검증된 기능이 이걸 깔끔하게 만듭니다. `.codex/agents/falsifier.toml`에 `sandbox_mode = "read-only"`를 주면 **검증기가 자기가 심판하는 산출물을 물리적으로 수정할 수 없습니다.** 판정과 수정의 분리가 프롬프트 규율이 아니라 샌드박스 속성이 됩니다.

**컨테이너 쪽은 새로 만들 것이 거의 없습니다.** 이미 있는 `ctfwrap`이 원칙 2를 도구 단위에서 구현하고, `entrypoint.sh`의 원본 해시 기록이 Proof의 무결성 검사에 쓸 재료를 남깁니다. 새 요구사항은 `R-ENV-2`, `R-ENV-3`, `R-ENV-7` 셋뿐입니다.

---

## 문제 상태 기계

원래 이 절의 전제는 한 문장이었습니다. **Agent가 한 문제에서 2시간 헤매는 동안 쉬운 5문제를 놓치지 않게 하는 것.**

근거는 두 개입니다. Second Look **[측정]**: Executor 단독 아키텍처는 실패한 실행에서 대부분 최대 스텝(50)을 소진했지만, Planner를 넣으면 계획이 틀렸다고 판단했을 때 평균 40스텝 부근에서 자발 종료했습니다. ExploitGym **[측정]**: 모델마다 시간-성공 곡선의 모양이 달라, 조기 포화형에 긴 예산을 주는 것은 낭비입니다.

> **09에서 바뀐 것.** 이 근거 둘은 모두 **한 문제 안에서 언제 멈출 것인가**에 대한 것이지, 문제 사이를 어떻게 전환할 것인가에 대한 것이 아닙니다. 그래서 09는 이 근거를 Challenge Engine의 중단 기준(`R-BGT-3`, STALLED 판정)으로만 받고, 문제 간 전환을 결정하는 Scheduler는 만들지 않습니다. 아래의 문제 상태 기계는 **한 문제의 상태 기계로** 그대로 유효합니다(09 §10). 사라진 것은 이 상태들을 훑어 다음 문제를 고르는 주체입니다 — 그 자리는 사람이 채웁니다.

문제는 다음 상태 중 하나를 갖습니다.

| 상태 | 의미 | 나가는 조건 |
| --- | --- | --- |
| `NEW` | 인테이크만 됨 | Scout이 정찰 |
| `TRIAGING` | 정찰 중 | `triage.json` 작성, 풀이 방향 2개 이상 확보 |
| `ACTIVE` | 폐쇄루프 실행 중 | Governor가 중단하거나 Proof 통과 |
| `STALLED` | 진전 없음으로 중단됨 | 회복 사다리의 다음 단계로 재개 |
| `NEEDS_RESEARCH` | 외부 원본 지식이 필요 | Librarian이 장문 원본 회수 |
| `NEEDS_HUMAN` | 사람 판단이 필요한 한 지점에서 막힘 | 사람이 그 지점만 답 |
| `PROVING` | flag 후보 확보, 재현 검증 중 | Proof 통과 또는 실패 |
| `READY_TO_SUBMIT` | Proof 통과 | Submitter가 제출 |
| `SOLVED` | 제출 정답 | — |
| `ABANDONED` | 예산·시간상 포기 | — |

**`STALLED`는 실패가 아니라 보류입니다.** 여기서 사다리 등급이 중요해집니다. 어디까지 갔는지가 남아 있으면 **어디서 막혔는지**를 사람이 즉시 봅니다. 이진 판정만 있으면 그 문제를 다시 열지 말지 판단할 근거가 없습니다. 09에서 이 값은 재개 순위를 계산하는 입력이 아니라 board의 진단 표시입니다.

`NEEDS_HUMAN`을 별도 상태로 둔 근거는 Decompiling the Synergy입니다. **[측정]** LLM 지원은 초보자의 이해도를 크게 높였지만 전문가의 전체 성과에는 거의 영향이 없었고, 잘못된 제안이 전문가의 분석 시간을 오히려 늘린 사례도 있었습니다. 사람을 부를 때는 **"정확히 막힌 한 지점"만** 넘겨야 하고, 그러려면 그 지점이 상태로 표현되어야 합니다.

### 회복 사다리

`STALLED`에서 재개할 때 비용이 낮은 것부터 올립니다.

| 단계 | 조치 | 비용 |
| --- | --- | --- |
| 1 | 같은 가설, 다른 실험 | 최저 |
| 2 | 포트폴리오의 다른 가설로 교체 | 낮음 |
| 3 | 정적 ↔ 동적 분석 전환 | 낮음 |
| 4 | 다른 역할 에이전트 투입 (`.codex/agents/`) | 중간 |
| 5 | 논문·원본 구현 검색 → `NEEDS_RESEARCH` | 중간 |
| 6 | `model_reasoning_effort` 상향 후 재시작 | 높음 |
| 7 | 사람에게 막힌 한 지점만 요청 → `NEEDS_HUMAN` | 최고 |

**5단계에는 제약이 붙습니다.** KryptoPilot **[측정]**에서 초록 수준 지식은 궤적을 길게 만들고 한 문제에서는 오히려 오도했습니다. 따라서 검색은 **장문 원본이어야 하며, 초록만 확보된 경우 주입하지 않고 그대로 `STALLED`로 둡니다**(`R-KNW-1`).

**그리고 이 사다리에는 아래 방향이 하나 빠져 있었습니다.** KryptoPilot의 Model Router 제거 실험은 성공률 동일, 평균 30초 → 169초였습니다. 5배가 **낮은 난이도 작업을 중급 모델로 내려보내는 데서** 나옵니다. 사다리는 위로만 가지만, Runner의 단계별 모델 선택은 아래로도 가야 합니다(`R-BGT-4`). Ingest, inventory, 요약이 대상입니다.

---

## 상태 스키마

Blackboard가 이 설계의 중심입니다. 스키마를 애매하게 두면 나머지가 전부 흐려지므로 필드 단위로 확정합니다.

위치는 대회 폴더와 문제 폴더 아래입니다. 컨테이너의 `/work` 안이 아니라 **호스트 쪽**에 둡니다. 컨테이너는 매 실행마다 새로 뜰 수 있고, 상태는 그보다 오래 살아야 합니다.

> **09에서 바뀐 것 — 이 절에서 가장 큰 변경입니다.**
>
> 아래의 **필드 정의는 전부 유효하지만, 파일 분해는 폐기되었습니다.** `facts.jsonl` / `hypotheses.jsonl` / `experiments.jsonl` / `deps.json` / `budget.json` / `audit.json`을 따로 두면 동시 append 순서가 비결정적이고, 파일 사이의 원자적 갱신이 불가능하며, 부분 쓰기 후 복구 기준을 정할 수 없습니다. 09는 이것을 **문제별 `state.json` 하나**로 합치고 단일 writer + 임시 파일 + `os.replace`로 교체합니다. `events.jsonl`은 감사·디버깅 전용이고 복구 기준이 아닙니다. 근거와 필드는 09 §3.1과 §8에서 그대로 이어받았습니다.
>
> 저장 위치도 바뀌었습니다. 상태는 `incoming/` 안이 아니라 별도 `.ctfos/contests/<contest-id>/challenges/<challenge-id>/` 아래에 두고, `incoming/`에는 읽기 전용 원본만 남깁니다(09 §8.1).
>
> 아래 스키마를 읽을 때는 **"이 필드가 필요하다"로 읽고 "이 파일을 만든다"로 읽지 마세요.**

```
incoming/<대회>/.ctfos/
├── contest.json       규칙, 종료시간, 점수, 제출 한도
├── board.json         문제별 상태·리스 보유량·stall 신호 (읽기 전용 파생 뷰, 순위 없음)
└── submissions.jsonl  제출 이력 (오답 재제출 차단용)

incoming/<대회>/<카테고리>/<문제>/.ctfos/
├── challenge.json     문제 메타, 원본 해시, 허용된 flag 획득 경로
├── triage.json        문제 유형 분류, 필요 능력, 풀이 방향 2개 이상
├── facts.jsonl        관측된 사실 (출처 등급과 재현 명령 필수)
├── hypotheses.jsonl   가설 포트폴리오 (반증 테스트 필수)
├── experiments.jsonl  실험 사전 등록 (유지·폐기 기준을 실행 전에)
├── deps.json          하위 목표 의존성 그래프
├── budget.json        소비·잔여, 진전 지표 이력, 중단 규칙
├── audit.json         경로 판정, 사다리 채점, 오염 감사
├── proof/             재현 스크립트와 결과
├── runs/              도구 원출력 + codex --json 이벤트 스트림
├── artifacts/         실행 가능한 산출물
└── knowledge/         doc_id로 인덱싱된 장문 원본
```

`runs/`에 도구 출력과 **Codex 이벤트 스트림을 함께** 두는 것이 중요합니다. `codex exec --json`의 JSONL을 그대로 적재하면 거부 로그(`R-BGT-7`), 토큰 사용량, 도구 호출 이력이 한 곳에서 나옵니다. 계측을 위해 따로 만들 것이 없습니다.

### facts.jsonl — 원칙 1의 구현체

한 줄이 하나의 관측입니다. **`confidence` 필드가 이 스키마의 존재 이유입니다.**

```json
{
  "id": "F-007",
  "claim": "argv[1]의 5번째 바이트를 0x2A와 비교한다",
  "confidence": "executed",
  "tool": "gdb",
  "cmd": "ctfwrap gdb -batch -ex 'b *0x4011a3' -ex run -ex 'x/8bx $rdi' --args ./chal AAAAAAAA",
  "raw": "runs/0007-gdb.txt",
  "observed_at": "2026-07-27T14:02:11Z",
  "supports": ["H-004"],
  "contradicts": ["H-002"]
}
```

`confidence`는 세 값만 허용합니다.

| 값 | 의미 | 규칙 |
| --- | --- | --- |
| `executed` | 실제로 실행해서 관측함. `cmd`로 재현 가능 | `cmd`와 `raw` 필수 |
| `tool-inferred` | 도구가 재구성한 것. 디컴파일 의사코드, 심볼 추정, 타입 추론 | **결론의 근거로 단독 사용 금지.** `executed`로 승격시켜야 함 |
| `model-claimed` | 모델이 서술한 것. 아직 아무것도 확인되지 않음 | 가설로 옮기거나 검증해야 함 |

이 세 값의 구분이 리버싱 편 W2(관측 과신)에 대한 직접적인 대응입니다. 디컴파일러 출력은 정의상 `tool-inferred`입니다. task #11의 디코이 함수가 `tool-inferred`로 기록되어 있으면, 그것을 근거로 결론을 내리기 전에 "실제로 호출되는가"를 `executed`로 확인해야 한다는 규칙이 자동으로 걸립니다.

**왜 `"confidence": 0.9` 같은 실수값을 쓰지 않는가.** 실수 confidence는 모델이 생성한 값이라 레코드 간 비교가 성립하지 않습니다. 어제의 0.9와 오늘의 0.9가 같은 뜻이 아닙니다. 그리고 W2가 요구하는 것은 **확률이 아니라 출처**입니다. "이게 얼마나 확실한가"가 아니라 "이걸 직접 봤는가, 도구가 재구성한 것인가, 모델이 말한 것인가"입니다.

열거형으로 두면 Falsifier의 검사 항목이 문법적으로 자동 판정됩니다. "디컴파일 결과를 사실로 가정하지 않았는가"는 `tool-inferred` 레코드가 결론의 유일한 근거인지 보는 질의 한 줄이 됩니다. 실수값으로는 이 질의를 쓸 수 없습니다.

또 하나. `cmd` 필드는 사람의 재검증 비용을 낮추기 위한 것이기도 합니다. Decompiling the Synergy는 잘못된 LLM 제안이 전문가의 분석 시간을 **오히려 늘렸다**고 보고했습니다. 확인된 사실과 재현 명령을 함께 남기는 것이 그 비용을 줄이는 방향입니다.

### hypotheses.jsonl — 원칙 3의 구현체

`falsifier`가 없는 레코드는 등록을 거부합니다.

```json
{
  "id": "H-004",
  "statement": "검증 루틴은 XTEA이며 키는 전역 테이블에서 온다",
  "paradigm": "rev/crypto-in-binary",
  "falsifier": {
    "desc": "XTEA라면 delta=0x9E3779B9가 라운드마다 누적되어야 한다. sum 갱신 순서가 TEA를 따르면 반증된다.",
    "cmd": "python3 artifacts/check_delta.py",
    "expect_if_false": "라운드별 sum 값이 참조 구현과 불일치"
  },
  "status": "open",
  "evidence": ["F-007"],
  "cost_spent_s": 420,
  "refuted_by": null,
  "created_at": "2026-07-27T14:05:02Z"
}
```

`status`는 `open` / `supported` / `refuted` / `confirmed`입니다. `confirmed`는 **Falsifier와 Proof를 통과한 경우에만** 붙습니다. 모델이 스스로 `confirmed`를 쓸 수 없습니다.

`confidence`는 여기서만 실수값입니다. 가설 포트폴리오는 서로 비교해서 다음 실험을 골라야 하므로 순서가 필요합니다. **반면 `facts.jsonl`에는 실수 confidence를 두지 않습니다** — 이유는 아래에 적었습니다.

### 가설 포트폴리오와 실험 사전 등록

한 가설에 올인하지 않고 **최소 2~3개를 동시에 유지**합니다. W4(계획 고착)에 대한 구조적 대응입니다. 고착은 대안이 기록되어 있지 않을 때 훨씬 강해집니다.

그리고 다음 실험은 "가장 그럴듯한 가설을 확인하는 실험"이 아니라 **가설들을 가장 잘 갈라내는 최소 비용 실험**을 고릅니다. 이것이 원칙 3의 실질적인 구현입니다.

실험은 실행 **전에** 등록됩니다.

```json
{
  "id": "E-011",
  "discriminates": ["H-004", "H-007"],
  "cmd": "python3 artifacts/check_delta.py --trace runs/0012-trace.txt",
  "keep_if": "라운드별 sum 이 0x9E3779B9 배수로 누적됨",
  "drop_if": "sum 갱신이 라운드당 2회 발생 (TEA 계열)",
  "max_runs": 3,
  "max_seconds": 600,
  "oracle": "artifacts/check_delta.py exit code 0",
  "result": null
}
```

`keep_if`와 `drop_if`를 실행 전에 적게 하는 것이 핵심입니다. **사후에 기준을 정하면 어떤 결과든 가설을 지지하는 쪽으로 해석됩니다.** 이게 Failing to Falsify가 측정한 확증 편향의 작동 방식입니다.

`paradigm` 필드는 크립토 편에서 나온 요구입니다. KryptoPilot이 정리한 실패 1번(공격 패러다임 오인)과 3번(통계적 누적 공격 인식 부족)은 같은 뿌리였습니다. **"이 문제가 어떤 종류의 게임인가"를 규정하는 단계가 명시적으로 수행되지 않고 첫 몇 토큰에서 암묵적으로 결정되기 때문**입니다. 이 필드를 필수로 두면 그 판정이 기록으로 남고, 틀렸을 때 되돌릴 지점이 생깁니다.

허용값은 카테고리별로 고정합니다.

| 카테고리 | `paradigm` 허용값 |
| --- | --- |
| crypto | `static-math` / `interactive-oracle` / `protocol-logic` / `impl-sidechannel` / `statistical-accumulation` |
| pwn | `memory-corruption` / `logic-bug` / `race` / `sandbox-escape` / `kernel-lpe` |
| web | `injection` / `authz-idor` / `business-logic` / `client-side` / `race` / `deserialization` |
| rev | `static-verifiable` / `runtime-constructed` / `vm-interpreter` / `crypto-in-binary` / `anti-analysis` |
| forensic | `surface-pattern` / `artifact-dissection` / `multi-stage-chain` / `stego` |

web의 `business-logic`과 `race`, crypto의 `statistical-accumulation`이 특히 중요합니다. 웹 편에서 인식 실패 7문제의 상당 부분이 비즈니스 로직으로 추정되고, race condition은 **claude-code가 병렬 서브에이전트를 띄울 능력이 있었는데도 동시성이 필요하다는 것 자체를 추론하지 못했습니다.** 분류를 강제하면 최소한 그 판정이 한 번은 수행됩니다.

### deps.json — Question Dependency 대응

SIABench에서 Question Dependency는 상위 모델 두 개 모두에서 실패 원인 1위였습니다. 선행 단계가 실패하면 그에 의존하는 이후 분석이 전부 무효가 되는 **연쇄 실패**입니다.

```json
{
  "goals": [
    {"id": "G-1", "goal": "PCAP에서 전송된 파일 추출",
     "status": "done", "artifact": "artifacts/extracted.pdf", "depends_on": []},
    {"id": "G-2", "goal": "PDF 내 난독화 스크립트 추출",
     "status": "blocked", "depends_on": ["G-1"], "blocked_reason": "G-1 산출물이 손상"},
    {"id": "G-3", "goal": "스크립트가 접속하는 C2 도메인 식별",
     "status": "parked", "depends_on": ["G-2"]}
  ],
  "on_block": "alt_path"
}
```

규칙은 두 개입니다. **선행 목표가 `blocked`면 후속 목표는 자동으로 `parked`가 되고, Solver는 그 목표에 예산을 쓰지 않습니다.** 그리고 `on_block`이 `alt_path`면 Governor가 선행 목표에 대한 대체 경로를 탐색하게 합니다(예: `tshark` 추출 실패 시 `foremost` 카빙으로 전환).

이 그래프는 포렌식 전용이 아닙니다. 포너블의 "크래시 재현 → 오프셋 확정 → 제어 획득 → 샌드박스 탈출"도 같은 형태이고, ExploitBench의 16개 flag 사다리가 그 사례입니다.

### budget.json — 원칙 5와 Governor의 입력

```json
{
  "deadline_utc": "2026-07-28T02:00:00Z",
  "allocated_s": 3600,
  "spent_s": 1840,
  "model_tier": "mid",
  "progress_markers": [
    {"t": 300,  "marker": "크래시 로컬 재현"},
    {"t": 900,  "marker": "오프셋 확정"},
    {"t": 1200, "marker": "libc 베이스 누출"}
  ],
  "no_progress_since_s": 640,
  "abort_rule": {
    "max_no_progress_s": 900,
    "max_consecutive_refuted": 3,
    "max_repeated_cmd": 4
  },
  "refusals": [],
  "curve_profile": "ledger/curves/claude-mythos-preview.json"
}
```

`progress_markers`가 Governor의 핵심 입력입니다. 웹 편에서 본 두 궤적이 이 필드의 존재 이유입니다. 한 궤적은 Step 9에서 IDOR을 확인하고도 `robots.txt`, `/admin`, `/debug`, path traversal, `/flag`, `/api/flag`를 차례로 찔러보며 6스텝을 낭비했고, 다른 궤적은 Step 26~31에서 XSS 필터 우회를 찾아냈는데 그 뒤로 우회를 전혀 쓰지 않고 Step 36부터 50까지 모든 정적 이미지에 `strings | grep flag`를 돌리다 끝났습니다.

**두 번째 궤적에서 필터 우회 발견은 그 문제의 가장 어려운 부분이었습니다.** 그것을 마커로 기록하고 "마커 이후 진전이 없으면 마커 지점으로 되돌아간다"는 규칙을 두는 것이, 이 실패에 대한 직접적인 대응입니다.

`refusals` 배열은 포너블 편에서 나온 요구입니다. 기본 안전 필터를 켠 GPT-5.5는 **88.2%의 경우 도구 호출 전에 차단**됐습니다. 이 수준이면 성능 측정 자체가 무의미해집니다. 원인 불명의 정체가 생겼을 때 모델 능력이나 프롬프트를 의심하기 전에 거부 로그를 먼저 보게 하려면, 상시 계측되어야 합니다.

`curve_profile`은 축적된 모델별 시간-성공 곡선을 가리킵니다. **이 값이 없으면 `allocated_s`는 근거 없는 값입니다.** 곡선은 실행 로그(`runs/`의 `codex exec --json` 이벤트)에서 산출합니다. 09에서는 이 곡선이 예산을 **자동 배정하는 입력이 아니라** board에 표시되는 운영 판단 재료입니다 — "이 모델은 30분쯤에서 포화하니 지금 세션을 하나 더 여는 게 낫다"를 사람이 판단합니다.

### audit.json — 원칙 4의 구현체

```json
{
  "flag": "flag{...}",
  "flag_source": "exploit",
  "solve_wall_s": 91,
  "fast_solve_threshold_s": 300,
  "audit_required": true,
  "path_check": {
    "intended_vuln_triggered": true,
    "reproduce": "artifacts/exploit.py",
    "rerun_ok": true,
    "rerun_count": 3,
    "judge": "oracle/path_judge.md"
  },
  "provenance_scan": {
    "flag_found_in_files": [],
    "network_access": false,
    "writeup_access": false
  },
  "ladder": {"reached": "control-flow-hijack", "max": "arbitrary-code-execution"}
}
```

`flag_source` 허용값은 `exploit` / `solver` / `file_read` / `external` / `unknown`입니다. `file_read`와 `external`은 자동으로 감사 대상이며, 자체 성적 집계에서 제외됩니다. `provenance_scan.flag_found_in_files`가 비어 있지 않으면 BearcatCTF의 CryptoPwn 사례와 같은 상황입니다.

`ladder`는 ExploitBench의 설계를 가져온 것입니다. **이진 성공/실패 채점은 병목을 감춥니다.** 100문제 중 5개를 풀었다는 정보만으로는 나머지 95개에서 크래시조차 못 냈는지, 크래시는 냈는데 제어를 못 잡았는지, 제어는 잡았는데 샌드박스를 못 나갔는지 알 수 없습니다.

ExploitBench는 41개 V8 버그에 16개 flag를 붙여 평가했고, **공개 배포 프론티어 모델 8개는 취약 코드 도달과 크래시는 일상적으로 해내지만 임의 코드 실행은 그렇지 못했습니다.** CTF-OS의 사다리는 이보다 단순해도 되지만, 최소한 카테고리별로 3~5단이 있어야 개선 지점이 보입니다.

| 카테고리 | 사다리 단계 |
| --- | --- |
| pwn | `crash` → `offset-fixed` → `leak` → `control-flow-hijack` → `shell/flag` |
| rev | `entry-located` → `validation-found` → `logic-modeled` → `solver-works` → `keygen-generalizes` |
| crypto | `paradigm-classified` → `attack-identified` → `params-recovered` → `plaintext-recovered` |
| web | `surface-mapped` → `vuln-recognized` → `poc-fires` → `flag-extracted` |
| forensic | `artifact-parsed` → `payload-extracted` → `payload-decoded` → `flag-extracted` |

rev의 마지막 단계가 `keygen-generalizes`인 이유는 CrackMeBench가 keygen을 요구하는 이유와 같습니다. keygen은 특정 입력 하나를 맞히는 것이 아니라 주어진 입력에 맞는 키를 생성하는 함수를 만들어야 하고, **숨겨진 사용자 이름으로도 검증되므로 값을 하드코딩해서는 통과할 수 없습니다.**

### proof/ — "flag처럼 보이는 문자열"은 성공이 아니다

`audit.json`이 판정 결과라면 `proof/`는 그 판정의 재현 가능한 근거입니다.

```
proof/
├── reproduce.sh     원본 파일에서 시작하는 단일 명령
├── result.json      실행 결과와 재현 횟수
└── transcript.txt   실행 로그
```

성공 조건은 **깨끗한 새 컨테이너에서** 다음이 성립하는 것입니다.

1. `/challenge`의 원본 파일로 시작한다 (`challenge.json`의 SHA-256과 일치)
2. `proof/reproduce.sh` 하나로 solver·exploit이 실행된다
3. 3회 이상 성공한다
4. 원격 서비스 문제면 원격에서도 확인된다
5. flag가 실행 결과로 산출된다 — 파일에서 읽힌 것이 아니다

**3번과 5번이 서로를 보완합니다.** ExploitGym **[측정]**에서 flag를 얻은 226건 중 실제 성공은 157건(69.5%)이었고 나머지는 옆의 더 쉬운 취약점으로 샌 것이었습니다. BearcatCTF **(C)**에서는 CryptoPwn 문제에서 `README.md`의 flag를 읽은 것이 `CHEATED`로 잡혔습니다. **새 컨테이너 + 원본 파일 조건이 두 유형을 동시에 막습니다.** 이전 실행의 부산물이 남아 있는 작업 디렉터리에서는 이 검사가 성립하지 않습니다.

### submissions.jsonl — 제출을 풀이와 분리한다

```json
{"ts":"2026-07-27T15:02:11Z","challenge":"rev/Warmup","flag":"flag{...}",
 "proof_passed":true,"format_ok":true,"attempt":1,"response":"correct","points":100}
```

Submitter는 제출 전에 네 가지를 검사합니다. 제출 한도 잔여, flag 형식(`FLAG_REGEX`), `proof_passed`, **그리고 같은 문제에 같은 값을 이미 오답으로 낸 적이 있는지.** 마지막 항목이 없으면 루프가 같은 오답을 반복 제출해 한도를 태웁니다.

> **폐기된 초안:** `clean_rate`가 안정되면 자동 제출로 전환한다는 제안은
> 채택하지 않았다. 현재 계약은 flag처럼 보이는 문자열을 발견 즉시
> **미제출 후보**로 터미널에 출력하고, clean proof 뒤에도 사람이 CTF
> 사이트에 직접 제출한 다음 `ctfos submit --outcome ...`으로 결과만
> 기록하는 것이다. CTF 자격증명 저장이나 자동 POST 경로는 없다.

---

## 제어 루프

두 계층의 루프를 의사코드로 확정합니다. 문제 루프는 리버싱 편의 S1–S3(Observe–Comprehend–Plan)에 원칙 3·4·5의 게이트를 끼운 형태입니다.

```
INGEST → TRIAGE → OBSERVE → MODEL → HYPOTHESIZE → PLAN_EXPERIMENT
                     ↑                                    ↓
                  RECOVER ← EVALUATE ←──────────────── EXECUTE
                                                          ↓
                                                 FALSIFY → PROVE → SUBMIT
```

```python
# 대회 계층 — 09에서 폐기되었습니다.
#
# 이전 설계는 board.pick_next(ledger) 로 다음 문제를 고르고
# allocate(...) 로 예산을 배정하는 while 루프였습니다.
# 09는 이 루프를 만들지 않습니다. 아래가 대체된 형태입니다.

def solve(contest_dir, challenge_id):        # ctfos solve — 사람이 필요한 만큼 실행한다
    lease = broker.acquire("captain", 1)     # captain 리스는 회계만 하고 차단하지 않는다
    try:
        run_challenge(challenge_id)          # 문제 계층. 아래 참조
    finally:
        broker.release(lease)                # 프로세스가 죽어도 flock 해제로 같이 풀린다

# 브로커의 전체 API는 셋뿐입니다 — acquire / release / status.
# 순위 계산도, 선점도, 자동 문제 전환도 없습니다.
# 무엇을 언제 열지는 사람이 정하고, board 는 상태·리스 보유량·stall 신호를
# 보여주기만 합니다. 09 §5.4, §16 Phase 6.
```

```python
# 문제 계층 — 목표를 하나씩 처리한다 (multi-state)
def run_challenge(ch, budget):
    bb = Blackboard.open(ch)
    brief = librarian.brief(ch.category, ledger)      # 세션 간 기법 브리핑

    for goal in bb.deps.ready_goals():                # blocked 선행이 있으면 건너뛴다
        while not governor.should_stop(bb, goal):
            # OBSERVE — 원출력은 runs/ 로, 컨텍스트에는 요약만
            bb.add_facts(observe(goal, bb))           # confidence 등급 강제

            # MODEL + HYPOTHESIZE — 포트폴리오를 2~3 개 유지한다
            bb.sync_portfolio(comprehend(bb, brief))  # falsifier 없으면 등록 거부

            # PLAN_EXPERIMENT — 가설들을 가장 잘 갈라내는 최소 비용 실험
            exp = plan_experiment(bb.open_hypotheses())
            bb.register(exp)                          # keep_if / drop_if 를 실행 전에

            # EXECUTE + EVALUATE — 사전 등록한 기준으로만 판정한다
            bb.apply(evaluate(exp, run(exp)))         # drop_if 적중 → refuted

            if not bb.has_supported_hypothesis():
                continue

            # 산출물. 설명으로 끝나지 않는다.
            art = produce_artifact(bb)                # solver / keygen / exploit
            bb.update_ladder(ladder_of(art, ch))

            # FALSIFY — 새 thread, read-only 샌드박스. 만든 쪽이 아니다.
            if falsifier.reject(art, bb, ch):         # 디코이·하드코딩·flag 유출 검사
                bb.mark_refuted(bb.top_hypothesis()); continue

            # PROVE — 새 컨테이너, 원본 파일, 단일 명령, 3회 이상
            if proof.reproduce(art, ch, runs=3):
                return Outcome("READY_TO_SUBMIT", bb.audit())

        bb.deps.mark(goal, governor.last_reason)      # done / blocked / parked

    return Outcome(governor.next_state(bb), bb.audit())   # STALLED / NEEDS_* / ABANDONED

# Governor — 중단·전환 결정
def should_stop(bb, goal):
    b = bb.budget
    if b.spent_s >= b.allocated_s:                    return "budget"
    if b.no_progress_since_s > b.abort_rule.max_no_progress_s:
        return "no_progress"                          # scholar-like enumeration 차단
    if bb.consecutive_refuted() >= b.abort_rule.max_consecutive_refuted:
        return "paradigm_wrong"                       # 패러다임 재분류로 되돌린다
    if bb.repeated_cmd_count() >= b.abort_rule.max_repeated_cmd:
        return "infinite_loop"                        # SIABench Infinite Loop 대응
    if bb.artifact_churn_without_new_facts():
        return "churn"                                # 아래 참조
    if bb.has_unexploited_marker():
        return "return_to_marker"                     # 유효 발견을 붙들게 한다
    return None
```

### 세 가지 설계 판단

**1. 반증을 별도 thread로 분리했습니다.** 원래 루프는 같은 세션에서 반증 테스트를 돌렸습니다. 그런데 Failing to Falsify가 측정한 것은 확증 편향이고, 편향된 컨텍스트에 자기 답의 반증을 맡기는 것은 약한 개입입니다. 지금은 `EXECUTE` 단계의 `drop_if` 판정(같은 세션, 사전 등록 기준)과 `FALSIFY` 단계(새 thread, read-only)가 **두 겹**입니다.

여전히 근거는 42% → 56%뿐이고 숫자 규칙 과제에서 나온 값입니다. 반증을 매번 돌리는 것은 예산을 씁니다. 그래서 `X-04`(사전 등록 기준의 효과)와 `X-19`(독립 thread가 같은 세션보다 나은가)로 나눠 등록했고, **기본값은 그 두 실험으로 정합니다.**

**2. `churn` 신호를 추가했습니다.** 산출물은 계속 바뀌는데 새 `executed` 사실이 추가되지 않는 상태입니다. 관측 없는 산출물 수정은 방황의 가장 정확한 지표이고, 다른 정체 신호(명령 반복, 진전 없음)가 잡지 못하는 유형입니다. solver를 20번 고쳐 쓰는 것은 매번 다른 명령이므로 `infinite_loop`에 걸리지 않습니다.

**3. 난이도 추정 위에 스케줄러를 올리지 않습니다.** Excalibur가 지목한 Type B 실패의 근본 원인이 **실시간 난이도 추정의 부재**입니다. 즉 난이도 추정은 우리가 의존해야 할 능력이 아니라 없는 것으로 측정된 능력입니다. 그 위에 스케줄러를 올리면 없는 기반 위에 짓는 것이 됩니다.

원래 이 절의 결론은 "그러니 모델 추정 대신 관측 프록시로 순위를 매기자"였습니다. **09는 여기서 한 걸음 더 갔습니다 — 순위를 매기는 주체 자체를 만들지 않습니다.** 관측 프록시가 모델 추정보다 나을 것이라는 근거도 없기 때문입니다. 도구 존재 여부, PoV 재현 여부, 진전 마커는 그대로 수집하되 **순위 계산의 입력이 아니라 board의 표시 항목**으로 씁니다. 사람이 그것을 보고 다음 세션을 엽니다.

---

## 요구사항 대장

요구사항 ID는 카테고리가 아니라 **실패 메커니즘** 축으로 붙였습니다. 시리즈 개요의 실패 메커니즘 표와 같은 축이고, 같은 요구사항이 여러 카테고리에서 참조되기 때문입니다.

접두어는 `CON`(대회 운영), `OBS`(관측 신뢰성), `CTX`(컨텍스트 연속성), `ORC`(검증 오라클), `KNW`(지식), `BGT`(예산·배분), `ENV`(환경 능력), `EVL`(자체 평가)입니다.

### CON — 대회 운영

이 그룹은 문제 하나가 아니라 **대회 전체**에 대한 요구사항입니다. 근거의 성격이 다릅니다. 다른 그룹은 벤치마크 측정에서 나왔지만, 이 그룹은 대회 운영의 구조적 요구와 실전 기록에서 나왔습니다.

| ID | 요구사항 | 근거 | 상태 | 구현 위치 |
| --- | --- | --- | --- | --- |
| **R-CON-1** | 대회 규칙·종료시간·문제목록·점수·제출 한도를 `contest.json`으로 고정한다 | 운영 요구 | 설계 결정 | Intake |
| **R-CON-2** | 원본 파일을 해시하고 허용된 flag 획득 경로를 명시한다. 이전 산출물이나 README의 flag를 성공으로 인정하지 않는다 | CryptoPwn `CHEATED` 사례 (C), flag 획득의 30~43%가 의도하지 않은 경로 **[측정]** | 측정 기반 | Intake + `challenge.json` |
| **R-CON-3** | 본격 풀이 전에 전역 정찰로 문제 유형·필요 능력을 분류하고 **풀이 방향 2개 이상**을 남긴다 | W4 계획 고착 (A). 대안이 기록되지 않으면 고착이 강해짐 | 해석 → 설계 | Scout + `triage.json` |
| **R-CON-4** | 문제를 10개 상태의 기계로 관리하고, 한 문제가 예산을 통째로 소진하지 못하게 한다 | Executor 단독은 대부분 최대 스텝 소진, Planner는 40스텝 부근 자발 종료 **[측정]** | 측정 기반 | **범위 축소.** 상태 기계는 Challenge Engine이 문제 하나에 대해 유지한다. "예산 통째 소진 방지"는 그 문제의 중단 기준(`R-BGT-3`)이지 문제 간 배분이 아니다 |
| **R-CON-5** | ~~작업 순위를 관측 프록시 우선으로 정하고 관찰된 진전으로 재순위한다~~ | 난이도 추정 부재가 Type B의 근본 원인 **[측정]** — 즉 의존할 수 없는 능력 | **폐기 (09 §3.2, Phase 6)** | 없음. 순위를 매기는 주체를 만들지 않는다. 진전 마커는 board의 표시 항목으로만 남는다 |
| **R-CON-6** | ~~`STALLED` 재개 순위를 사다리 도달 단계로 정한다~~ | 이진 판정은 병목을 감춤 (B) | **범위 축소** | 사다리는 순위 입력이 아니라 **진단 필드**로 `state.json`에 남긴다. 어디서 막혔는지 사람과 `X-17`이 보기 위한 것이다 |
| **R-CON-7** | 제출을 풀이와 분리한다. 한도·형식·Proof·**중복 오답**을 검사한다 | 운영 요구 | 설계 결정 | Submitter + `submissions.jsonl` |
| **R-CON-8** | 사람 호출은 `NEEDS_HUMAN` 상태로 표현하고 **막힌 한 지점만** 넘긴다 | 잘못된 LLM 제안이 전문가 분석 시간을 늘림 **[측정]** (A) | 측정 기반 | Challenge Engine 상태 전이 + board 표시 |
| **R-CON-9** | 대회 후 지식 증류는 **전략과 실패 패턴만** 저장한다. flag와 문제 고유 상수는 저장하지 않는다 | 오염이 성공률을 부풀림 **[측정]** — 커닝 71건 중 63건이 flag 외부 복사 | 측정 기반 | Ledger (`X-14`) |

**`R-CON-9`의 금지 조항이 중요합니다.** 세션 간 학습은 효과가 관찰됐지만(C등급), flag나 문제 고유 상수를 축적하면 우리가 스스로 오염을 만듭니다. CTFusion이 측정한 것이 정확히 그 현상입니다. 저장할 것은 "어떤 관측이 결정적이었는가", "어떤 가설이 왜 틀렸는가", "어느 시점에 도구를 전환해야 했는가"입니다.

### OBS — 관측 신뢰성

| ID | 요구사항 | 근거 | 상태 | 구현 위치 |
| --- | --- | --- | --- | --- |
| **R-OBS-1** | 모든 사실은 `confidence`(executed / tool-inferred / model-claimed)와 재현 명령을 함께 기록한다 | W2 관측 과신 (A) | 해석 → 설계 | `state.json`의 facts 필드 |
| **R-OBS-2** | 정적 관측을 해석하기 전에 실행 경로 여부를 확인한다. `tool-inferred` 단독으로 결론을 내지 못한다 | task #11 디코이 함수 (A, **측정**) | 측정 기반 | Solver S1 게이트 |
| **R-OBS-3** | 디컴파일러와 어셈블리를 대등하게 두고, 불일치 시 어셈블리를 신뢰한다 | 15/24 → 17/24, task #23 (A, **측정**) | 측정 기반 (교차검증 조건은 미측정) | `ghidra-decompile` 정책 + `X-03` |
| **R-OBS-4** | 런타임 관측 채널을 확보한다. 힙 상태 요약, 메모리 덤프, trace | 커널 난이도의 주원인은 관측성 (B, **해석**) | 가설 | `R-ENV-3` + `X-16` |
| **R-OBS-5** | 언패킹·안티디버깅이 감지되면 재관측을 강제한다 | M1 Concealment, task #9·#12·#18 (A, **측정**) | 측정 기반 | Runner OBSERVE 재진입 규칙 |
| **R-OBS-6** | 새 `executed` 사실 없이 산출물만 바뀌는 상태(churn)를 정체로 판정한다 | W4 계획 고착 (A) + Infinite Loop (B)가 잡지 못하는 유형 | **[가설]** | Governor `artifact_churn_without_new_facts` |

### CTX — 컨텍스트 연속성

| ID | 요구사항 | 근거 | 상태 | 구현 위치 |
| --- | --- | --- | --- | --- |
| **R-CTX-1** | 도구 원출력은 `runs/`에 저장하고 컨텍스트에는 요약과 포인터만 올린다 | CLE 5 → **0**, 부분 해결률 +12.5~31.9%p (B, **측정**) / F1 −10%p (A) | **측정 기반, 최강 근거** | `ctfwrap`(구현됨) + 호스트 요약기 |
| **R-CTX-2** | 목표를 하나씩 순차 처리한다. 한 프롬프트에 모든 목표를 넣지 않는다 | 45.9% → **70.0%** (B, **측정**) | 측정 기반 | Runner 루프 (`deps.ready_goals`) |
| **R-CTX-3** | 하위 목표 의존성 그래프를 명시 관리하고, 선행 실패 시 후속을 자동 보류한다 | Question Dependency 실패 1위 (B, **측정**) | 측정 기반 (대응책은 가설) | `deps.json` |
| **R-CTX-4** | 반복 추출 상태(시도한 페이로드, 이진 탐색 경계, 확보한 문자)를 컨텍스트 밖 파일로 외부화한다 | blind SQLi 컨텍스트 잠식 (B, **해석**) | 가설 | `.ctfos/state/` + `X-01` |
| **R-CTX-5** | call graph, data flow, xref를 구조화된 컨텍스트로 제공한다 | ReCopilot 13% 개선 (B, **측정**, 함수명·타입 과제) | 측정 기반 (CTF 전이 미검증) | Ghidra 배치 추출 |

### ORC — 검증 오라클과 반증

| ID | 요구사항 | 근거 | 상태 | 구현 위치 |
| --- | --- | --- | --- | --- |
| **R-ORC-1** | 결론은 실행 가능한 산출물로만 인정한다. 설명은 산출물이 아니다 | CrackMeBench 실행 오라클, keygen 일반화 (B) | 벤치마크 설계 철학 (효과 미측정) | `proof.reproduce` |
| **R-ORC-2** | flag 판정과 경로 판정을 분리한다 | 226→157(69.5%), 210→120(56.7%) (B, **측정**) | 측정 기반 | `audit.json.path_check` |
| **R-ORC-3** | 비정상적으로 짧은 풀이에 자동 감사를 건다 | CryptoPwn README 커닝, 감사 라벨 `CHEATED` (C) | 운영 사례 | `audit.json.provenance_scan` |
| **R-ORC-4** | 가설마다 반증 테스트를 등록하고, 지지 증거 수집보다 먼저 실행한다 | 42% → 56% (B, **측정, 도메인 밖**) | **가설** | `state.json`의 hypotheses[].falsifier + `X-04` |
| **R-ORC-5** | 카테고리별 3~5단 사다리로 채점한다. 이진 판정을 쓰지 않는다 | ExploitBench 16 flag, 41개 V8 버그 (B) | 벤치마크 설계 | `audit.json.ladder` |
| **R-ORC-6** | 산출물은 여러 테스트 케이스로 재실행하며, 재현 실패 시 `confirmed`를 취소한다 | keygen은 숨겨진 입력으로도 검증됨 (B) | 벤치마크 설계 | `proof.reproduce(runs≥3)` |
| **R-ORC-7** | 반증은 산출물을 만든 세션이 아니라 **새 thread에서 read-only 샌드박스로** 수행한다 | 확증 편향 (B, 도메인 밖). 같은 컨텍스트의 자기 검토는 약한 개입 | **[가설]** | `.codex/agents/falsifier.toml` (`X-19`) |
| **R-ORC-8** | Proof는 **새 컨테이너에서 원본 파일로 시작해 단일 명령**으로 재현되어야 한다 | flag 획득의 30~43%가 의도하지 않은 경로 **[측정]**, README 커닝 (C) | 측정 기반 | `proof/reproduce.sh` |
| **R-ORC-9** | 가설을 2~3개 포트폴리오로 유지하고, 가설들을 **가장 잘 갈라내는 최소 비용 실험**을 고른다 | W4 계획 고착 (A), Excalibur EGATS **[측정]** | 측정 기반 (선택 규칙은 가설) | `state.json`의 hypotheses 필드 |
| **R-ORC-10** | 실험의 유지·폐기 기준을 **실행 전에** 등록한다 | 확증 편향 (B). 사후 기준은 어떤 결과든 가설을 지지하게 됨 | **[가설]** | `experiments.jsonl` (`X-04`) |

### KNW — 지식

| ID | 요구사항 | 근거 | 상태 | 구현 위치 |
| --- | --- | --- | --- | --- |
| **R-KNW-1** | 장문 원본을 회수한다. 초록·요약만 주입하는 것을 금지한다 | 9/9 전략 식별 vs 6/9 방향 오류, 초록은 오도 유발 (B, **측정**, n=9) | 측정 기반 (표본 작음) | Librarian + `X-07` |
| **R-KNW-2** | 회수한 원본을 `doc_id`로 인덱싱해 영속 보관하고 재사용한다 | KryptoPilot 영속 워크스페이스 (B) | 설계 채택 | `knowledge/` |
| **R-KNW-3** | 검증된 구현이 존재하는 연산은 직접 구현하지 않는다 (LLL/BKZ, Coppersmith, 이산로그, GF(2) 선형대수) | 논문 전문을 줘도 재구현 오류로 실패 (B, **측정**) | 측정 기반 (강제 효과는 미측정) | Solver SOP + `X-08` |
| **R-KNW-4** | 완화 기법 우회 카탈로그와 카테고리별 기법 브리핑을 세션 간 축적한다 | 우회 방식이 전부 공개된 표준 기법 (B, **측정**) / 기법 브리핑 효과 관찰 (C) | 가설 | Ledger + `X-14` |
| **R-KNW-5** | 비표준 사양이 감지되면 외부 원본 소스 검색을 절차로 수행한다 | task #12 뒤섞인 WebAssembly opcode, 인간 3.5% 해결 / 전 Agent 실패 (A, **측정**) | 측정 기반 | Librarian 트리거 |

### BGT — 예산과 배분

| ID | 요구사항 | 근거 | 상태 | 구현 위치 |
| --- | --- | --- | --- | --- |
| **R-BGT-1** | 모델별 시간-성공 곡선을 먼저 측정하고 그에 따라 예산을 배정한다 | 곡선 모양이 모델마다 다름 (B, **측정**) | 측정 기반 (분할 전략은 가설) | Ledger `curves/` + `X-06` |
| **R-BGT-2** | 난이도를 네 축(horizon, evidence confidence, context load, historical success)으로 추정해 탐색·활용을 결정한다 | Excalibur 최대 91%, 상대 39~49% 개선 (B, **측정**) | 측정 기반 | Scout `estimate_difficulty` |
| **R-BGT-3** | 계획이 틀렸다고 판정되면 예산을 남기고 종료한다 | Planner 도입 시 평균 40스텝 부근 자발 종료, 비용 −34% (B, **측정**) | 측정 기반 | Governor `should_stop` |
| **R-BGT-4** | 저난도 작업은 중급 모델로 라우팅한다 | 성공률 동일, 30초 → 169초 (B, **측정**) | 측정 기반 | Codex Pool의 role 라우팅 (09 §6). 문제 간 배분이 아니라 한 문제 안의 작업 유형 라우팅이다 |
| **R-BGT-5** | 진전 지표를 정의하고, 진전 없는 반복을 감지해 강제 전환한다 | Infinite Loop (B, **측정**), scholar-like enumeration (B, **측정**) | 측정 기반 | `budget.json.progress_markers` |
| **R-BGT-6** | 유효 발견을 마커로 기록하고, 이후 진전이 없으면 마커로 되돌린다 | XSS 필터 우회를 찾고도 버리고 20스텝 낭비 (B, **측정**) | **가설** | Governor `return_to_marker` |
| **R-BGT-7** | 모델 거부를 상시 계측한다 | 도구 호출 전 차단 88.2% (B, **측정**) | 측정 기반 | `budget.json.refusals` |

### ENV — 환경 능력

| ID | 요구사항 | 근거 | 현재 상태 |
| --- | --- | --- | --- |
| **R-ENV-1** | headless 브라우저로 렌더링과 JS 실행을 제공한다 | XSS 전원 실패의 원인은 브라우저 부재 (B, **측정**) | **충족** — Playwright + Chromium |
| **R-ENV-2** | 병렬·동기화 실행기를 제공하고, "동시성이 필요한가" 판정 단계를 둔다 | 순차 아키텍처는 병렬을 표현조차 못 함. claude-code는 능력이 있어도 필요성을 추론 못 함 (B, **측정**) | **미충족** — 실행기와 판정 단계 모두 없음 |
| **R-ENV-3** | 디버거 관측을 구조화된 인터페이스로 노출한다 (힙 상태 요약, 레이아웃 덤프) | 커널·힙 병목은 관측성 (B, **해석**) | **부분** — pwndbg 있음, 구조화 인터페이스 없음 |
| **R-ENV-4** | 픽셀 단위 이미지 도구를 제공한다 (QR, 채널 분리, LSB) | 이미지 2문제 미해결 원인은 전문 비전 도구 부재 (C) | **충족** — zbar, stegseek, zsteg, opencv, stegoveritas |
| **R-ENV-5** | SageMath와 검증된 암호 라이브러리를 제공한다 | 격자·타원곡선 계산, 재구현 오류 회피 (B) | **부분** — Sage, flatter, RsaCtfTool 있음. `cuso`·`gf2bv` 미확인 |
| **R-ENV-6** | 어떤 명령도 stdin 없이 멈추지 않고, 긴 출력은 파일로 간다 | R-CTX-1의 도구 단위 구현 | **충족** — `AGENTS.md` 원칙 + `ctfwrap` |
| **R-ENV-7** | 병렬화 규율: 한 산출물의 작성자는 한 명. 파라미터 스윕과 독립 재현만 병렬화한다 | 동일 파일 동시 편집은 상태 손상. 근거는 운영 요구 | **미충족** — 09의 Builder 단일 writer 규칙으로 구현 (09 §6, §11.2). 이전 판이 근거로 든 `max_concurrent_threads_per_session`은 Ultra 내부 위임에 적용되는지 미검증 |

**ENV 계층에서 새로 만들 것은 `R-ENV-2`, `R-ENV-3`, `R-ENV-7` 셋뿐입니다.** 나머지는 이미 이미지에 있습니다. 이것이 앞에서 "무게중심은 오케스트레이션"이라고 한 근거입니다.

`R-ENV-7`은 검증된 기능으로 절반이 해결됩니다. `[agents] max_concurrent_threads_per_session`이 동시 thread 수를 상한하고, 각 역할 에이전트에 `sandbox_mode = "read-only"`를 주면 탐색용 에이전트가 산출물을 건드릴 수 없습니다. **쓰기 권한을 가진 역할을 하나로 제한하는 것이 규율이 아니라 설정이 됩니다.**

### EVL — 자체 평가

| ID | 요구사항 | 근거 | 상태 |
| --- | --- | --- | --- |
| **R-EVL-1** | write-up이 없는 Live CTF를 1차 평가 환경으로 쓴다 | 정적 벤치마크가 Live보다 2.2~2.4배 높게 나온 조합들 (B, **측정**, 원인 미분리) | 측정 기반 |
| **R-EVL-2** | 오염·커닝 감사를 상시 돌린다 | 커닝 시도 71건 중 63건이 flag 외부 복사, `nyuctf` 패키지 설치 사례 (B, **측정**) | 측정 기반 |
| **R-EVL-3** | 사다리 지표와 실패 원인 라벨을 함께 기록한다 | ExploitBench, SIABench 실패 5분류 (B) | 벤치마크 설계 |
| **R-EVL-4** | 설계 변경은 총 예산을 고정한 A/B로 판정한다 | 합집합 239는 총 연산량이 더 큰 조건의 값 (B, **측정**) | 이 시리즈의 원칙 |
| **R-EVL-5** | 오케스트레이션 변경의 1차 지표는 `consistency`·`cost_per_solve`·대회시간당 착지 수다. 해결률은 2차다 | 아키텍처 세 변형이 모두 19/30. 오른 것은 3/3 성공 12→16, 스텝 −24%, 비용 −34% (B, **측정**) | **측정 기반. 이 설계도의 평가 전제** |

**`R-EVL-5`를 빼면 나머지 53개를 다 구현하고도 실패했다고 결론 내립니다.** 원칙 6에 근거를 적었습니다. 그리고 이 요구사항은 반대 방향의 오용도 막습니다. **인식·지식 계층의 개선을 `consistency`로 평가하면 그쪽 이득이 안 보입니다.** 천장을 올리는 변경(`R-KNW-*`, 취약점 인식)은 해결률로, 처리량을 올리는 변경(`R-CON-*`, `R-BGT-*`)은 일관성과 비용으로 봅니다.

---

## 구현 단계

각 단계에 **완료 판정 기준**을 붙였습니다. 기준이 없으면 단계가 끝나지 않습니다.

**다음 실질적인 이정표는 1~4단계, 즉 재현 가능한 단일 문제 폐쇄루프입니다.** 처음부터 에이전트 열 명을 만들지 않습니다.

> **09와의 단계 번호 대응.** 아래는 이 문서의 1~8단계 번호이고, 구현 기준선은 09 §16의 Phase 0~7입니다. 대응은 다음과 같습니다.
>
> | 이 문서 | 09 |
> | --- | --- |
> | — | **Phase 0** 개발 기준선과 Doctor (새로 생김) |
> | 1단계 스키마 + 2단계 실행기·계측 | **Phase 1** 파일 상태와 구조화 결과 |
> | — | **Phase 2** Sandbox Broker와 Resource Broker (**두 번째 세션이 가능해지는 지점**) |
> | 3단계 단일 폐쇄루프 + Proof | **Phase 3** 단일 문제 폐루프 |
> | 4단계 Falsifier + 5단계 정체 감지 | **Phase 4** 역할 분리와 정체 복구 |
> | 6단계 카테고리 어댑터 | **Phase 5** 카테고리 Adapter |
> | 7단계 (구 Contest Scheduler) | **Phase 6** 보드와 제출 게이트 |
> | 8단계 자동 제출 + 학습 *(자동 제출 제안 폐기)* | **Phase 7** 평가 |

### 1단계 — 스키마

`R-OBS-1`, `R-ORC-9`, `R-ORC-10`, `R-CON-2`.

문제 상태와 `proof/result.json`을 JSON Schema로 확정합니다. 코드보다 스키마가 먼저인 이유는, 스키마가 곧 `--output-schema`의 입력이기 때문입니다. 09에서는 facts·hypotheses·experiments가 별도 파일이 아니라 **`state.json`의 필드**이므로, 확정할 것은 파일 목록이 아니라 그 필드들의 스키마입니다.

**완료 판정**: 각 스키마 파일이 있고, 손으로 만든 예시 레코드가 검증을 통과한다.

### 2단계 — 단계 실행기 + 계측

`R-CTX-1`, `R-BGT-7`, `R-EVL-3`.

`codex exec --json --output-schema` 기반 실행기입니다. **여기에 두 가지를 반드시 포함합니다.**

- **스키마 검증과 재호출 루프.** `--output-schema`가 요청 수준이므로 우리가 검증합니다. 이게 없으면 3·4단계가 조용히 깨집니다
- **이벤트 스트림 적재.** `--json`의 JSONL을 `runs/`에 그대로 저장합니다. 거부 로그와 토큰 사용량이 부산물로 나옵니다

**이것이 계측 전용 단계를 없앱니다.** 원래는 곡선 측정과 거부 계측을 맨 앞의 독립 단계로 두려 했지만, `turn.completed.usage`와 `turn.failed`가 이미 필요한 것을 다 줍니다. **계측은 단계가 아니라 실행기의 속성입니다.**

**완료 판정**: 임의 단계를 실행해 스키마 준수 JSON을 얻고, 같은 실행에서 토큰 사용량과 거부 건수를 조회할 수 있다.

### 3단계 — 단일 폐쇄루프

`R-CTX-2`, `R-CTX-3`, `R-ORC-1`, `R-ORC-5`, `R-ORC-8`.

OBSERVE → MODEL → HYPOTHESIZE → PLAN_EXPERIMENT → EXECUTE → EVALUATE → PROVE 한 바퀴입니다.

- 목표 단위 순차 처리와 `deps.json`
- 사다리 채점을 루프에 연결 (`R-CON-6`의 전제)
- Proof: 새 컨테이너, 원본 파일, `reproduce.sh` 단일 명령, 3회 이상

**완료 판정**: 한 문제를 처음부터 끝까지 돌려 `proof/`가 생성되고, **그 `reproduce.sh`가 새 컨테이너에서 통과한다.** 그리고 요약 계층 on/off로 컨텍스트 한계 오류 건수를 비교할 수 있다(`X-01`).

### 4단계 — 독립 Falsifier

`R-ORC-7`, `R-ORC-2`, `R-ORC-3`, `R-EVL-2`.

`.codex/agents/falsifier.toml`을 `sandbox_mode = "read-only"`로 두고 별개 thread에서 돌립니다.

- 디컴파일 결과를 사실로 가정했는지, 호출되지 않는 디코이를 분석했는지
- 산출물이 하드코딩된 단일 샘플만 통과하는지
- flag가 로컬 파일이나 이전 기록에서 유출된 것인지 (`flag_source` 분류)

**완료 판정**: 지난 세션 전체에 대해 `flag_source` 분포를 낼 수 있고, `file_read`·`external` 건이 성적 집계에서 제외된다. `X-19`로 독립 thread가 같은 세션보다 나은지 판정되어 있다.

### 5단계 — 정체 감지와 재개

`R-BGT-3`, `R-BGT-5`, `R-BGT-6`, `R-OBS-6`.

Governor의 중단 규칙과 `codex exec resume` 기반 재개입니다. `PreToolUse` 훅으로 명령 감사와 반복 탐지를 붙입니다.

**완료 판정**: 정체 상황에서 예산을 남기고 종료하며, 재개 시 이전 Blackboard를 이어받는다.

### 6단계 — 카테고리별 어댑터

`R-OBS-3`, `R-OBS-5`, `R-CTX-5`, `R-KNW-1`~`R-KNW-5`, `R-ENV-2`, `R-ENV-3`.

카테고리별 관측·검증 어댑터와 Librarian입니다. 근거가 약해지는 구간이므로 **기능을 켜기 전에 해당 실험을 먼저 돌립니다.**

**완료 판정**: `X-03`, `X-07`, `X-08`의 결과가 나와 있고 각 기능의 기본값이 그 결과로 정해져 있다.

### 7단계 — 보드와 제출 게이트

`R-CON-1`, `R-CON-3`, `R-CON-8`, `R-BGT-1`, `R-BGT-2`, `R-BGT-4`.

원래 이 단계의 이름은 "Contest Scheduler"였고 상태 기계, 전역 정찰, 예산 배분, 모델 라우팅을 담았습니다. **09에서 스케줄러 부분이 빠졌습니다.** 상태 기계는 3단계의 문제 계층으로 내려갔고, 예산 배분은 2단계의 자원 리스로 대체됐습니다. 남는 것은 **보는 것과 막는 것** 둘입니다 — 읽기 전용 보드와 제출 게이트.

**두 번째 세션을 열 수 있게 되는 시점도 이 단계가 아니라 2단계(샌드박스·리스 브로커)입니다.** 이것이 09에서 가장 크게 앞당겨진 항목입니다.

**완료 판정**: 세션을 여러 개 열어도 각 세션이 자기 문제에 대해 온전한
논리 폭(Captain 1 + worker 3)을 유지한다. 도구·GPU·원격 자원뿐 아니라
Batch provider call도 계정 상한에서 대기할 수 있지만 역할을 삭제하거나
wave를 줄이지 않는다. Live native subcall별 대기는 CTF-OS가 직접 강제하지
못한다. 보드는 다른 세션의 진행을 정확히 보여주고 그 진행을 방해하지
않으며, proof 없는 후보의 제출은 차단된다.

### 8단계 — 폐기된 자동 제출 초안과 대회 후 평가

`R-CON-7`, `R-CON-9`, `R-KNW-4`.

이 절의 자동 제출 부분은 현재 구현 계획이 아니다. 09의 Phase 7은 자동
제출 없이 L1/L2/L3 평가, fixed-budget 비교, 사람 제출 결과 감사와 지식
오염 검사를 수행한다.

**현재 완료 판정**: 사람의 accepted/rejected 결과가 대회 이력에 남고,
지식 증류 산출물에 flag나 문제 고유 상수가 없으며, 코드에는 CTF
사이트로 자동 제출하는 경로가 없다.

### 단계 배치의 근거

**계측을 1단계가 아니라 2단계에 넣은 것**이 원래 계획에서 바뀐 부분입니다. 예산 정책은 곡선 없이 짤 수 없지만, 곡선은 비교 가능한 실행이 있어야 측정됩니다. 즉 폐쇄루프가 먼저입니다. 그리고 `codex exec --json`이 계측을 거의 무료로 주므로 별도 단계로 둘 이유가 없습니다.

**대회 계층을 7단계로 미룬 것**도 의도적이었습니다. 스케줄러는 "이 문제를 계속할지 다른 문제로 갈지"를 판단해야 하고, 그 판단의 입력이 사다리 등급과 진전 마커입니다. 폐쇄루프가 그것들을 생산하기 전에 스케줄러를 만들면 판단 근거 없이 순서를 정하게 됩니다.

**09는 이 논리를 끝까지 밀어 결론을 바꿨습니다.** 판단 근거가 준비된 뒤에도 그 판단을 기계가 해야 할 이유가 없습니다. 사다리와 진전 마커를 보드에 띄우면 사람이 훨씬 적은 코드로 같은 판단을 합니다. 그래서 스케줄러는 미뤄진 것이 아니라 취소됐고, 대신 **자원 리스가 2단계로 앞당겨졌습니다.**

**Proof를 3단계에 넣은 것**은 미루기 쉬운 항목이라서입니다. Proof 없이 폐쇄루프를 "완성"하면 그 시점의 성적표가 신뢰할 수 없고, 원칙 4의 근거를 보면 성적의 30%가 의도하지 않은 경로일 수 있습니다. 3단계 완료 판정을 "새 컨테이너에서 `reproduce.sh` 통과"로 잡은 이유입니다.

---

## 이 설계도가 틀렸을 수 있는 지점

설계 문서가 자기 약점을 적지 않으면, 읽는 사람이 근거의 무게를 가늠할 수 없습니다.

**1. 근거의 절반 이상이 도메인 밖에서 왔습니다.** 가장 강한 인과 증거(요약 계층, multi-state)는 SIABench에서 나왔고, SIABench는 **CTF 포렌식이 아니라 SOC 보안사고 분석 벤치마크**입니다. 반증 루프의 근거인 Failing to Falsify는 숫자 규칙 과제입니다. Excalibur는 침투 테스트입니다. 구조적 유사성으로 전이했지만, 전이 폭은 측정되지 않았습니다.

**2. 표본이 작습니다.** 크립토의 핵심 실험은 9문제, 리버싱은 24문제에 문제당 최대 3회 시도, 웹은 30문제에 claude-code만 1회 실행입니다. 이 규모에서는 신뢰구간이 넓습니다.

**3. 등급 B가 지배적입니다.** A등급은 NDSS BAR 2026, NDSS 2026, ISSTA 2025, FSI:DI 넷뿐입니다. 나머지는 2026년 프리프린트이고, 후속 심사에서 수치가 바뀔 수 있습니다.

**4. 컴포넌트 열 개가 다 필요한지는 검증되지 않았습니다.** Second Look의 측정은 아키텍처를 정교하게 해도 **최대 성능은 안 올랐다**는 것이었습니다. 오른 것은 일관성과 비용이었습니다. 이 설계도가 그 함정에 빠지지 않는다는 보장은 없고, 컴포넌트를 일곱에서 열로 늘렸으므로 위험은 오히려 커졌습니다.

두 가지로 대응합니다. 원칙 6과 `R-EVL-5`로 **평가 지표를 일관성·비용·착지 수로 고정**했고, 컴포넌트별 ablation을 `X-17`로 등록했습니다. **효과가 확인되지 않은 컴포넌트는 제거 대상입니다.** 다만 `consistency`나 `cost_per_solve`만 개선하는 컴포넌트는 유지합니다 — Second Look에서 아키텍처가 실제로 기여한 것이 그 둘이었습니다.

**5. 실행 형태의 전제는 일부 해소됐습니다.** 원래 이 항목은 "인용한 연구들은 자체 에이전트 루프를 구현했지만 CTF-OS는 Codex CLI를 호출하므로, 프롬프트로 주입한 규약이 준수되는지 알 수 없다"였습니다.

검증 결과 두 가지가 이 전제를 바꿉니다. `--output-schema`는 단계 산출물의 형태를 고정하고(단 검증기는 우리가 붙여야 합니다), **`PreToolUse` 훅은 규약 위반 도구 호출을 차단하거나 재작성할 수 있습니다.** 즉 준수율을 측정해서 대응하는 게 아니라 강제할 수 있습니다.

**그래도 완전히 해소되지는 않았습니다.** 단계 *내부*의 추론은 여전히 우리가 통제하지 않고, 서브에이전트 spawn 시점은 부모 모델이 결정합니다. 그래서 `X-18`을 "프롬프트 주입의 준수율 측정"에서 **"훅 강제와 프롬프트 주입의 비교"**로 바꿨습니다.

**6. 대회 계층의 근거가 가장 얇았고, 그래서 09에서 대회 계층이 사라졌습니다.** `R-CON-*` 아홉 개 중 측정 기반은 네 개이고, 나머지는 운영 요구나 가설이었습니다. 특히 `R-CON-5`(순위 정책)는 Excalibur가 "난이도 추정 능력이 없다"고 측정한 것에서 **역으로 끌어낸 회피 설계**였습니다. 관측 프록시가 모델 추정보다 나을 것이라는 근거는 없었고, 근거 없는 설계를 실험으로 정당화하려 하는 대신 **만들지 않기로** 했습니다. 이것이 이 설계도에서 09가 뒤집은 가장 큰 항목입니다.

---

## 관련 문서

- [시리즈 개요](00-series-index.md) — 인용 규칙, 출처 등급, 카테고리 교차 비교
- [1. 포너블 편](01-pwn.md) · [2. 리버싱 편](02-reversing.md) · [3. 크립토 편](03-crypto.md) · [4. 포렌식 편](04-forensics.md) · [5. 웹 편](05-web.md)
- [실험 백로그](07-experiment-backlog.md) — 이 문서의 모든 [가설]을 A/B 실험으로 변환한 것
- [출처 검증 기록](08-verification-log.md) — 참고문헌 실재성·수치 대조 결과
- [이전 보고서에서 수정한 것](99-corrections.md)

---

← [웹 편](05-web.md) | [시리즈 개요](00-series-index.md) | 다음 → [실험 백로그](07-experiment-backlog.md)
