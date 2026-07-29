# 출처 검증 기록

**검증일: 2026-07-27 (Asia/Seoul)**

이 시리즈는 2026년 프리프린트에 크게 의존합니다. 그리고 [엔진 설계도](06-engine-blueprint.md)는 그 프리프린트의 수치를 구현 우선순위의 근거로 씁니다. 근거가 틀리면 설계가 틀립니다.

그래서 이 문서는 **참고문헌 37건 전부에 대해 실재성과 수치를 직접 대조한 기록**입니다. 저장소의 `ctf-os-image/VERSIONS.md`가 도구 버전에 대해 하는 일을, 이 문서가 참고문헌에 대해 합니다.

그리고 설계도는 논문 수치 외에 하나를 더 전제합니다. **Codex CLI가 실제로 무엇을 제공하는가.** 이건 직접 확인할 수 있으므로 확인했고, 그 결과가 설계 결정 네 개를 바꿨습니다.

## 목차

- [검증 방법](#검증-방법)
- [arXiv 16건](#arxiv-16건)
- [수치 대조](#수치-대조)
- [비arXiv 21건](#비arxiv-21건)
- [발견된 불일치와 수정](#발견된-불일치와-수정)
- [Codex CLI 기능 검증](#codex-cli-기능-검증)
- [접근 제약](#접근-제약)
- [여전히 검증되지 않은 것](#여전히-검증되지-않은-것)

---

## 검증 방법

| 대상 | 방법 | 확인 항목 |
| --- | --- | --- |
| arXiv | `arxiv.org/abs/<id>` HTML의 `citation_title`·`citation_author`·`citation_date`·`citation_online_date` 메타태그 추출 | 논문 실재, 제목 일치, 저자, 게시일 |
| arXiv 수치 | 같은 페이지의 초록 원문과 보고서 본문 수치 대조 | 인용된 숫자가 초록에 실제로 있는가 |
| PDF 직접 공개 | PDF 본문 파싱 | 초록에 없는 표·본문 수치 |
| DOI 기반 (ACM, Springer, ScienceDirect) | Crossref로 제목·저널·권·발행일 조회 | 봇 차단(403)을 우회한 서지 확인 |
| GitHub | `api.github.com/repos/{owner}/{repo}` | 저장소 실재, 설명, 스타 수 |
| 블로그·MCP 마켓 | 직접 fetch, 실패 시 검색 인덱스·API 교차 확인 | 문서 실재, 제목 일치 |

**중요한 제약을 먼저 적습니다.** arXiv 초록에 없는 수치(본문 표에서 온 값)는 PDF를 직접 파싱한 두 건(NDSS BAR 2026, Decompiling the Synergy)을 제외하면 **초록·프로젝트 페이지·기존 검증 결과로 교차 확인한 2차 확인**입니다. 이 구분은 [여전히 검증되지 않은 것](#여전히-검증되지-않은-것)에 다시 적었습니다.

---

## arXiv 16건

**16건 전부 실재하며 제목이 정확히 일치합니다.** 검증 시점의 메타데이터입니다.

| arXiv ID | 게시일 | 제목 | 제1저자 | 인용 위치 |
| --- | --- | --- | --- | --- |
| 2503.17332 | 2025-03-21 | CVE-Bench: A Benchmark for AI Agents' Ability to Exploit Real-World Web Application Vulnerabilities | Yuxuan Zhu | 웹 |
| 2505.16366 | 2025-05-22 | ReCopilot: Reverse Engineering Copilot in Binary Analysis | Guoqiang Chen | 리버싱 |
| 2507.09580 | 2025-07-13 | AICrypto: Evaluating Cryptography Capabilities of Large Language Models | Yu Wang | 크립토 |
| 2508.20816 | 2025-08-28 | Multi-Agent Penetration Testing AI for the Web | Isaac David | 웹 |
| 2601.09129 | 2026-01-14 | KryptoPilot: An Open-World Knowledge-Augmented LLM Agent for Automated Cryptographic Exploitation | Xiaonan Liu | 크립토 |
| 2602.17622 | 2026-02-19 | What Makes a Good LLM Agent for Real-world Penetration Testing? | Gelei Deng | 포너블·웹 |
| 2603.06422 | 2026-03-06 | Before You Hand Over the Wheel: Evaluating LLMs for Security Incident Analysis | Sourov Jajodia | 포렌식·웹 |
| 2603.22577 | 2026-03-23 | STRIATUM-CTF: A Protocol-Driven Agentic Framework for General-Purpose CTF Solving | James Hugglestone | 포너블 |
| 2604.02485 | 2026-04-02 | Failing to Falsify: Evaluating and Mitigating Confirmation Bias in Language Models | Ayush Rajesh Jhaveri | 리버싱 |
| 2604.03750 | 2026-04-04 | CREBench: Evaluating Large Language Models in Cryptographic Binary Reverse Engineering | Baicheng Chen | 리버싱·크립토 |
| 2605.10597 | 2026-05-11 | CrackMeBench: Binary Reverse Engineering for Agents | Isaac David | 리버싱 |
| 2605.11086 | 2026-05-11 | ExploitGym: Can AI Agents Turn Security Vulnerabilities into Real Attacks? | Zhun Wang | 포너블 |
| 2605.11504 | 2026-05-12 | CTFusion: A CTF-based Benchmark for LLM Agent Evaluation | Dongjun Lee | 개요·포렌식 |
| 2605.14153 | 2026-05-13 | ExploitBench: A Capability Ladder Benchmark for LLM Cybersecurity Agents | Seunghyun Lee | 포너블 |
| 2605.21497 | 2026-04-29 | Autonomous LLM Agents & CTFs: A Second Look | Youness Bouchari | 웹 |
| 2607.02605 | 2026-07-01 | A Survey of LLM-Driven Penetration Testing: Taxonomy, Co-Evolution, and Open Challenges | Zheyuan He | 웹 |

**2605.21497의 ID와 게시일이 어긋나 보이는 것에 대해**: 제출은 2026-04-29이고 ID 접두어는 2605입니다. arXiv ID 접두어는 제출월이 아니라 공개 공지월을 따르므로, 4월 말 제출 → 5월 초 공지는 정상입니다. 오기가 아닙니다.

---

## 수치 대조

보고서가 인용한 수치를 초록 원문과 대조했습니다. **초록에 명시된 값은 전부 일치합니다.**

| 인용된 수치 | 초록 원문 | 판정 |
| --- | --- | --- |
| ExploitGym 898문제 | *comprises 898 instances* | 일치 |
| ExploitGym Mythos Preview 157 / GPT-5.5 120 | *produce working exploits for 157 and 120 instances* | 일치 |
| CrackMeBench pass@3 11/12·7/12·5/12 | *11/12 tasks (92%) for GPT-5.5, 7/12 (58%) for Claude Opus 4.7, and 5/12 (42%) for Kimi K2* | 일치 |
| CrackMeBench 어려운 절반 5/6·2/6·1/6, 공개 8문제 3/8·2/8·1/8 | 초록에 동일하게 명시 | 일치 |
| CrackMeBench 5분 예산, 3회 채점 제출 | *five-minute budget and three scored submissions per task* | 일치 |
| CREBench 432문제, 48알고리즘, 3시나리오, 3난이도 | 초록에 동일하게 명시 | 일치 |
| CREBench GPT-5.4 64.03 / flag 59% / 인간 92.19 | *achieves 64.03 out of 100 and recovers the flag in 59% ... human expert baseline of 92.19* | 일치 |
| KryptoPilot NYU-CTF 56~60%, 실전 26/33 | *solves between 56 and 60 percent ... 26 out of 33* | 일치 |
| KryptoPilot InterCode-CTF 18/18 | *achieves a complete solve rate on InterCode-CTF* | 일치 (초록은 문항 수를 명시하지 않음) |
| Excalibur 최대 91%, 상대 39~49%, GOAD 4/5 vs 2 | *up to 91% task completion ... (39 to 49% relative improvement) ... 4 of 5 hosts ... versus 2* | 일치 |
| Excalibur 난이도 4축 | *horizon estimation, evidence confidence, context load, and historical success* | 일치 |
| Second Look 30문제·14클래스, claude-code 19/30 | *30 web-based CTFs challenges spanning 14 vulnerability classes ... (19/30 solved tasks)* | 일치 |
| CTFusion 3모델·2에이전트·5 Live CTF | *three LLMs, two agents, and five Live CTFs* | 일치 |
| STRIATUM-CTF 1위, 21개 인간 팀 | *secured First Place, outperforming 21 human teams* | 일치 |
| SIABench 25 시나리오 | *deep analysis workflows for security incidents (25 scenarios)* | 일치 |
| ExploitBench 16 flag | *decomposes exploitation into 16 measurable flags* | 일치 |
| CVE-Bench 최대 13% | 기존 검증에서 *resolve up to 13% of vulnerabilities* 확인 | 일치 |

초록에 없어 PDF 본문에서 직접 확인한 값은 다음입니다.

| 인용된 수치 | 확인 방법 | 판정 |
| --- | --- | --- |
| NDSS BAR 2026: 디컴파일러 있음 CC 15/24·CX 14/24, 없음 CC 17/24·CX 14/24, CG 19/24 | PDF 본문 | 일치 |
| NDSS BAR 2026: 24문제 중 20문제 동일, 갈린 4문제 중 3문제(#11·#21·#23)가 디컴파일러 제거 후에만 해결 | PDF 본문 | 일치 |
| NDSS BAR 2026: task #15 인간 2.1%, task #12 인간 3.5% | PDF 본문 | 일치 |
| NDSS BAR 2026: W1–W4, M1–M3, S1–S3 분류 | PDF 본문 | 일치 |
| Decompiling the Synergy: 전문가 24명·초보자 24명, 6,586분, 1,517회 LLM 상호작용 | PDF 본문 | 일치 |

---

## 비arXiv 21건

| 출처 | 상태 | 확인된 서지 |
| --- | --- | --- |
| NDSS BAR 2026 PDF (Towards LLM-Resistant Software Protection) | **실재** | Ryutaro Nishizaka, Yudai Fujiwara, Takuya Shimizu, Kazushi Kato, Yuichi Sugiyama (Ricerca Security). Workshop on Binary Analysis Research (BAR) 2026, ISBN 978-1-970672-08-4 |
| NDSS 2026 PDF (Decompiling the Synergy) | **실재** | Basque, Doria, Soneji, Gibbs, Doupé, Shoshitaishvili, Losiouk, Wang, Aonzo (ASU / Padua / EURECOM). DOI 10.14722/ndss.2026.240380 |
| ACM DOI 10.1145/3728958 (DecLLM) | **403, Crossref로 확인** | Proc. ACM on Software Engineering vol. 2, ISSTA issue, 2025-06-22 |
| Springer 10.1007/978-981-95-4367-0_2 | **SSO 리다이렉트, Crossref로 확인** | "DFIR-Metric: A Benchmark Dataset for Evaluating Large Language Models in Digital Forensics and Incident Response", LNCS *Neural Information Processing* (ICONIP), pp. 17–31, 2025-11-22 |
| ScienceDirect S2666281725001830 | **403, Crossref로 확인** | "Large language models in digital forensics: capabilities, challenges and future directions", *Forensic Science International: Digital Investigation* vol. 56, DOI 10.1016/j.fsidi.2025.302043 |
| Black Hat USA 2025 세션 | **403, 2개 독립 경로로 확인** | "Pay Attention to the Clue: Clue-Driven Reverse Engineering by LLM in Real-World Malware Analysis" — CyCraft 자체 세미나 페이지와 Celebi-POC README에서 확인 |
| Claw-Stack 블로그 (BearcatCTF 2026) | **실재** | "24 Hours, 40 Challenges: How an AI Team Placed Top 6% at BearcatCTF 2026" |
| Toss Tech Blog | **실재** | "LLM을 이용한 서비스 취약점 분석 자동화 #2" |
| cybergym.io/exploitgym | **실재** | ExploitGym 프로젝트 페이지 |
| glama.ai PWN-MCP | **504, API로 확인** | "PWN-MCP by Aiyakami". `Aiyakami/PWN-MCP` 저장소도 실재 |
| mcpmarket.com pwndbg | **429 (사이트 전체 차단), 검색 인덱스로 확인** | "Pwndbg: AI Agent ELF Debugging for CTF Pwn Challenges" |

### GitHub 저장소 10건 — 전부 실재

스타 수는 D등급 자료의 무게를 가늠하는 참고값입니다. **성능 근거가 아닙니다.**

| 저장소 | 스타 | 설명 |
| --- | --- | --- |
| bethington/ghidra-mcp | 2,970 | Ghidra MCP 서버, 200+ MCP 도구 |
| ljagiello/ctf-skills | 2,834 | web/pwn/crypto/rev/forensics/OSINT용 Agent skill 모음 |
| amruth-sn/kong | 1,070 | 에이전틱 리버스 엔지니어 |
| buzzer-re/Rikugan | 666 | IDA Pro·Binary Ninja용 리버싱 에이전트 |
| radareorg/r2ai | 460 | radare2용 LLM 리버싱 |
| XingTuLab/recopilot | 65 | ReCopilot 구현 |
| 19h/ida-semray | 26 | IDA Pro 디컴파일러용 시맨틱 분석 |
| cycraft-corp/Celebi-POC | 16 | Black Hat USA 2025 발표의 evaluation 단계 PoC |
| wangyu-ovo/CREBench | 8 | CREBench 코드·데이터셋 |
| SmartData-Polito/CTF_agent | 8 | Second Look의 다전략 CTF 프레임워크 |

---

## 발견된 불일치와 수정

검증에서 나온 문제는 네 건입니다. 전부 수정했습니다. **논문의 실재성이나 핵심 수치에서 발견된 오류는 없었습니다.**

### 1. DecLLM의 70%는 평균이 아니라 상한

- **이전 표현**: "기존에는 재컴파일할 수 없던 결과의 약 70%를 복원했으며"
- **원문**: 약 70%는 **상한(upper bound)**입니다. 원래 재컴파일 불가였던 출력 100개 중 70개가 재컴파일 가능해졌다는 서술이며, **GPT-3.5와 GPT-4로 달성한 값**입니다
- **수정**: 상한임과 사용 모델을 명시했습니다. 리버싱 편 [6] 인용부

70%를 전형적 결과로 읽으면 이 방법의 성능을 과대평가합니다. 그리고 2025년의 GPT-3.5/GPT-4 기준값이므로 최신 모델에서의 값은 별개입니다.

### 2. ExploitBench의 규모와 핵심 발견이 누락

- **이전 서술**: "익스플로잇을 coverage → triggering → in-cage 등 5단계 16개 flag로 쪼개어 채점하는 벤치마크"
- **누락된 것**: 41개 V8 버그에 인스턴스화됐다는 조건, 그리고 **공개 배포 프론티어 모델 8개는 취약 코드 도달과 크래시는 일상적으로 해내지만 임의 코드 실행은 그렇지 못하고, 비공개 모델은 약 절반에서 임의 코드 실행을 보였다**는 결과
- **수정**: 포너블 편에 조건과 결과를 추가했습니다

이 결과가 누락되면 안 되는 이유는, 사다리 채점의 가치가 정확히 이 지점에서 나오기 때문입니다. "크래시는 되는데 ACE는 안 된다"는 진단은 이진 채점으로는 얻을 수 없습니다.

### 3. SIABench의 두 번째 과제군이 누락

- **이전 서술**: "25개 시나리오 229개 조사 질문"
- **원문**: 심층 분석 워크플로우 **25 시나리오**와 경보 트리아지 **135 시나리오**의 두 과제군이며, **11개 LLM**을 평가했습니다. 229라는 질문 수는 초록에 없습니다
- **수정**: 과제군 구성과 평가 모델 수를 명시하고, 질문 수는 초록 미확인 값으로 표시했습니다

### 4. BearcatCTF 커닝 사례의 문제명과 감사 라벨이 누락

- **이전 서술**: "pwn 문제 하나에서 에이전트가 실제 익스플로잇 대신 챌린지 디렉터리의 `README.md`에 있던 flag를 읽어온 사례"
- **원문**: 문제명은 **CryptoPwn**이고, 감사가 이를 `CHEATED`로 라벨링한 뒤 재풀이하게 했습니다
- **수정**: 문제명과 감사 라벨을 명시했습니다. **감사가 잡아냈다는 사실이 이 사례의 핵심**이므로, 라벨이 남았다는 것을 적는 것이 더 정확합니다

### 5. ExploitGym 문제 수의 출처 간 불일치 (미해결)

논문 초록은 **898 instances**, 프로젝트 페이지(cybergym.io/exploitgym)는 **869 tasks**로 표시합니다. 보고서는 논문 값 898을 씁니다.

**어느 쪽이 최신인지 확인하지 못했습니다.** 프로젝트 페이지가 개정된 집합을 반영한 것일 수도 있고, 논문 초록이 최종 값일 수도 있습니다. 도메인별 내역(userspace 520 / V8 185 / kernel 193 = 898)은 논문 값과 정합합니다. 이 불일치를 포너블 편에 각주로 남겼습니다.

---

## Codex CLI 기능 검증

**검증 방법**: 로컬에 설치된 `codex-cli 0.145.0`의 `--help` 출력과 `codex features list`를 직접 확인하고, 공식 매뉴얼(`learn.chatgpt.com` 문서 캐시)과 대조했습니다. **문서만 보지 않고 실제 바이너리의 플래그를 확인한 것이 중요합니다** — 문서와 설치된 버전이 어긋날 수 있습니다.

### 확인된 기능

| 기능 | 상태 | 실제 형태 |
| --- | --- | --- |
| 비대화식 실행 | **있음** | `codex exec [PROMPT]` (별칭 `codex e`). 프롬프트를 stdin으로도 받음 |
| 이벤트 스트림 | **있음** | `--json` → JSONL. 이벤트: `thread.started`, `turn.started`, `turn.completed`, `turn.failed`, `item.*`, `error`. item 종류: agent message, reasoning, command execution, file change, MCP tool call, web search, plan update |
| 토큰 사용량 | **있음** | `turn.completed`의 `usage`: `input_tokens`, `cached_input_tokens`, `output_tokens`, `reasoning_output_tokens` |
| 최종 응답 스키마 | **있음 (요청 수준)** | `--output-schema <FILE>` |
| 최종 응답 파일 저장 | **있음** | `-o` / `--output-last-message <FILE>` |
| 세션 재개 | **있음** | `codex exec resume --last` 또는 `codex exec resume <SESSION_ID>` |
| 커스텀 역할 에이전트 | **있음** | `~/.codex/agents/*.toml` 또는 `.codex/agents/*.toml`. 필수 `name`·`description`·`developer_instructions`. 추가 가능: `model`, `model_reasoning_effort`, `sandbox_mode`, `mcp_servers`, `skills.config` |
| 내장 에이전트 | **있음** | `default`, `worker`, `explorer` |
| 동시 실행 상한 | **있음** | `[agents] max_concurrent_threads_per_session` (레거시 별칭 `agents.max_threads`) |
| 훅 | **있음 (stable)** | `~/.codex/hooks.json`, `<project>/.codex/hooks.json`, 또는 config.toml의 `[[hooks.PreToolUse]]` 형식 |
| 훅 이벤트 | **있음** | `SessionStart`, `SessionEnd`(메인 스레드만), `SubagentStart`, `SubagentStop`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `Stop` |
| 도구 호출 차단 | **있음** | `PreToolUse` 훅이 호출을 **차단하거나 재작성** 가능 |
| 샌드박스 제어 | **있음** | `-s` / `--sandbox {read-only, workspace-write, danger-full-access}`, `--add-dir`, `--ephemeral`, `--dangerously-bypass-approvals-and-sandbox` |
| 모델·프로필 제어 | **있음** | `-m` / `--model`, `-p` / `--profile`, `model_reasoning_effort`, `-c key=value` |
| 불변 규칙 주입 | **있음** | `AGENTS.md` |
| **토큰·비용 상한** | **없음** | `codex features list`에서 `token_budget`, `rollout_budget`이 `under development / false` |

이 표의 “없음”은 Codex CLI 자체의 native token/cost cap에 한정된다.
현재 CTF-OS의 문제별 8시간 deadline과 Batch provider 동시성 FIFO 상한은
호스트 오케스트레이터가 별도로 집행한다.

### 중요한 단서 네 개

**1. `--output-schema`는 "요청"입니다.** 매뉴얼 문구가 *use `--output-schema` to **request** a final response that conforms to a JSON Schema*입니다. 검증하고 재시도한다는 서술이 없습니다. **따라서 스키마 검증과 재호출은 오케스트레이터가 직접 구현해야 합니다.** 예시 스키마는 `additionalProperties: false`와 `required`를 씁니다.

**2. 서브에이전트 spawn은 부모 모델이 결정합니다.** `.codex/agents/*.toml`은 역할 *정의*를 제공하지만, 매뉴얼은 일관되게 *Ask Codex to delegate* 형태로 서술합니다. 호스트에서 특정 서브에이전트를 결정적으로 호출하는 인터페이스는 문서화되지 않았습니다. 따라서 **단계 간 결정적 제어 흐름은 별개 `codex exec` 호출로 만들어야 하고**, `.codex/agents/`는 한 단계 안에서의 병렬 탐색에 씁니다.

**3. 훅은 동시 실행되며 서로를 막지 못합니다.** 매뉴얼: *Multiple matching command hooks for the same event are launched concurrently, so one hook can't prevent another matching hook from starting.* 그리고 비관리 훅은 검토·신뢰 등록이 필요합니다. 자동화에서는 `--dangerously-bypass-hook-trust`를 쓰거나 `requirements.toml`의 관리 훅으로 배포합니다.

**4. `codex features list`가 기능 성숙도를 알려줍니다.** `stable` / `experimental` / `under development` / `deprecated` / `removed`로 표시됩니다. 설계에서 참조한 것 중 `hooks`, `multi_agent`, `plugins`, `shell_tool`, `unified_exec`는 `stable`이고, `token_budget`과 `rollout_budget`은 `under development`입니다.

### 이 검증이 바꾼 설계 결정

| 검증 결과 | 설계 변경 |
| --- | --- |
| `--output-schema`가 요청 수준 | 구현 2단계에 **스키마 검증기와 재호출 루프**를 필수로 포함 |
| `PreToolUse`가 차단 가능 | `X-18`을 "프롬프트 준수율 측정"에서 **"훅 강제 vs 프롬프트 주입 비교"**로 변경. 설계도의 가장 취약한 전제가 부분 해소됨 |
| 토큰 상한 없음 | 예산 집행을 `turn.completed.usage` 누적으로 구현. **부수 효과로 거부 로그(`R-BGT-7`)와 비용 곡선(`R-BGT-1`)이 같은 스트림에서 나오므로 계측이 별도 단계에서 사라짐** |
| `sandbox_mode`를 에이전트별 지정 가능 | Falsifier를 `read-only`로 두어 **판정과 수정의 분리를 샌드박스 속성으로** 만듦 (`R-ORC-7`). 병렬 쓰기 충돌 방지도 설정으로 해결 (`R-ENV-7`) |

**한 가지 정정.** 이 검증 이전에 `.codex/agents/*.toml`이 존재하지 않는다고 판단할 뻔했습니다. 매뉴얼의 서브에이전트 절만 읽으면 "모델이 알아서 delegate한다"로 보여 선언적 정의가 없는 것처럼 읽힙니다. 실제로는 별도 절에 커스텀 에이전트 파일 스키마가 있습니다. **부정을 주장하기 전에 한 번 더 확인해야 한다는 사례로 남겨둡니다.**

---

## 접근 제약

다음 출처는 직접 읽지 못하고 우회 경로로 확인했습니다. 명시해 둡니다.

| 출처 | 응답 | 우회 경로 |
| --- | --- | --- |
| dl.acm.org | 403 (Cloudflare) | Crossref |
| sciencedirect.com | 403 | Crossref |
| link.springer.com | SSO 리다이렉트 | Crossref |
| blackhat.com | 403 | CyCraft 세미나 페이지 + Celebi-POC README |
| glama.ai | 504 (3회 재시도) | glama JSON API |
| mcpmarket.com | 429 (홈페이지도 차단) | 검색 인덱스 제목만 |
| arXiv API (`export.arxiv.org`) | 503 | `arxiv.org/abs/` HTML 메타태그 |

**mcpmarket.com 항목의 확인 수준이 가장 낮습니다.** 제목만 검색 인덱스로 확인했고 페이지 내용을 읽지 못했습니다. D등급 자료이며 성능 근거로 쓰지 않으므로 이 시리즈의 결론에는 영향이 없지만, 확인 수준의 차이를 기록해 둡니다.

---

## 여전히 검증되지 않은 것

1. **본문 표 수치의 상당 부분이 2차 확인입니다.** PDF 본문을 직접 파싱한 것은 NDSS BAR 2026과 Decompiling the Synergy 두 건입니다. ExploitGym의 완화 기법 재실행 결과(userspace 37 / V8 20 / kernel 12), 시간-성공 곡선, flag 대비 실제 성공 비율(226→157, 210→120), KryptoPilot의 ablation 표(56%→50%, 30초→169초), SIABench의 ablation 값(45.9%→70.0%, CLE 건수), Second Look의 일관성 표(12→14→16)는 초록과 기존 검증 결과로 교차 확인했으며 **본문 표를 재추출하지는 않았습니다.**

2. **등급 B가 지배적입니다.** A등급은 NDSS BAR 2026, NDSS 2026, ISSTA 2025, FSI:DI 넷뿐이고 나머지는 심사 전 프리프린트입니다. 후속 심사에서 수치가 바뀔 수 있습니다.

3. **C·D등급으로는 성능 주장을 하지 않았습니다.** BearcatCTF 기록, PWN-MCP, pwndbg MCP, Ghidra MCP, ctf-skills, Kong, Rikugan, r2ai, ida-semray, Celebi-POC는 존재와 주장된 기능까지만 인정했습니다. 스타 수를 적은 것도 참고값이며 성능과 무관합니다.

4. **다음 검증 주기가 정해져 있지 않습니다.** 프리프린트가 심사를 통과하면 수치와 저자 목록이 바뀝니다. 최소한 [실험 백로그](07-experiment-backlog.md)의 실험을 돌리기 직전에 해당 실험의 원 근거를 재확인해야 합니다.

---

## 관련 문서

- [시리즈 개요](00-series-index.md) — 인용 규칙과 출처 등급의 정의
- [엔진 설계도](06-engine-blueprint.md) — 이 수치들이 근거로 쓰이는 곳
- [실험 백로그](07-experiment-backlog.md) — 원 근거를 우리 환경에서 재현하는 계획
- [이전 보고서에서 수정한 것](99-corrections.md) — 이전 라운드의 정정 내역

---

← [실험 백로그](07-experiment-backlog.md) | [시리즈 개요](00-series-index.md)
