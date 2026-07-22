# CTF-OS

CTF-OS는 허가된 CTF를 위한 단일 문제 중심의 Sol 네이티브 선착순 플래그
환경입니다. 문제와 시도 간 격리, 읽기 전용 입력, 카테고리별 샌드박스,
명시된 대상 범위, 프로세스/GPU 자원, 수동 제출, 수동 Claude 인계를
보장합니다.

```text
선택한 문제 준비
→ Root Sol xhigh가 즉시 공격
→ 선택적으로 Sol/Terra/Luna 네이티브 워커 0–3개 사용
→ 실제 명령, 산출물, 공격 변형 수행
→ 명시된 원격 대상 공격
→ 대상 출력에서 첫 유효 플래그 확인
→ 동료 워커 취소 후 사람이 제출
```

활성 Solve 엔진은 하나뿐입니다. 선택한 문제는 플래그를 찾거나,
90분 제한에 도달하거나, Claude에게 인계할 때까지 머신과 세션을
독점합니다.

## 설치

```bash
uv sync --frozen
uv run python -m ctf_os.agent_tools doctor
```

카테고리별 이미지는 `bash sandbox/build-images.sh`로 빌드합니다.

## Solve 흐름

필요하면 대회 작업 공간을 초기화한 다음, 선택한 문제만 준비합니다.

```bash
uv run python -m ctf_os.agent_tools init-contest 'My CTF 2026'
uv run python -m ctf_os.agent_tools prepare-challenge 'web/Challenge' --contest 'My CTF 2026'
```

준비 결과로 직접 공격에 사용할 컨텍스트가 반환되며, 워커는 생성되지
않습니다. Root는 즉시 직접 공격을 시작합니다. 필요하면 Root가 선택적
패킷 하나를 생성합니다.

```bash
uv run python -m ctf_os.agent_tools worker-spawn-packet 'web/Challenge' \
  --contest 'My CTF 2026' --model-profile terra-high --role builder \
  --context-mode directed --task 'Turn the current request path into remote exploit.py'
```

프로파일은 새 공격 기법에 `sol-xhigh`, 실행 가능한 산출물에
`terra-high`, 범위가 제한된 기계적 작업에 `luna-high`를 사용합니다.
패킷 자체는 모델을 시작하지 않습니다. Root는 `spawn_agent_args`를
`fork_turns="none"`과 함께 네이티브 `spawn_agent`에 전달한 다음,
반환된 식별자를 기록합니다.

```bash
uv run python -m ctf_os.agent_tools worker-spawn-confirm 'web/Challenge' \
  --contest 'My CTF 2026' --lane terra-1 --native-session '<thread-id>'
```

실제 네이티브 식별자가 있어야만 `RUNNING`입니다. Root와 최대 3개의
네이티브 자식을 합쳐 동시 실행 모델을 4개로 유지합니다. 워커는 기존
자원과 서비스 기반을 공유하면서도 각자의 전용 쓰기 경로를 유지합니다.

## 이벤트와 워커 교체

`SWARM.json`은 시도와 워커 상태를 간결하게 보관하고, `ATTACK_EVENTS.jsonl`은
실행 후의 사실을 보관합니다. `attack-event`는 실제 명령, 산출물, 프리미티브,
PoC, 원격 결과, 유용한 실패, 방해 요인, 후보를 기록합니다. 실행이 기록보다
먼저이므로, 이벤트 기록 실패가 이미 완료된 명령을 무효로 만들지 않습니다.

`worker-status`는 실제 출력 이력을 간결하게 보여줍니다. Root는 워커를 유지할지
중지할지 판단하며, 다른 프로파일·역할·작업과 새 컨텍스트 또는 지정된
컨텍스트로 `worker-replace`를 호출할 수 있습니다. Python은 역할의 품질을
평가하지 않습니다.

60분이 지난 뒤에는 `worker-endgame`이 자격을 갖춘 워커 하나를
`ctf_sol_max`로 교체할 수 있습니다. 자격을 갖추려면 실행 가능한 부분 경로,
실제 공격 출력 2건, 환경과 무관한 명확한 추론 장애물, 구체적인 다음 공격이
필요합니다. 할당 시간은 10분 또는 공격 2회입니다. 90분 제한에 도달하면
`artifacts/TIMEOUT_HANDOFF.md`를 작성하고 취소 대상을 반환하며, 시간을
연장하지 않습니다.

## 플래그와 격리

사용 가능한 페이로드나 의미 있는 로컬 응답을 확보하면 명시된 원격 대상을
공격할 수 있습니다. `flag-found`는 정확히 실행한 명령과 함께 실제 대상
출력에 나타난 후보 중, 형식이 유효하고 플레이스홀더가 아닌 것만
받아들입니다. 가장 먼저 발견된 플래그를 승자로 선택하고 취소할 네이티브
동료 워커 목록을 반환합니다. CTF-OS는 절대 자동 제출하지 않으며,
`submission-result`는 사람이 남긴 `wrong` 또는 `accepted` 피드백을
기록합니다.

- 새 시도는 이전의 산출물, 캐시, 네이티브 식별자, 샌드박스, 서비스,
  솔버 상태를 상속하지 않습니다.
- 입력은 읽기 전용이며, 각 워커는 자신의 전용 `work`, `evidence`,
  `artifacts` 경로에만 쓸 수 있습니다.
- 샌드박스는 주최 측이 명시한 대상 범위를 강제하고 호스트와 비공개 데이터에
  대한 접근을 차단합니다.
- 공유 서비스와 전역 자원은 Root만 변경할 수 있습니다.

전체 대회 Intake와 Triage는 명시적으로 요청받을 때만 실행하며 Solve에
영향을 주지 않습니다. “클로드 구조대 준비해라”라는 명령을 받으면 공격을 멈추고
인계 스킬을 사용해 근거가 포함된
`rescue/<contest>/<challenge>/HANDOFF.md` 하나를 작성합니다.
