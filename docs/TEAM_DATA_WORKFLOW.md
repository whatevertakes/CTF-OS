# 팀 데이터 워크플로

이 저장소의 목표는 Level 3 agent 설계에 사용할 수 있는 비교 가능한 CTF 풀이
데이터를 모으는 것입니다. 팀원은 프레임워크 변경이 아니라 정제된 챌린지
데이터를 제출합니다.

## 브랜치

`main`은 소유자 `jiwoongchoi-norun`만 push합니다. 팀원은 자기 이름의 고정
브랜치에만 commit/push합니다.

```text
shyunseok1029
holymo-ly
lee
```

처음 클론한 뒤 자기 브랜치를 체크아웃합니다.

```bash
git fetch origin
git switch --track origin/<github-user>
tools/team_member_setup.sh
```

`main` 업데이트를 자기 브랜치에 반영하려면 다음을 실행합니다.

```bash
git fetch origin
git switch <github-user>
git merge origin/main
```

승인된 blindtest 데이터 파일만 commit합니다.

```text
challenges/blindtest/<category>/<challenge>/state.json
challenges/blindtest/<category>/<challenge>/notes.md
challenges/blindtest/<category>/<challenge>/replay.sh
challenges/blindtest/<category>/<challenge>/evidence/*
challenges/blindtest/<category>/<challenge>/work/*
```

raw flag, raw replay log, private key, `.env` 파일, challenge `work/` scratch
dependency checkout, 프레임워크 파일은 commit하지 않습니다.

## 정제 데이터 계약

제출되는 `state.json`은 현재 템플릿 형태를 유지해야 합니다. 특히 다음 필드는
terminal 상태(`solved`, `blocked`, `partial`)에서 필수입니다.

```text
blocker.reason
blocker.next_action
metadata.proof_scope
metadata.remote_status
metadata.remote_solve
metadata.replay_kind
metadata.current_remote_liveness
metadata.evidence_sensitivity
metadata.last_replay
metadata.agent_mode
metadata.failure_class
metadata.replay_quality
metadata.shareability
metadata.tool_effectiveness
tool_routing.primary_tools_used
tool_routing.considered
tool_routing.used
tool_routing.skipped
tool_routing.missing
tool_routing.decision_summary
```

일반 Codex-assisted 풀이의 `metadata.agent_mode`는 `assisted`입니다. solved
상태는 `metadata.failure_class`를 `none`으로 둡니다. blocked 또는 partial
상태는 `docs/FAILURE_TAXONOMY.md`에서 가장 좁은 실패 분류를 선택합니다.

`notes.md`는 다음 `##` heading을 포함해야 합니다.

```text
## Summary
## Artifacts
## Observations
## Hypotheses
## Attempts
## Tool Routing Decision
## Agent Design Metadata
## Blocker or Solve
## Evidence
```

raw 로그에 flag나 secret이 있으면 raw 로그는 제출하지 말고 matching redacted
summary와 sanitizer check 결과만 제출합니다. `metadata.shareability`에는 공유
가능한 파일과 local-only 파일을 명시합니다.

## 로컬 검증

PR을 열기 전에 다음을 실행합니다.

```bash
python3 tools/validate_data_submission.py --base origin/main
python3 tools/evaluate_corpus.py
```

staged 파일만 검증하려면:

```bash
python3 tools/validate_data_submission.py --staged
```

## Push 및 Pull Request

자기 브랜치에 push합니다.

```bash
git push origin HEAD:<github-user>
```

자기 브랜치에서 `main`으로 PR을 엽니다. data-submission GitHub Action은
`shyunseok1029`, `holymo-ly`, `lee` 브랜치에서 올라온 PR이
승인된 blindtest 데이터 경로만 바꾸는지 검사합니다. 병합은 소유자 리뷰 후에만
진행합니다.

직접 브랜치 push가 불가능하면 benchmark data issue template을 사용하고 동일한
정제 파일을 첨부합니다.
