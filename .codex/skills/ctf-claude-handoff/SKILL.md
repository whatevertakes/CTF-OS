---
name: ctf-claude-handoff
description: Create the single manual HANDOFF.md for the current exact CTF Solve run and then end that solve. Use for “클로드 구조대 준비해라”, “Claude 구조대 준비해라”, “클로드에게 넘길 내용 정리해라”, or “Claude handoff 만들어라”.
---

# Create a Manual Claude Handoff

Treat this request as an immediate termination command for the selected Solve. Do not ask for a mode, profile, objective, blocker, operation ID, research policy, model, runtime path, or original ZIP path.

1. Stop all new recon, exploit, remote, service, and challenge-file commands immediately. Do not start or wait for child work.
2. Confirm the current exact contest, challenge, and `run_id` from the already selected Solve state. Do not prepare a new run and do not inspect, locate, copy, extract, rename, or otherwise touch the original ZIP.
3. Read only the current run's `RUN_MANIFEST.json`, challenge `SESSION-INPUT.json` or equivalent metadata, `ATTACK_EVENTS.jsonl`, actual command receipts, bounded output/evidence, saved exploit artifacts, and explicitly failed experiments. Current-session observations may be used only when they are results of commands that actually ran.
4. Exclude other challenges, generic narrative events, unsupported candidates, confidence-only claims, model/swarm/scheduler state, internal monologue, unexecuted commands, untested ideas, unverified flags, long logs, full transcripts, and internal absolute paths. A `PRIMITIVE` event is insufficient without actual output, a command result, or an executable artifact.
5. Select at most ten decisive experiments. Merge repetitions. For each, record what ran, what was observed, and what that observation confirmed or refuted. Include only evidence-backed confirmed facts. Do not add a hypotheses or candidate section.
6. Include reusable code only when it is text, directly reproduces a confirmed fact, contains at most 100 lines, and fits the total 32 KiB UTF-8 limit. Embed required values or logic; never assume Claude can access a CTF-OS artifact path.
7. Compose exactly this structure in a temporary regular UTF-8 file:

```markdown
# <problem name>

## Challenge
- Contest:
- Category:
- Problem:
- Description:
- Flag format:
- Remote:

## Confirmed facts
- <evidence-backed fact>

## Verified solve history
1. <executed command or experiment>
   - Observed:
   - Conclusion:

## Refuted paths
- <experimentally refuted path and evidence>

## Useful technical material
- <exact reusable value, offset, primitive, protocol, command, or small snippet>

## Unresolved state
- <exact unresolved point; explicitly mark what remains unverified>

## Clean start
이 문서는 이전 Codex 풀이에서 실제로 확인된 사실과 실행 기록만 압축한 것이다.
추측이나 정답이 아니므로 원본 문제를 독립적으로 다시 분석하고 최종 flag를 획득하라.
```

8. Save it only through:

```bash
uv run python -m ctf_os.agent_tools claude-handoff-save \
  '<selector>' --contest '<contest>' --run-id '<exact-run-id>' \
  --markdown-file '<temporary-markdown-file>'
```

9. Verify that the command reports the current exact identity, `HANDOFF` termination, and `rescue/<contest>/<challenge>/HANDOFF.md`, that the file is at most 32 KiB, and that the challenge handoff directory contains only `HANDOFF.md`. Native-interrupt every returned cancel target and record each with `worker-stop-confirm`. Remove the temporary draft.
10. Do not call a Claude runtime, create a sandbox/job/start command, copy files, or continue solving. End the turn with exactly this shape, using `~` for the repository's home-relative installation path:

```text
Claude handoff 준비 완료

파일:
~/CTF-OS/rescue/<contest>/<challenge>/HANDOFF.md

원본 문제 ZIP과 이 파일을 사용자가 직접 Claude 시스템으로 옮기면 됩니다.
이 문제에 대한 Codex 풀이를 여기서 종료합니다.
```
