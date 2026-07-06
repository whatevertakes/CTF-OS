# Amo's OAuth Level 3 Sanitized Benchmark Report

## Scope

- Event: blindtest
- Category: web
- Challenge: Amo's OAuth
- Primary workspace: local-only blindtest workspace, removed from main
- Independent comparison workspace: local-only blindtest workspace, removed from main
- Status: solved
- Replay kind: remote live exploit
- Evidence sensitivity: raw replay logs contain the flag; raw Request Bin data may contain a consumed authorization code.

## Level 3 Design Use

This case is a web orchestration data point for Level 3 agent design. Two
independent solves used the same exploit architecture and reached the same
remote proof, but preserved different evidence surfaces.

The machine-readable companion manifest is
`benchmarks/AMOS_OAUTH_LEVEL3_DATA_MANIFEST.json`.

The useful Level 3 lesson is not a new payload family. It is the data contract
needed for a multi-worker web solve:

- model public mutable OAuth configuration separately from per-session state;
- preserve state-changing requests in a mutation ledger;
- preserve negative probes that falsify ordinary OAuth callback paths;
- keep raw sensitive proof local while emitting redacted summaries and stable hashes;
- compare independently produced outputs by invariant fields, not by fresh per-run values such as request-bin hostnames and authorization codes.

## Exploit Architecture

Both solves used the same chain:

1. Create a DreamHack Request Bin host under `*.request.dreamhack.games`.
2. Set the client app's process-global OAuth callback base to that Request Bin.
3. Set the client app's auth server URL back to the internal auth server.
4. Submit `http://client-app:3000/login` to the admin bot.
5. Capture the admin authorization code from the Request Bin callback.
6. Redeem the captured code through a fresh client session with the `state` parameter omitted.
7. Call the protected resource API through the client app and receive the admin response.

## Invariant Output Comparison

The two raw replay logs were inspected locally without copying flag text into
this benchmark report.

- Primary replay timestamp: `2026-06-30T17:43:08Z`
- Comparison replay timestamp: `2026-06-30T17:40:20Z`
- Remote liveness: `live` in both runs
- Captured authorization code length: `24` in both runs
- Flag count extracted from each raw log: `1`
- Flag length extracted from each raw log: `65`
- Flag SHA-256 from each raw log: `0567c3e6a0cbcd16377a919d08cbc8e69f02cc94e55efc6f03e58920326a762f`

Fresh per-run values intentionally differ:

- Request Bin hostnames are different.
- Authorization codes are one-use values and are not preserved in this report.
- Raw replay working directories differ by operator environment.

## Preserved Data Files

Primary workspace files useful to Level 3:

- `state.json`
- `notes.md`
- `replay.sh`
- `work/solve.py`
- `work/ATTEMPT_MATRIX.md`
- `work/MUTATION_LEDGER.md`
- `evidence/baseline_client_root.http`
- `evidence/baseline_auth_root.http`
- `evidence/baseline_bot_report.http`
- `evidence/client_login_redirect.headers`
- `evidence/requestbin_create_probe.http`
- `evidence/replay_20260630T174308Z.summary.md`
- `evidence/replay_20260630T174308Z.sanitize_check.md`

Comparison workspace files useful to Level 3:

- `state.json`
- `notes.md`
- `replay.sh`
- `work/solve.py`
- `work/ATTEMPT_MATRIX.md`
- `work/MUTATION_LEDGER.md`
- `work/baseline-client.http`
- `work/baseline-auth.http`
- `work/baseline-bot.http`
- `work/login-redirect.http`
- `work/set-auth-server.http`
- `work/set-client-url.http`
- `work/bot-report.http`
- `work/callback-no-state.http`
- `work/call-api-amo.http`
- `work/requestbin-create.json`
- `work/requestbin-log.json`
- `evidence/requestbin_admin_callback.summary.md`
- `evidence/replay_20260630T174020Z.summary.md`
- `evidence/replay_sanitize_check.summary.md`
- `evidence/proof_validate.txt`

Sensitive local-only files:

- primary raw replay log
- comparison raw replay log
- comparison raw Request Bin data

## Evidence Shape Difference

The primary workspace is stronger for final proof comparison because it records
the parsed API JSON, a stable flag hash, and an explicit proof label in the
redacted replay summary.

The comparison workspace is stronger for Level 3 worker design because it
preserves more intermediate HTTP request/response files, the admin callback
provenance summary, and a final proof-validation transcript.

Together they show that Level 3 should keep both classes of evidence: narrow
final proof invariants and broad intermediate state-transition files.

## Redaction Boundary

This report intentionally excludes:

- the flag;
- captured authorization codes;
- raw Request Bin callback data;
- raw replay logs;
- any one-use credential or token value.

This file is suitable as a commit-safe Level 3 design corpus item. Raw evidence
remains in the challenge workspaces for local verification only.
