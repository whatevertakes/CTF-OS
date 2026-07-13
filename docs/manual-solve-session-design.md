# Manual Solve Session workbench

## Product boundary

CTF-OS is a human-directed, challenge-scoped Solve Session workbench. It is
not a contest-wide autonomous scheduler. The operator prepares `contest.md`
and challenge files, runs intake, chooses exactly one challenge, chooses the
lead model, runtime profile, priority and subworker ceiling, and explicitly starts or
stops that session.

The default workflow is:

```text
human prepares input
  -> ctf-os intake
  -> per-challenge intake reports
  -> human reviews one challenge
  -> ctf-os solve <challenge>
  -> one lead session for that challenge
  -> optional challenge-scoped subworkers, bounded by the human-selected cap
  -> human reviews evidence and submits any flag manually
```

There is no CTFd polling, login, assignment, submission, contest-global queue,
automatic retry or automatic worker launch outside the selected Solve Session.
All network access remains limited to the exact authorized remote declared in
`contest.md`.

## Intake contract

`ctf-os intake --config CONFIG` evaluates every locally owned challenge
independently. A malformed archive, missing source or runtime requirement for
one challenge becomes that challenge's report and never prevents sibling
reports.

Reports are written to:

```text
output/<team>/<member>/<contest>/briefs/<challenge>/intake.md
```

Each report records challenge metadata, detected inputs, Docker/Compose files,
admission status (`ready`, `blocked`, or `needs_preparation`), tools, runtime
requirements, blockers, recommended lead/subworker roles and an operator
checklist. Intake never starts a model or a solver container.

## Solve Session contract

`ctf-os solve CHALLENGE` resolves exactly one manifest challenge and refuses
ambiguous selectors. It fails before creating a session when model routing is
disabled, intake is blocked, or the explicitly selected runtime is unavailable.
It creates only one lead session. Subworkers may be requested only from inside
that session, must have non-overlapping scopes, and are bounded by
`--max-subworkers`.

The challenge artifact root is:

```text
output/<team>/<member>/<contest>/<challenge>/
  intake.md
  plan.md
  notes.md
  evidence.log
  findings.jsonl
  exploit/
  writeup.md
  handoff.md
  session.json
  workers/<worker-id>/
```

`session.json` is a local session index, not a scheduler lease. Terminal states
are written explicitly. The solve terminal and durable artifacts are the user
interface; there is no separate TUI or projected contest-global RUNNING state.

## Runtime profiles

- `standard`: default unprivileged CTF tool sandbox.
- `nested_podman_trusted_ctf`: explicit opt-in for reviewed challenges whose
  Dockerfile/Compose environment must be reproduced. Intake marks the extra
  privilege and nested-container risk. It is never selected automatically.

Runtime preparation failure blocks only the selected challenge/session.

## Model roles

- Sol: lead strategy, difficult analysis, strategy changes and final evidence
  review.
- Terra: implementation, exploit construction and local reproduction.
- Luna: fast recon, file/environment inventory and alternative hypotheses.

Workers may write only below their challenge artifact/workspace roots, may use
only the manifest-authorized remote, must record commands/findings/failures,
and cannot submit flags. Flag-like text is retained only as a candidate with
evidence and reproduction instructions.

## Compatibility and removals

`ctf-os run` remains only as a deprecated error that directs operators to
`intake` and `solve`; it does not start the legacy global scheduler. Existing
SQLite data remains readable as a local history/index, but manual Solve
Sessions do not depend on contest-wide leases, stale-attempt recovery,
automatic retries or queue state. `pause`, `resume` and `retry` are scoped to a
human-selected challenge session.

## Implementation files

- `ctf_os/workbench.py`: isolated intake reports, manual session lifecycle,
  challenge artifact layout, role/runtime policy and session index.
- `ctf_os/cli.py`: `intake`, `solve` and session-scoped operator commands;
  deprecates global `run` execution and removes the TUI command.
- `ctf_os/doctor.py`: reports per-challenge intake blockers without treating
  one broken challenge as a contest-wide admission failure.
- `ctf_os/config.py`, `config.example.yaml`: manual mode defaults.
- `ctf_os/tui.py`, `tests/test_textual_tui.py`: removed together with the
  Textual dependency; durable artifacts replace the dashboard.
- `README.md`: final operator workflow.
- `tests/test_manual_workbench.py`: focused behavioral regression tests.
