---
name: ctf-solve
description: Race exactly one authorized CTF challenge to the first target-observed valid flag.
---

# CTF Solve

Read root `AGENTS.md` and `ctf_os/resources/agent-policy.md`. Root is the lead
attacker. Treat the `root_model_profile` and `root_model_profile_source`
returned by `race-prepare` as authoritative for the current Root; the policy
default is Sol Ultra. Do not load a category playbook into initial context.

If the user requests a Claude handoff, stop before any new attack and follow the
handoff skill immediately.

For each returned native action batch, collect all native results and make one
`race-reconcile` call containing every `SPAWNED` or `INTERRUPTED` event. Never
record native results with per-lane legacy confirmation commands.

1. Prepare exactly one challenge:

   ```bash
   uv run python -m ctf_os.agent_tools race-prepare '<selector>' --contest '<contest>'
   ```

   Add `--remote-execution human-relay` only when the contest requires a
   participant to execute every organizer-remote request. Treat the returned
   `remote_execution` value as immutable for the exact run.

2. Require `attack_ready: true` and `root_sandbox.status: READY`. If unavailable,
   report the exact returned blocker and recovery command. Never inspect or run
   challenge tools on the host.

3. Immediately append the highest-probability actual attack argv to
   `next_root_action.exec_command_prefix`. Root attacks continuously and never
   pauses merely to prepare workers.

4. When useful, call `race-bootstrap` once with one to three lane specs. Each has
   exactly `model_profile`, `role`, `task`, `context_mode`, and a distinct
   `attack_family`. Use Sol Ultra or Sol max for independent high-reasoning lanes
   when worth their cost, Sol xhigh for efficient independent attacks, Terra high
   for a verified build direction, and Luna high only for bounded mechanical
   work. Pass every returned `spawn_agent_args` unchanged to native
   `spawn_agent`; after all calls return, batch their native thread IDs as
   `SPAWNED` events through the reconciliation rule above. A child becomes
   RUNNING only after that reconciliation.

5. Execute every analyzer, debugger, compiler, script, payload, solver, and
   remote request with `sandbox-exec` or a bounded persistent session. Move a
   remote-ready primitive to the declared remote immediately. The sole exception
   is `human-relay`: never send an organizer-remote request through any model
   tool, host tool, web/browser tool, connector, socket, or sandbox command.
   Return a `HUMAN_REMOTE_ACTION` block with the exact working directory, argv,
   timeout, and full-output capture command, then analyze the participant's
   `HUMAN_REMOTE_RESULT` as unverified external input. Never convert that input
   into a verified receipt, blackboard event, target observation, or winner.

6. Share only compact events accepted from an existing command/session receipt.
   Fresh lanes receive no Root history. Directed lanes receive only the verified
   delta produced by the race engine.

7. Poll `race-status` while Root keeps attacking. Interrupt stagnant, duplicate,
   or remote-avoiding native lanes returned as native `INTERRUPT` actions. After
   all calls return, batch their exact native session IDs as `INTERRUPTED` events
   through the reconciliation rule above. Reconciliation cleans each stopped
   lane sandbox while preserving its host-side artifacts. Only a `STOPPED` lane
   frees capacity for a new attack family in a fresh private sandbox.

   Legacy `race-endgame` remains available after minute 60 as a bounded
   fallback, replacing one `STOPPED` child when the blackboard already contains
   an executable partial artifact, two actual attack outputs, and an exact
   non-environment reasoning blocker. Its lease is ten minutes or two attacks.

8. When any verified execution returns a winner, display `display` immediately. Interrupt
   every returned sibling cancel target, batch their results through
   `race-reconcile`, and stop analysis. Do not replay, build a report, or submit.
   A human submits the flag.

9. At 90 minutes, terminate without extension, interrupt native cancel targets,
   batch their results through `race-reconcile`, preserve needed lane-private
   artifacts, and run exact `race-cleanup`.

Maintain read-only input, declared-target-only egress, private writable paths,
Root-only service lifecycle, no host credentials/socket, and no automatic flag
submission throughout.
