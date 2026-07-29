# CTF-OS implementation rules

- The product unit is one challenge. Humans decide which challenge sessions to
  open; do not add a scheduler, priority queue, or automatic challenge switch.
- Keep logical roles and wave widths independent from account/provider
  concurrency. Provider limits queue model calls; they never remove roles or
  silently narrow a wave.
- Challenge input under `incoming/` is untrusted and immutable to the engine.
  Execute challenge binaries, parsers, browsers, and remote requests only
  through the challenge-scoped sandbox boundary.
- Default network access is denied. Remote tools require an explicit
  per-challenge target allowlist.
- `state.json` is the canonical state. Only the engine/store may replace it;
  workers write run-specific proposals and artifacts.
- Preserve raw output in bounded files and give models summaries plus exact
  pointers. Never pass secrets or credentials into model prompts or run logs.
- A flag-looking string is a candidate, not proof. Print candidates immediately
  for the operator, never submit automatically, and record manual outcomes.
- Keep the core standard-library-first. Do not add a database, task queue,
  container SDK, or service framework unless measured use requires it.
- Preserve the existing `ctf_os.agent_tools` and `ctf-container` behavior while
  routing new functionality through the `ctfos` CLI.
- Tests must not make model API calls or remote CTF requests.
