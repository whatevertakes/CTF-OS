# Blindtest Challenge Workspaces

This event directory keeps category slots on main and allows concrete
challenge workspaces to share solve outputs.

Raw blindtest handouts and provided problem files stay local-only under
`dist/`. Solve outputs such as `state.json`, `notes.md`, `replay.sh`, and
`evidence/` may be committed when they are appropriate to share. Sanitized
benchmark summaries still live under `benchmarks/`.

Current committed category slots:

- `pwn/`
- `web/`

Create concrete workspaces with `tools/intake_challenge.py` under:

```text
challenges/blindtest/<category>/<challenge>/
```
