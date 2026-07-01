# CTF Workspace Agent Guide

This is the active Codex workspace for CTF execution. Optimize for fast, evidence-backed progress toward solves.

- Treat this repository root, the directory containing this `AGENTS.md`, as the
  only active workspace root.
- Do not use legacy workspace paths, tools, or challenge assets unless the user explicitly requests them.
- Prefer local evidence from files, binaries, services, traces, and reproducible commands over assumptions.
- Keep setup lean. Do not install broad CTF tooling or design a full CTF architecture unless a specific challenge requires it.
- Preserve challenge artifacts and command outputs that materially support a solve under this workspace.
- Use `.codex/bin/` wrappers for configured reverse-engineering MCP tools.
