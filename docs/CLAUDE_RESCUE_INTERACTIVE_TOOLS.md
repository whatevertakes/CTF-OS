# Claude Rescue Interactive Tools

The rescue runtime keeps stateful attack tools inside the exact category sandbox. The implementation uses `tmux` for PTY-backed shell, GDB, and REPL sessions and a binary-safe Python socket relay for TCP. WebSocket is explicitly `UNAVAILABLE` because no trusted common backend is bundled.

## Session lifecycle

```bash
./ctf-tool session list
./ctf-tool session open --kind shell --name main-shell -- /bin/bash
./ctf-tool session open --kind gdb --name exploit-gdb -- gdb -q /challenge/chall
./ctf-tool session open --kind repl --name python -- python3 -q
./ctf-tool session open --kind tcp --name remote --target-index 0
```

`open` creates `sessions/<session-id>/SESSION_STATE.json`, `transcript.jsonl`, `stdout.bin`, `stderr.bin`, and `control/`. The state is fixed to the run, rescue attempt, packet digest, session kind, container, image ID/digest, input fingerprint, and target revision. PTY commands execute as the unprivileged challenge user in the existing container.

Input supports exactly one encoding:

```bash
./ctf-tool session send --session-id '<id>' --text 'break main'
./ctf-tool session send --session-id '<id>' --hex '000102ff'
./ctf-tool session send --session-id '<id>' --base64 '<base64>'
./ctf-tool session send --session-id '<id>' --file work/payload.bin
```

TCP input is binary safe, including NUL bytes. Reads are incremental and bounded:

```bash
./ctf-tool session read --session-id '<id>' --cursor 0 \
  --max-bytes 32768 --wait-seconds 2
```

The response contains `cursor_before`, `cursor_after`, UTF-8 `stdout` or `stdout_base64`, `truncated`, `eof`, and `observation_receipt_id`. The runtime does not replay the full transcript into Claude context. The spool is capped and advances a durable `cursor_base` if older bytes must be discarded.

`status` reports `OPENING`, `RUNNING`, `EXITED`, `CLOSED`, `STALE`, or `ERROR`. `close` terminates the tmux server/session or TCP relay process group, checks that it is gone, and records the result. Recovery marks prior sessions `STALE`; it never guesses how to recreate debugger or protocol state.

## Canonical receipts

`RESCUE_SESSIONS.jsonl` records `SESSION_OPENED`, `SESSION_INPUT_SENT`, `SESSION_OUTPUT_OBSERVED`, `SESSION_EXITED`, `SESSION_CLOSED`, and `SESSION_ERROR`. Output observations bind the cursor range, output SHA-256, bounded evidence path, protocol-specific network observation, artifact snapshot, and exact sandbox identity.

TCP proof uses target-specific packet delta and TCP connection-state evidence. UDP and DNS command observations use target-specific UDP/TCP packet deltas and do not require TCP `ESTABLISHED`. Managed local service traffic is never treated as remote flag provenance. One-shot commands and persistent sessions call the same sandbox network-observation backend.

## MCP parity

The project-local server exposes the same backend as the CLI:

- `ctf_inventory`, `ctf_exec`
- `ctf_session_list`, `ctf_session_open`, `ctf_session_send`, `ctf_session_read`, `ctf_session_status`, `ctf_session_close`
- `ctf_progress_record`, `ctf_progress_show`, `ctf_progress_checkpoint`
- `ctf_task_create`, `ctf_task_result`, `ctf_task_show`
- `ctf_knowledge_hint_record`, `ctf_knowledge_show`

All output is bounded; session output uses cursors. The server cannot choose another run, start a model, modify the frozen benchmark, create a race child, or submit a flag.

## Toolchain contract

`./ctf-tool inventory --refresh` inspects the running container and writes authoritative `TOOLCHAIN_RECEIPT.json`. Contracts live under `ctf_os/resources/claude-rescue/toolchains/`. The common image installs `tmux`, `socat`, and `expect`; category files require only attack tools that category promises. Missing `REQUIRED` tools fail with their exact names instead of being papered over.

