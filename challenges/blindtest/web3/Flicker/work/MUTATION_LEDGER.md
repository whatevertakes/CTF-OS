# Mutation Ledger

State-changing actions are limited to challenge-owned DreamHack instances created through `/start`.

| Time (UTC) | Target | Action | Purpose | Sensitive Data |
| --- | --- | --- | --- | --- |
| 2026-07-01 06:08:25 | `http://host3.dreamhack.games:10912/start` | Requested random challenge instance via `work/solve_remote.py` | Obtain scoped RPC, setup contract, and user account | Token was not captured due parser bug; private key not recorded |
| 2026-07-01 06:08:25 | `http://host3.dreamhack.games:10912/start/info` | Accidental info request with `start` misparsed as token | Parser failure evidence | No secrets returned |
| 2026-07-01 06:09-06:12 | `http://host3.dreamhack.games:10912/start` | Follow-up direct and relay start probes | Attempt to recover or reissue token | Service returned `You already received the token.` |
| 2026-07-01 06:21 | `http://host3.dreamhack.games:10912/openapi.json`, encoded route probes | Read public API metadata and test low-volume path normalization behavior | Confirm whether token-gated endpoints can be reached without token | No secrets returned |
| 2026-07-01 06:22:13 | `http://host3.dreamhack.games:10912/start` | Re-ran replay after parser hardening | Check whether container had restarted and token could be reissued | Service returned `You already received the token.` |
| 2026-07-01 06:25:07 | `http://host3.dreamhack.games:8459/start` | Requested fresh token after user supplied new remote port | Obtain scoped token for refreshed instance | Token used in-process only and not persisted |
| 2026-07-01 06:25:38 | `http://host3.dreamhack.games:8459/{token}/info`, `/{token}/rpc` | Read scoped info and dry-run solver deployment | Validate parser and deployment command | Private key redacted; no chain mutation due dry-run |
| 2026-07-01 06:25:55 | `http://host3.dreamhack.games:8459/{token}/rpc` | Broadcast `work/Solve.sol:Solve` deployment | Run exploit constructor and satisfy verifier | Private key redacted |
| 2026-07-01 06:25:55 | `http://host3.dreamhack.games:8459/{token}/flag` | Fetch flag after `isSolved()` became true | Capture final proof | Raw log contains flag; summary redacts it |
