# Summary

Flicker is a Web3 challenge built around ERC1155 deposits into an ERC20 vault. The solve condition is `Setup.isSolved() == true`, which requires the recorded solver address to hold at least `5e17` WDHC.

Challenge prompt details recorded from the assignment:

- Description: `Opportunities flicker like light, so you should seize them well.`
- Remote: `http://host3.dreamhack.games:10912/`; RPC is exposed at `/{token}/rpc`.
- `/start` generates a random token and redirects or points to `/{token}`. The prompt warns this token information cannot be retrieved again.
- `/{token}/info` exposes `setup_contract_address`, `user_private_key`, and `user_address`.
- `/{token}/flag` returns the flag after the verifier condition is satisfied.
- `/{token}/reset` resets a stuck scoped instance.
- 2025-04-09 notice: `Vault.withdraw()` was changed from `IERC1155(token).safeTransferFrom(msg.sender, token, id, value, "");` to `IERC1155(token).safeTransferFrom(address(this), msg.sender, id, value, "");`; the notice states this does not affect the solve.

# Artifacts

- Original handout copy: `dist/Dockerfile`, `dist/deploy/`
- Source under existing root handout: `deploy/src/Setup.sol`, `deploy/src/Vault.sol`, `deploy/src/DHC.sol`
- Hashes: `work/sha256sum.txt`
- File types: `work/file.txt`
- Local exploit contract: `work/Solve.sol`
- Local exploit test: `work/FlickerLocal.t.sol`

# Observations

- `Setup.free(tokenId)` can be called once and sets `solver = msg.sender`, then mints `1e10` DHC for the chosen ERC1155 `tokenId`.
- `Vault.deposit()` writes the registered token address to transient storage slot `1`, transfers ERC1155 tokens, then reads slot `1` as the transferred token ID.
- `Vault.onERC1155Received()` authorizes `msg.sender` against the transient slot and then overwrites the same transient slot with the ERC1155 token ID.
- The two enum types both resolve their active member to slot `1`, so token address and token ID collide in transient storage.

# Hypotheses

- A normal deposit cannot reach `5e17` WDHC because the free mint only grants `1e10` DHC.
- If the minted token ID is `uint160(address(exploitContract))`, a valid deposit leaves transient slot `1` equal to the exploit contract address.
- In the same transaction, the exploit contract can call `Vault.onERC1155Received()` directly and pass the guard because `msg.sender` equals the stored token ID interpreted as an address.

# Attempts

- `forge build --root challenges/blindtest/web3/Flicker/deploy --contracts src --out ../work/forge-out --cache-path ../work/forge-cache`: compiled the provided contracts successfully with solc `0.8.35`.
- `forge test --root challenges/blindtest/web3/Flicker --contracts work --match-contract FlickerLocalTest --out work/forge-out --cache-path work/forge-cache -vvv`: local exploit test passed.
- `python3 tools/replay_runner.py --allow-remote-live challenges/blindtest/web3/Flicker`: first live replay failed before deployment because the `/start` token was not parsed from the HTTP 200 response body.
- Follow-up direct and relay `/start` probes returned `{"error":"You already received the token."}`, so the live instance token cannot currently be recovered from this environment.
- Recorded the full prompt environment details, including the one-time token warning and 2025-04-09 withdraw notice.
- Inspected `dreamhackofficial/web3-base:2025-04-04`; `/start` returns a `RedirectResponse(f"/{token}")`, and `TokenManager.generate_token()` writes one 12-hex-character token to `/tmp/token/token` exactly once.
- Patched `work/solve_remote.py` to call `/start` with `allow_redirects=False`, matching the official challenge flow and preventing future loss of the redirect token.
- New remote port `8459` was provided and recorded as the live solve target.
- Manual low-volume `/start` check on port `8459` returned a redirect token. The token was used immediately for replay but not persisted to files because it gates `/info`, `/rpc`, `/reset`, and `/flag`.
- `forge create` first ran as a dry run; `work/solve_remote.py` was patched to include `--broadcast`.
- Live replay against `http://host3.dreamhack.games:8459/` succeeded: solver contract deployed, `is_solved=true`, and `/flag` returned a flag.

# Tool Routing Decision

- Primary tools used: local source review, Foundry `forge`, Python `requests`/`web3.py`, workspace replay/proof validators.
- Considered: `cast` for manual calls, Playwright for browser behavior, Burp for HTTP inspection, MCP integrations.
- Used: `forge` for compile/test/deploy, Python for DreamHack instance orchestration and verification.
- Skipped: Playwright and Burp because `/start`, `/info`, `/rpc`, and `/flag` are simple HTTP/RPC endpoints; MCP tooling because local source and Foundry were sufficient.
- Missing: none.
- Decision summary: the bug is source-level and reproducible locally, so a lean Foundry plus Python replay is the shortest evidence-backed route.

# Blocker or Solve

Solve path: deploy `work/Solve.sol:Solve` to a fresh challenge instance. The constructor calls `free()` with token ID equal to its own address, performs a 1-token legitimate deposit, then directly calls `onERC1155Received()` to mint `5e17` WDHC to itself.

Solved: the exploit was replayed on the refreshed `8459` remote instance. The raw replay log contains the flag, and the matching summary redacts it.

Replay note: the live instance token is not stored. If re-running against the same still-live instance, provide the token externally and use `FLICKER_RESET_BEFORE_SOLVE=1 FLICKER_TOKEN=<token> python3 tools/replay_runner.py --allow-remote-live challenges/blindtest/web3/Flicker`. The saved-evidence validation command avoids storing the token.

# Evidence

- Local regression: `evidence/local_forge_test.log` passed.
- Failed live replay: `evidence/replay_20260701T060825Z.log`
- Redacted replay summary: `evidence/replay_20260701T060825Z.summary.md`
- Successful live replay: `evidence/replay_20260701T062555Z.log`
- Redacted successful replay summary: `evidence/replay_20260701T062555Z.summary.md`
- Sanitize check: `evidence/replay_20260701T062555Z.sanitize_check.md`
- Final saved-evidence command succeeded: `python3 tools/replay_runner.py --summarize-existing challenges/blindtest/web3/Flicker`
- Final proof validation succeeded: `evidence/proof_validate.txt`
