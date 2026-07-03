# Attempt Matrix

| Probe Family | Result | Evidence |
| --- | --- | --- |
| Source review | Found `Setup.isSolved()` checks only `vault.balanceOf(solver) >= 5e17`. | `deploy/src/Setup.sol` |
| Normal deposit path | Only mints WDHC equal to transferred DHC; initial free mint is `1e10`, below target. | `deploy/src/Vault.sol`, `deploy/src/DHC.sol` |
| Transient storage guard | `deposit()` stores token address and callback overwrites the same transient slot with token ID. | `deploy/src/Vault.sol` |
| Exploit path | Token ID equal to exploit contract address leaves the guard slot set to the exploit contract, allowing direct callback mint. | `work/FlickerLocal.t.sol` |
| Live replay | Failed before deployment because `/start` returned a token format the first parser did not capture; subsequent `/start` calls refuse reissue. | `evidence/replay_20260701T060825Z.log` |
| Base runtime source | Confirmed `/start` is a one-shot redirect to `/{token}` and token storage is exact-match only. | `work/web3_base_src/app/main.py`, `work/web3_base_src/app/token_manager.py` |
| Route bypass probes | Encoded path traversal and docs routes did not expose token, info, RPC, reset, or flag. | `evidence/route_probe_20260701T0621Z.log` |
| Refreshed remote port | Port `8459` exposed a fresh instance; `/start` returned a redirect token. | user-provided remote details, live `/start` probe |
| Forge deployment dry run | First `8459` replay parsed info correctly but did not broadcast because `forge create` defaulted to dry-run. | `evidence/replay_20260701T062538Z.log` |
| Live exploit | Added `--broadcast`; solver deployment succeeded, `is_solved=true`, and `/flag` returned the flag. | `evidence/replay_20260701T062555Z.log` |
