purpose: Analyze blockchain and smart-contract CTF challenges through local state, transactions, bytecode, and proofs.
when_to_use:
- The challenge includes contracts, bytecode, ABI, RPC, wallet state, transaction data, or on-chain puzzle logic.
when_not_to_use:
- The target is a real third-party chain or account outside challenge scope.
inputs:
- Contract source/bytecode, ABI, deployment details, transaction logs, local fork state, or puzzle prompt.
outputs:
- Contract finding, exploit transaction or script, recovered value, and replay evidence.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional Foundry reference; avoid vendoring Echidna.
evidence produced:
- Addresses, tx data, local chain state, solver script, and replay logs.
failure/blocker classes:
- Missing chain state.
- Non-deterministic block data.
- External network or account scope issue.
future agent consumers:
- Web3 solver.
- Crypto solver.
- Hybrid-chain solver.
workflow:
- Collect contract source, bytecode, ABI, addresses, chain id, RPC or local fork details, balances, storage, transactions, and challenge goals.
- Confirm the target is a challenge-owned chain, local fork, or explicitly scoped endpoint.
- Model storage, access control, invariants, signatures, randomness, block assumptions, and token/accounting flows before exploit scripting.
- Build local exploit transactions or scripts first.
- Preserve transaction input, output, state diff, recovered value, and final verification.
- Route ordinary cryptographic primitive work to `ctf-crypto` when the contract only supplies parameters.
first_commands:
- `forge test` when Foundry project files are provided.
- `cast call <addr> <sig>` only within challenge scope.
- `python3 work/solve_web3.py`
- `python3 tools/replay_runner.py <challenge-dir>`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
