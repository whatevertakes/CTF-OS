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
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
