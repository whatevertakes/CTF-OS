# Web3 Reference Digest

## Trusted Sources

- `ref:foundry`: local smart-contract test and exploit scripting reference.
- `ref:slither`: Solidity static analysis reference.
- `ref:echidna`: smart-contract fuzzing reference.

## CTF-Relevant Patterns

- Collect source, bytecode, ABI, addresses, chain id, RPC/local fork details, balances, storage, transactions, and goal state.
- Confirm target chain/account is challenge-owned or local before interaction.
- Model storage, access control, signatures, randomness, block assumptions, invariants, and accounting flows before exploit transactions.
- Preserve transaction input, output, state diff, and final verification.

## CWE/CVE Mapping

- Map reentrancy, access control, arithmetic, signature replay, and randomness weaknesses only after contract-state evidence.
- CVEs are rare in CTF web3 unless a known dependency or compiler version is evidenced.

## Canonical Papers And Deep Dives

- DAO/reentrancy, MEV/front-running, signature malleability, and oracle manipulation references are useful pattern sources.
- Fuzzing and static analysis reports are hypotheses until reproduced in local chain state.

## When To Use

- Use for smart contracts, bytecode, ABI, local forks, transactions, wallets, and chain-state puzzles.

## When Not To Use

- Do not target real third-party chains or accounts outside explicit challenge scope.

## Source Anchors

- `idx:web3:foundry:overview`
- `idx:web3:slither:overview`
- `idx:web3:echidna:overview`
