# Challenge Notes

## Summary

- Event: blindtest
- Category: rev
- Name: prismledger
- Status: solved
- Description: Analyze the supplied binary and recover the flag.
- Remote: `host3.dreamhack.games:15838` (TCP); user also supplied `http://host3.dreamhack.games:15838/`.

## Artifacts

- Original handouts are preserved under `dist/`.
- `dist/chall`: stripped x86-64 PIE ELF, SHA-256 `0a9d7d3a7bc6ac8efc707f8cafebbb30fbf2094b9950a346e8370a9b9b4ef69d`.
- `dist/flag`: 13-byte local placeholder flag file, SHA-256 `af7a5b59a578ff9675380e0535a090d22abbb007053a1067f5a553168615973c`.
- `work/chall.analysis`: executable analysis copy of `dist/chall`; content hash is identical.
- `work/solve.py`: deterministic solver that extracts the embedded digest targets directly from `dist/chall`.

## Observations

- Initial strings expose `correct!`, `wrong`, `./flag`, `%4095s`, and twenty 64-character hexadecimal constants.
- The original ELF arrived without its executable mode bit; only the analysis copy was made executable.
- `main` requires exactly 60 characters and accepts only `0-9`, `a-f`, and `-`.
- The input is processed as twenty independent 3-byte blocks. Even and odd block indexes use different byte permutations and arithmetic/XOR transformations.
- Each transformed block is SHA-256 hashed. A second index-dependent transform is applied to the 32-byte digest before comparison with the corresponding embedded target.
- The binary has PIE, NX, stack canary, full RELRO, and immediate binding. These protections are not relevant because the task is a verifier inversion, not memory corruption.
- Direct TCP submission returned `correct!` and a flag-shaped response. This confirms `host3.dreamhack.games:15838` is the binary verifier service.

## Hypotheses

- Confirmed: the hexadecimal constants are twenty target digests decoded to 32 bytes each.
- Confirmed: block independence reduces the search from a 60-character global problem to twenty searches of `17^3 = 4,913` candidates.
- Falsified: the supplied HTTP form is not needed. A raw TCP connection reproduces the local verifier protocol and returns the final proof.

## Attempts

- `tools/intake_challenge.py` refused to initialize because the supplied directory already existed. The directory was normalized manually without `--force`, preserving original file hashes.
- `file`, `strings`, `readelf`, and radare2 CLI analysis identified `main` and the verifier helpers at offsets `0x1cea`, `0x1d1f`, `0x1d70`, `0x1dc1`, `0x1e3a`, `0x1eb4`, `0x1bb5`, and `0x2031`.
- `work/solve.py` brute-forces each independent 3-byte block and requires exactly one matching candidate per block.
- Local verification against the unmodified `dist/chall` produced `correct!` and the provided placeholder flag.
- One direct remote submission produced `correct!` and a real flag-shaped response; the raw response is retained locally and a redacted summary is provided for benchmark use.

## Tool Routing Decision

- Primary tools used: local ELF utilities, radare2 CLI, Python standard library, direct TCP replay.
- Considered: `file`, `sha256sum`, `strings`, `readelf`, local dynamic execution, radare2 CLI/MCP, angr MCP, direct TCP, HTTP/curl, Playwright, Burp, `checksec`.
- Used: `file`, `sha256sum`, `strings`, `readelf`, `objdump`, radare2 CLI, Python `hashlib` brute force, unpatched local execution, `nc` remote proof.
- Skipped: radare2 MCP server because batch CLI output was directly reproducible; angr because concrete independent bounds made symbolic execution unnecessary; HTTP, Playwright, and Burp because raw TCP matched the ELF protocol and solved the service.
- Missing: no required dependency. The installed `checksec` entrypoint is broken because its recorded interpreter is unavailable; equivalent security properties were obtained with `readelf`.
- Decision summary: static and dynamic local evidence reduced the verifier to twenty small independent searches. MCP symbolic execution and browser tooling would add complexity without improving proof quality.

## Blocker or Solve

- Current state: solved with local verifier confirmation and live remote flag proof.
- Final command: `python3 tools/replay_runner.py --allow-remote-live challenges/blindtest/rev/prismledger`

## Evidence

- `evidence/remote_proof.raw.log`: initial live remote proof containing sensitive flag material; do not submit directly.
- `evidence/remote_proof.raw.summary.md`: sanitized form of the initial remote proof.
- `evidence/local_verification.summary.md`: sanitized unmodified-local-binary verification result.
- `evidence/replay_20260630T162550Z.log` and matching summary: official replay-runner proof; raw log is sensitive.
- `evidence/proof_validate.txt`: passing proof-validation transcript.
