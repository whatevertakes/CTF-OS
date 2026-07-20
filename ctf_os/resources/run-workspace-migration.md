# Run workspace migration

Schema v3 separates a challenge workspace from its mutable solve generations.
New state lives in `runs/<run-id>/`; `ACTIVE_RUN.json` is the only active-run
pointer. A run is content-bound to one challenge ID, input fingerprint, and
target revision.

On the first compatibility read of a legacy challenge-level `STATE.json`,
CTF-OS takes the challenge-local run lock, copies legacy state, receipts,
evidence, race ledgers, workers, and artifacts into a deterministic
`runs/legacy-<digest>/` directory, writes a v3 state and manifest, and then
atomically publishes `ACTIVE_RUN.json`. The original challenge-level files are
kept as non-authoritative compatibility views. Repeating migration resolves the
same run and does not copy, erase, or rename prior evidence.

Existing commands continue to accept a challenge workspace and transparently
resolve its active run. `prepare-challenge` retains `solve_root` as the
challenge workspace for input compatibility and additionally returns `run_root`
and `authoritative_solve_launch_path`. New lifecycle tools should persist state
under `run_root`.
