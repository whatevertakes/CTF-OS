# Solver benchmark plan

Benchmark runs distinguish primitive candidate/confirmed/refuted and measure confirmation-to-automatic-utility, duplicate cleanup, required Sol takeover, minimal PoC, and remote latency. Candidate-only claims do not count as progress. Scheduler comparisons use minimum allocation for ordinary lanes and opt-in elasticity only for evidenced long compute; timeout continuation records whether the selected profile retained or cleaned the sandbox.

This benchmark measures whether competition policy reduces time-to-flag. Unit, policy, and integration tests prove implementation invariants only; passing them is not evidence that CTF solve rate or speed improved.

## Configurations

Run the same challenge snapshot and tool environment under four configurations:

| ID | Configuration | Definition |
|---|---|---|
| A | plain Sol xhigh CLI | One unmodified strong CLI agent, no CTF-OS solve orchestration |
| B | current CTF-OS Sol-only | CTF-OS scope/sandbox/evidence/receipt path with Tier 0 and no children |
| C | CTF-OS fixed race | Fixed category fallback lanes and width, without evidence-driven lane selection/replacement |
| D | CTF-OS evidence-driven race | Current exploit-first prompt, evidence-selected lanes, exploit-proximity utility, and research-drift replacement |

“Current” must name the exact Git commit and configuration digest for each run. Never compare a changing live branch to an older baseline without pinning both.

## Challenge sets

- `public-known`: published challenges with available ground truth; use to debug the harness, not to claim generalization.
- `transformed-family`: semantics-preserving variants that change constants, layout, protocol details, or surface syntax.
- `private-heldout`: unseen challenges kept away from prompt/policy development.
- `live-contest`: authorized, timestamped contest attempts with organizer-declared scope and human flag submission.

Stratify by category, expected solve duration, interaction type, remote/local dependence, and long-compute requirement. Report results for each stratum as well as the aggregate.

## Metrics

Capture timestamps and event/command counters sufficient to compute:

- solve rate
- time-to-first-viable-hypothesis
- time-to-working-PoC
- time-to-first-remote-attempt
- time-to-flag
- commands before first PoC
- research-drift events
- hypothesis kill latency
- branch replacement count
- false flags
- strict replay success
- run-to-run variance

A viable hypothesis requires a named expected primitive, decisive experiment, success condition, and kill condition. A working PoC must execute and demonstrate the primitive/solver/extraction; analysis notes do not qualify. A remote attempt must contact only the declared target and exercise the candidate exploit path.

## Protocol

1. Freeze the challenge inputs, target availability window, model/surface, reasoning setting, tool image, host capacity, network conditions, time limit, and flag pattern.
2. Randomize configuration order. Run multiple independent seeds/sessions per challenge; do not reuse branch artifacts or hidden solution notes.
3. Record command/event timestamps automatically where possible. Have a blinded reviewer label viable hypotheses, working PoCs, research drift, and false flags from compact receipts.
4. Apply the same scope, sandbox, manual-submission, and stopping rules to all CTF-OS variants. Plain CLI must receive equivalent challenge scope and target declarations.
5. Stop timing at the first valid flag observation. Measure optional strict replay separately so it cannot inflate time-to-flag.
6. Report medians, tail latency, confidence intervals, unsolved counts, resource use, and per-challenge paired differences. Include failures and target outages.

## Decision criteria

Treat D as an improvement only when held-out/live solve rate is non-inferior and time-to-flag or time-to-working-PoC improves without more scope violations or false flags. Use research-drift reduction and lower variance as mechanism evidence, not substitutes for flags. A unit-test pass, more events, more artifacts, lower prompt length, or higher utility score alone is never a solve-performance result.
