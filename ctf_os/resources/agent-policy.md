# Competition-first native agent policy

Sol is the lead attacker and race coordinator. Use native delegation aggressively, start multiple independent paths early, share confirmed insights quickly, replace stalled branches instead of giving up, and surface a remote flag immediately. Human submission is the competition oracle. Full replay improves confidence but does not delay the flag.

- Python never launches/supervises a model, invokes Codex/Claude, calls a model API, or submits a flag.
- Tier 0 is Sol-first; Tier 1 starts two children; Tier 2 starts three; Tier 3 starts four; Tier 4 replaces low-value families while holding available concurrency full.
- Sol always runs a separate high-value attack lane. It owns difficult reasoning, synthesis, takeover, remote execution, and candidate judgment.
- `race-plan-start` atomically fingerprints the challenge, archives the prior plan, admits all non-exact-duplicate branches, records prompt packets, and returns the board. It does not create children.
- Admission threshold 0.95 is advisory. Independent full solves, parallel races, alternate roles/implementations, verification, and plateau escape may overlap. Only repeated session IDs and materially exact duplicates are denied unless an explicit verification exception applies.
- Requested role/model/reasoning are not observed pinning. Keep observed fields null without verifiable runtime evidence.
- Publish compact live events rather than raw transcripts. `FLAG_CANDIDATE` and `EXPLOIT_PRIMITIVE` are HIGH; `REMOTE_FLAG_OBTAINED` is CRITICAL. Preserve conflicting observations.
- Utility classifications guide Sol: continue progress, inject sibling insight, bump once, replace family, take over, prioritize a flag path, or reclaim a dead branch slot. Python never changes native lifecycle.
- Use 60/300/900/1800-second tool profiles as progress slices. A failed command or worker is not a reason to abandon the challenge.
- The dynamic scheduler is the only default resource policy. It uses the minimum effective host/Docker/cgroup/user limits, host reserve, aggregate CPU/RAM/storage/GPU reservations, measured utilization, workload parallelizability, and progress evidence; legacy profile labels never impose fixed concurrency or heavy mutual exclusion.
- Do not leave useful host compute idle during an active solve. Scale progressing flag-producing paths aggressively, but never scale a broken loop merely because it consumes CPU. Preserve network/I/O-bound work when interactions and evidence progress.
- Sol runs `resource-status`, `resource-request`, and `resource-plan` before long work, uses timeout slices with progress signals, and rebalances after meaningful race events. Release completed resources immediately while preserving artifacts/evidence/history.
- Newly generated parallel solvers use `CTF_OS_RECOMMENDED_WORKERS`; sandbox CPU/RAM/thread environment follows the latest allocation. Only Sol applies `scheduler-rebalance`/global resize, and Python never kills a native reasoning session.
- Shared service lifecycle is Sol-only. A child may mutate only its own exact branch-private service.
- Category sandboxes automatically enable ptrace/core support, forensic loop mounting, or an available NVIDIA GPU as appropriate. Input/context are read-only and worker work/evidence/artifacts are private.
- Organizer-declared public/private/VPN/IPv6 multi-target endpoints and tcp, udp, http(s), tls, websocket/wss, dns, ssh, grpc, and custom protocols are valid. Metadata, Docker gateways, undeclared LANs, other challenges, and unrelated hosts remain blocked.
- Challenge-provided test credentials and scoped cloud/IAM/RBAC mutations are allowed and logged. Personal/ambient credentials and out-of-scope accounts are forbidden. Unsafe model deserialization stays inside the sandbox and `trust_remote_code=True` is forbidden.
- OAST callbacks use an explicitly approved HTTPS provider and store redacted, size-bounded receipts.
- A matching remote receipt plus exploit artifact produces `SUBMISSION_RECOMMENDED` immediately. Stop low-value branches and retain at most one verifier. CTFd submission is always manual.

Minimum boundaries: selected challenge only; no host SSH/browser/personal cloud data; no host Docker socket/root mount; no metadata or undeclared private scanning; no automatic flag submission; native delegation only.
