# CTF Solve Playbooks

This document is the practical solve layer for category workers. It complements
the thinner `skills/ctf-*/SKILL.md` routing contracts and should be read by
Level 3 workers before they probe a real challenge.

## Global Solve Loop

1. Freeze the prompt, files, endpoints, versions, and current `state.json`.
2. Copy original handouts into `dist/`; keep generated scripts under `work/`.
3. Read the selected category skill, category reference digest, and category
   reference index. Treat GitHub, CVE/CWE, and paper references as hypothesis
   sources, not proof.
4. Record every material command, transcript, output file, and hash.
5. Query `tools/reference_query.py` only after evidence exists, then open exact
   pinned files rather than loading whole repositories.
6. Split work by evidence type, not by payload spelling.
7. Write negative families to `work/ATTEMPT_MATRIX.md`.
8. Write state-changing remote actions to `work/MUTATION_LEDGER.md`.
9. Put durable proof output under `evidence/`, then update `replay.sh`.
10. Claim solved only after `tools/replay_runner.py` and
   `tools/proof_validate.py` accept the challenge state.

## Pwn

First pass:

- Hash binaries and supplied libraries.
- Run `file`, `checksec`, `ldd` when safe, and identify architecture, libc,
  loader, RELRO, NX, PIE, canary, seccomp, and container topology.
- Use `pwninit` only when the challenge provides a binary, libc, and loader
  that must be aligned for local reproduction.
- Reproduce the service locally with the provided Docker or wrapper before
  exploit work.
- Save initial process transcript and any crash input under `evidence/`.

Exploit loop:

- Minimize crashes and record signal, offset, controlled bytes, registers, and
  allocator state.
- Promote only evidenced primitives: leak, write, control-flow, sandbox escape,
  format string, heap overlap, UAF, OOB, or race.
- Use `ROPgadget` or `ropper` after control-flow evidence shows a gadget search
  is needed; use `one_gadget` only with a matched libc and recorded
  constraints.
- Use `seccomp-tools` when seccomp is detected or suspected, and save the
  policy dump before syscall-chain work.
- Build `work/exploit_*.py` with deterministic local mode first.
- Separate local proof from remote proof; capture remote transcripts with
  timing, leak values, retry count, and failure reason.

Stop or escalate when:

- The remote libc or loader is unknown and the exploit depends on it.
- A crash is nondeterministic and no stabilization path is recorded.
- The primitive is actually a parser, crypto, or reverse-engineering problem.

## Reverse Engineering

First pass:

- Hash artifacts, run `file`, `strings`, architecture detection, imports, and
  packer indicators.
- Use `floss` when strings are sparse or obfuscated; use `yara` and `upx` when
  rule matches or packer state affect routing.
- Use `qemu-*` only for scoped cross-architecture local execution that can be
  reproduced safely.
- Identify input format, output format, success predicate, anti-debug checks,
  and high-value functions before opening a broad symbolic search.
- Save offsets, function names, extracted constants, and commands in notes.

Analysis loop:

- Use static extraction to recover constants, tables, encodings, and check
  functions.
- Use dynamic traces to bound real input lengths, branches, syscalls, and side
  effects.
- Use patching only to observe or bypass one named check; keep original bytes
  and verify final candidates against the unpatched semantics.
- Use symbolic execution only after concrete bounds exist; save constraints,
  model output, and original-binary verification.

Stop or escalate when:

- The recovered logic is a math primitive and should move to crypto.
- The recovered bug is memory corruption and should move to pwn.
- The sample is packed or malware-like and needs safe unpacking discipline.

## Web

First pass:

- Freeze base URL, local source, docker-compose, credentials, cookies, roles,
  and request samples.
- Inventory routes, methods, content types, auth boundaries, upload/render
  paths, background jobs, and state-changing endpoints.
- Save representative requests and responses under `evidence/` or `work/html/`.

Branching loop:

- Auth/session: compare roles, cookies, CSRF, JWT fields, reset/invite flows,
  feature flags, and cache boundaries.
- Parameter discovery: run `arjun` only after route and method baselines exist,
  then save discovered parameters with the target URL.
- Flask cookies: use `flask-unsign` only when a Flask signed cookie or secret
  key hypothesis is evidenced.
- Filtering and public context: use `wafw00f` when WAF behavior changes probe
  interpretation, and use `shodan` only for challenge-owned or explicitly
  scoped public targets.
- Manual proxying: record Burp Suite or Caido when either GUI materially shapes
  request construction, comparison, or replay.
- Source disclosure: test traversal, backup files, template includes, archive
  extraction, XXE, file handlers, and error oracles.
- Policy oracle: build a table of granted, denied, row-count, timing, and
  error-shape differences.
- Mutation: log every POST/PUT/PATCH/DELETE, import, webhook, admin, or job
  side effect in `work/MUTATION_LEDGER.md`.
- Render/runtime: separate uploads, previews, converters, templates, PDFs,
  images, and schedulers; preserve job ids and rendered output.
- SSRF/internal: classify reflected, stored, blind, and semi-blind channels
  with low-impact probes.

Stop or escalate when:

- The useful artifact is leaked source, binary, key material, or a sandbox.
- Session state is drifting and probes are no longer comparable.
- Remote state mutation is not understood.

## Crypto

First pass:

- Extract exact parameters, encodings, ciphertexts, public keys, transcripts,
  source code, oracle endpoints, and sample pairs.
- Normalize every numeric value and byte encoding in a local script.
- Write the attack assumption explicitly before coding the attack.

Attack loop:

- Classify primitive: RSA, ECC, lattice, PRNG, stream cipher, block mode,
  hash/MAC/signature, commitment, ZK, custom algebra, or protocol oracle.
- Use `RsaCtfTool` for RSA key/ciphertext cases with concrete public
  parameters.
- Use `z3` for explicit finite constraints, `fplll` for lattice reduction, and
  `gp`/PARI-GP for number-theory calculations when parameters justify them.
- For oracles, record input, output, error class, timing, rate limit, and query
  budget before adaptive exploitation.
- Use Sage only when math structure justifies it; keep a Python verifier when
  possible.
- Verify recovered plaintext, key, seed, nonce, or flag with an independent
  deterministic check.

Stop or escalate when:

- Parameters came from a binary or source extraction that is not yet reliable.
- Oracle behavior is unstable or remote-only without transcript replay.
- The issue is actually encoding, parsing, or web transport.

## Forensics

First pass:

- Hash and classify every image, archive, pcap, memory dump, log, document, and
  extracted file before mutation.
- Record container/archive nesting, timestamps, timezone assumptions, file
  systems, packet counts, and tool versions.
- Preserve original artifacts in `dist/`; write extracted material under
  `work/` with source offsets and hashes.

Analysis loop:

- Split artifact inventory, timeline, carving, memory/network, and crypto
  bridge work.
- Use `tshark` for packet inventories, filters, and stream reconstruction; use
  `vol`/Volatility3 for memory dumps only with recorded plugin assumptions.
- Use `zsteg` or `stegolsb` only when carrier properties suggest bit-plane or
  LSB extraction.
- Use `floss`, `yara`, and `upx` on recovered suspicious binaries before
  routing them to reverse engineering or malware.
- Reassemble streams and carved files with command logs and provenance.
- Route recovered binaries, keys, ciphertext, or web traces to the matching
  category only after preserving boundary evidence.

Stop or escalate when:

- A recovered artifact is now a normal crypto, rev, pwn, web, or malware task.
- Extraction changes data without hashes or source offsets.
- Memory symbols, profiles, or packet metadata are missing.

## Jail And Sandbox

First pass:

- Identify interpreter, version, blacklist, allowlist, parser, evaluation
  context, timeout, builtins, imports, filesystem, and environment.
- Build a local reproducer when source or prompt behavior allows it.
- Log rejected payload families and exact error messages.

Analysis loop:

- Group payloads by bypass family: encoding, object graph, parser confusion,
  import recovery, builtins recovery, shell escape, template escape, SQL escape,
  JS/browser escape, or syscall surface.
- Compare local and remote behavior before relying on a payload.
- Preserve the final accepted payload and output transcript.

Stop or escalate when:

- The restriction is just a web injection path without a jail.
- The useful primitive is native sandbox escape and should move to pwn.
- Local and remote versions diverge without a recorded delta.

## Programming And PPC

First pass:

- Extract constraints, examples, input grammar, output grammar, scoring rules,
  and time limits.
- Write sample tests before remote automation.
- Preserve remote prompt transcripts and hidden-state observations.

Analysis loop:

- Build deterministic solvers under `work/`.
- Use timeouts, retries, transcript capture, and local fixtures for interactive
  services.
- Keep generated inputs and outputs if they materially prove the solve.

Stop or escalate when:

- The core is crypto, binary exploitation, reverse engineering, or web behavior.
- Manual-only progress cannot be replayed.
- Search space is unbounded and needs a narrower hypothesis.

## Stego

First pass:

- Hash carriers and record dimensions, codec, channels, metadata, thumbnails,
  chunk structure, frame count, palette, and compression.
- Avoid broad blind extraction until a hint or carrier property justifies it.

Analysis loop:

- Test metadata, appended data, archive signatures, bit planes, palettes, audio
  channels, frame deltas, transforms, and text encodings with provenance.
- Use `zsteg` for PNG/BMP-style channel and bit-plane hypotheses; use
  `stegolsb` for explicit LSB extraction hypotheses.
- Rehash recovered payloads and route them to forensics, crypto, rev, or misc as
  soon as they become conventional artifacts.

Stop or escalate when:

- The carrier is lossy or modified and the hypothesis depends on exact bits.
- Extraction yields a normal archive, binary, ciphertext, or script.
- Too many tools are being run without a discriminating observation.

## OSINT

First pass:

- Confirm challenge scope and avoid unrelated private targets.
- Record clue text, names, handles, domains, image metadata, location hints,
  time windows, and language assumptions.

Analysis loop:

- Track every source with URL, access date, archive link when available, and
  screenshot when useful.
- Disambiguate identities and locations with multiple independent clues.
- Keep the final answer tied to cited evidence, not memory.

Stop or escalate when:

- Evidence points to a downloadable technical artifact for another category.
- The identity or location remains ambiguous.
- The path would require private or out-of-scope access.

## Mobile

First pass:

- Hash APK/IPA/source/app-data artifacts.
- Extract manifests, resources, signing info, package names, URLs, native
  libraries, storage paths, and permissions.

Analysis loop:

- Use jadx/apktool only when the artifact justifies it.
- Use `frida-ps` and `frida` only after static findings identify a runtime
  target and a scoped device or emulator is available.
- Recover secrets, crypto, API endpoints, local checks, feature gates, and
  native logic with snippets and commands.
- Replay API or local verifier behavior without device-only state when
  possible.

Stop or escalate when:

- The mobile app reduces to web, crypto, rev, or native pwn.
- Dynamic device behavior is required but no local/replay path exists.
- A recovered secret is not independently verified.

## Malware

First pass:

- Treat suspicious artifacts static-first.
- Hash samples, classify file types, extract strings/imports/resources, and
  note packers, persistence clues, network clues, and embedded payloads.

Analysis loop:

- Recover packed layers, configs, decryptors, indicators, and payloads without
  uncontrolled execution.
- Use `floss`, `yara`, and `upx` for static string, rule, and packer triage;
  use `tshark` or `vol` when supplied packet or memory artifacts drive behavior
  claims.
- Use memory or pcap evidence to model behavior when provided.
- Validate extracted config or decrypted content with narrow scripts.

Stop or escalate when:

- Safe dynamic execution would be required but no sandbox is established.
- The sample becomes a standard rev, forensics, or crypto task.
- Behavior claims lack static, memory, pcap, or transcript evidence.

## Web3

First pass:

- Collect contract source/bytecode, ABI, deployment addresses, chain id, RPC or
  local fork details, balances, storage, transactions, and challenge goals.
- Confirm the target is a challenge-owned chain or local fork.

Analysis loop:

- Model storage, access control, invariants, signatures, block assumptions,
  randomness, and token/accounting flows.
- Use `slither` for source-backed static checks, then verify findings through a
  transaction or state proof.
- Use `anvil` for local chains or forks before live challenge transactions.
- Build local exploit transactions or scripts first.
- Preserve transaction input, output, state diff, and final verification.

Stop or escalate when:

- The primitive is normal cryptography and should move to crypto.
- The target is a real third-party account or chain outside scope.
- Block data assumptions are not reproducible.

## Cloud And Container

First pass:

- Freeze authorization boundary, challenge-provided credentials, configs,
  images, manifests, logs, local endpoints, and secret-handling rules.
- For containers, hash images/layers and record users, caps, mounts, sockets,
  environment, entrypoints, and Kubernetes context.

Analysis loop:

- Cloud: analyze identity policy, metadata, storage, serverless, logs, and
  deployment paths independently.
- Container: reproduce runtime behavior, namespace/cgroup state, filesystem
  layout, kernel interfaces, and escape surface locally.
- Use `crane` or `skopeo` for scoped registry metadata, `syft` for package/SBOM
  inventory, and `grype` or `trivy` for vulnerability, secret, or
  misconfiguration clues in challenge-owned images.
- Preserve sanitized command transcripts and never store real secrets in notes.

Stop or escalate when:

- Authorization boundary is unclear.
- Behavior is host-specific and not reproduced.
- The recovered artifact is a standard web, pwn, crypto, or forensics task.

## AI/ML

First pass:

- Freeze prompts, hidden instructions, tool descriptions, datasets, model
  artifacts, transcripts, retrieval context, and non-determinism settings.
- Do not store API secrets or real credentials.

Analysis loop:

- Test prompt injection, instruction hierarchy, classifier behavior, embedding
  retrieval, agent tools, and downstream browser/API effects with transcripts.
- Sample nondeterministic outputs enough to distinguish signal from noise.
- Route concrete web/API/tool effects to the matching category when evidenced.

Stop or escalate when:

- Reproduction requires unavailable secrets.
- Output variation is not sampled.
- The task becomes ordinary web, crypto, or data parsing.

## Hardware/RF And Side-Channel

First pass:

- Record raw traces, sample rate, capture format, channel, modulation hints,
  hardware notes, firmware, timing logs, oracle behavior, and hashes.
- Preserve raw data unchanged; write derived data under `work/`.

Analysis loop:

- Hardware/RF: decode modulation, framing, symbols, packets, and protocol
  fields with command provenance.
- Side-channel: define timing, power, cache, fault, or leakage model with
  sample counts and confidence notes.
- Verify recovered secrets or payloads with an independent deterministic check.

Stop or escalate when:

- Capture metadata is missing.
- Hardware-only reproduction is required and unavailable.
- Recovered firmware, crypto, or protocol data belongs to another category.

## Hybrid Chains

First pass:

- Name the boundary artifact that justifies each category switch.
- Keep source category evidence, intermediate artifacts, and destination
  category assumptions separate.

Analysis loop:

- Run one category at a time with explicit stop conditions.
- Preserve handoff notes and artifacts.
- Build an integrated replay command only after individual steps have evidence.

Stop or escalate when:

- Category switching is based on intuition instead of an artifact.
- Intermediate artifacts are not preserved.
- Final proof scope is unclear.

## Misc

First pass:

- Treat misc as a router until evidence proves a narrower domain.
- Inventory files, protocol samples, constraints, remote prompts, and scoring
  rules.
- Build a minimal local model of the input/output state before automation.

Solve loop:

- Protocol model: states, tokens, grammar, transitions, and failure responses.
- Parser state: serialization, compression, Unicode, archive, image, and
  ambiguity tests.
- Automation solver: deterministic script with samples, timeouts, retries, and
  saved final transcript.
- Category router: escalate only when an artifact changes domain.

Stop or escalate when:

- The task becomes crypto math, binary analysis, web behavior, forensics, or a
  jail escape.
- Manual progress cannot be replayed.
- The remote protocol has hidden state that needs transcript capture first.
