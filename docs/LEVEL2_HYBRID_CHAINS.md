# Level 2 Hybrid Chains

Hybrid chains are used when evidence crosses category boundaries. Start from the first category that produced a concrete artifact, then switch only when the artifact demands it.

## Common Workflow Contract

1. Name the source artifact and where it came from.
2. State the boundary crossed, such as request payload to native crash.
3. Preserve the command or interaction that reproduces the boundary.
4. Add the next category skill only for the new artifact type.
5. Validate the final claim with `tools/replay_runner.py` and `tools/proof_validate.py`.

## web -> pwn

- Trigger: a web endpoint uploads, parses, deserializes, or invokes a native component.
- Evidence: HTTP request/response, uploaded file, native binary or crash trace, local reproducer.
- Local flow: use `ctf-web` to isolate the input path, then `ctf-pwn` for memory corruption, exploitation, and final command proof.
- Stop condition: replay creates the same crash, leak, shell command, or flag retrieval without manual browser state.

## rev -> crypto

- Trigger: reverse engineering reveals a custom cipher, key schedule, packed constant, or verifier.
- Evidence: binary hash, disassembly notes, extracted constants, solver script.
- Local flow: use `ctf-rev` for extraction and `ctf-crypto` for mathematical recovery.
- Stop condition: replay extracts or documents constants and runs the solver from clean challenge state.

## forensics -> crypto

- Trigger: a disk, memory, packet, image, or archive artifact contains encrypted data or key material.
- Evidence: source artifact hash, extraction command, encrypted blob, recovered key or parameters.
- Local flow: use `ctf-forensics` for acquisition and carving, then `ctf-crypto` for recovery.
- Stop condition: replay derives the key or plaintext from preserved artifacts.

## cloud -> container

- Trigger: cloud metadata, IAM, service config, or deployment files expose a container or Kubernetes path.
- Evidence: config files, local manifests, image digests, logs, commands run against owned/local targets.
- Local flow: use `ctf-cloud` for identity and service context, then `ctf-container` for image, pod, or namespace analysis.
- Stop condition: replay demonstrates the local/owned container path and final result without touching unrelated infrastructure.

## web3 -> crypto

- Trigger: smart contract behavior depends on signatures, hashes, commitments, PRNG, or elliptic-curve misuse.
- Evidence: contract source/bytecode, chain state, transaction inputs, solver script.
- Local flow: use `ctf-web3` for contract and transaction context, then `ctf-crypto` for primitive analysis.
- Stop condition: replay proves the exploit input or key recovery against local or recorded chain state.

## AI -> web

- Trigger: prompt injection, tool use, agent browsing, or model output becomes a web exploit path.
- Evidence: prompt transcript, model/tool output, generated URL/request, web response.
- Local flow: use `ctf-ai-ml` for prompt and model behavior, then `ctf-web` for the concrete web primitive.
- Stop condition: replay shows the prompt-to-request path and the web-side effect with secrets redacted.
