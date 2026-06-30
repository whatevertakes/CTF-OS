purpose: Analyze container, image, namespace, runtime, and Kubernetes CTF artifacts in local or owned environments.
when_to_use:
- The challenge provides an image, Dockerfile, manifest, pod context, namespace clue, or local container service.
when_not_to_use:
- The work would target infrastructure outside challenge authorization.
inputs:
- Images, Dockerfiles, manifests, logs, local runtime state, or extracted filesystems.
outputs:
- Image inventory, privilege/path findings, exploit or escape proof, and replay command.
dependencies:
- `skills/ctf-triage/SKILL.md`
- kCTF and Kubernetes Goat references only.
reference_digest:
- `docs/reference-digests/cloud-container.md`
evidence produced:
- Image digests, file listings, config extracts, command output, and replay logs.
failure/blocker classes:
- Missing image or runtime.
- Host-specific behavior not reproducible.
- Scope boundary unclear.
future agent consumers:
- Container solver.
- Cloud solver.
- Hybrid-chain solver.
workflow:
- Hash images, Dockerfiles, manifests, extracted layers, logs, and filesystem dumps.
- Record users, capabilities, mounts, sockets, environment, entrypoints, seccomp, AppArmor, and Kubernetes context.
- Reproduce runtime behavior locally before considering namespace, cgroup, socket, or host interfaces.
- Preserve extracted filesystem paths under `work/` and durable proof transcripts under `evidence/`.
- Route recovered services to web, native binaries to pwn/rev, and policies to cloud only after boundary evidence exists.
first_commands:
- `docker image inspect <image>` when an image is provided.
- `docker run --rm ...` only within challenge scope.
- `find work/rootfs -maxdepth 3 -type f -print`
- `python3 tools/replay_runner.py <challenge-dir>`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
