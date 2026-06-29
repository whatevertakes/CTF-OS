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
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
