purpose: Analyze mobile CTF artifacts such as APKs, IPAs, app data, and mobile protocol logic.
when_to_use:
- The challenge provides a mobile package, app source, device artifact, or mobile API flow.
when_not_to_use:
- The app artifact has already reduced to a plain web, crypto, or reverse task.
inputs:
- APK/IPA, source, manifests, resources, logs, traffic captures, or extracted data.
outputs:
- Artifact inventory, static findings, recovered secrets or logic, and replayable proof.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional jadx, apktool, or frida references when required.
evidence produced:
- Hashes, manifest/resource extracts, decompiled snippets, commands, and replay logs.
failure/blocker classes:
- Missing app artifact.
- Tooling not installed and not justified by evidence.
- Device-only behavior without a local path.
future agent consumers:
- Mobile solver.
- Reverse solver.
- Crypto solver.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
