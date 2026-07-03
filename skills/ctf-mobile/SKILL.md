---
name: ctf-mobile
description: Analyze mobile CTF artifacts such as APKs, IPAs, app data, and mobile protocol logic.
---

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
- Optional jadx, apktool, adb, objection, frida, and frida-ps references when
  required.
reference_digest:
- `docs/reference-digests/mobile.md`
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
workflow:
- Hash APK, IPA, source, app data, logs, and traffic artifacts.
- Extract manifests, resources, signing information, package names, URLs, native libraries, storage paths, and permissions.
- Use jadx, apktool, strings, and local scripts only when the artifact justifies them.
- Use adb only for scoped local devices or emulators, and record device state
  before mutation.
- Use objection only after a concrete runtime instrumentation target is known.
- Use frida-ps and frida only after static evidence identifies runtime-only
  logic or instrumentation targets; record package/process names and scripts.
- Recover secrets, crypto, API endpoints, feature gates, native checks, and local verifier logic with snippets and commands.
- Replay API or local verifier behavior outside device-only state when possible.
- Route reduced web, crypto, rev, or pwn work to the matching category with boundary evidence.
first_commands:
- `file dist/*`
- `sha256sum dist/*`
- `jadx -d work/jadx <apk>` when APK analysis is justified.
- `apktool d -o work/apktool <apk>` when resource/smali analysis is justified.
- `adb devices` when a scoped device or emulator is required.
- `objection --gadget <package> explore` when runtime instrumentation is justified.
- `frida-ps -Uai` when a scoped device or emulator is available and dynamic instrumentation is justified.
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
