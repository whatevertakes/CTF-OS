# Mobile Reference Digest

## Trusted Sources

- `ref:jadx`: Android decompilation reference.
- `ref:apktool`: APK resources and smali reference.
- `ref:frida`: dynamic instrumentation reference.
- `ref:mobsf`: mobile analysis checklist reference.
- `ref:owasp_cheatsheets`: mobile-relevant weakness guidance.

## CTF-Relevant Patterns

- Hash APK/IPA/source/app-data artifacts before extraction.
- Extract manifests, resources, signing info, package names, URLs, native libraries, storage paths, permissions, and hardcoded constants.
- Recover API endpoints, feature gates, crypto keys, native checks, and local verifier logic with snippets and commands.
- Replay API or local verifier behavior outside device-only state when possible.

## CWE/CVE Mapping

- Map insecure storage, crypto misuse, hardcoded credentials, exported components, and WebView issues only after manifest/source evidence.
- Use CVEs only with exact dependency or platform version evidence.

## Canonical Papers And Deep Dives

- OWASP MAS-style testing concepts are useful for mobile weakness classes.
- Dynamic instrumentation references apply only after static evidence justifies runtime probing.

## When To Use

- Use for APKs, IPAs, app source, app data, mobile traffic captures, and native mobile checks.

## When Not To Use

- Do not use once the app reduces cleanly to web, crypto, rev, or native pwn.

## Source Anchors

- `idx:mobile:jadx:overview`
- `idx:mobile:apktool:overview`
- `idx:mobile:frida:overview`
- `idx:mobile:mobsf:overview`
- `idx:mobile:owasp_cheatsheets:overview`
- `idx:mobile:hacktricks:overview`
