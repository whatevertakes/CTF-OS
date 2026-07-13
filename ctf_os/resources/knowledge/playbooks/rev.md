# Reverse engineering playbook

## Scope and recon

Analyze only provided binaries, bytecode, mobile packages, or source inside the attempt container. Identify format, architecture, libraries, embedded data, packers, strings, and execution inputs with `file`, `strings`, hashes, and controlled local runs. Copy untouched originals and log each transformation.

## Hypotheses and tooling

Map the input-to-check path before attempting a solve. Use `radare2`, `gdb-multiarch`, `ltrace`, `strace`, `angr`, and small Python helpers. Branch APK/JAR work to `jadx` and `apktool`, WebAssembly to `wabt` and `wasmtime`, .NET to Mono, and packed files to `upx`. Consider symbolic constraints or custom-VM lifting only when static or dynamic evidence supports them.

## Validation and replay

Validate a candidate by tracing the exact comparison branch or by replaying the program with a captured input. Keep scripts, patched copies clearly labeled, function addresses for the original hash, and concise notes about assumptions. Do not treat an unverified decoded string as a result.
