# Release packaging verification

Build release artifacts from a clean `dist/` directory with the locally
resolved lockfile:

```bash
rm -rf dist
uv lock --check
SOURCE_DATE_EPOCH=0 uv build
python scripts/normalize_sdist.py dist/ctf_os-0.1.0.tar.gz
```

The wheel must contain the current filesystem-spool broker, disabled Codex
network profile, schema-v3 state code, model-routing resource, sandbox
Dockerfile and entrypoint, and watcher. The sdist must contain those package
files plus `config/`, `sandbox/`, the example config, documentation, and
tests so it can independently rebuild the same wheel.

`normalize_sdist.py` removes setuptools' build-time tar and gzip timestamps
from the source distribution. It changes only archive metadata, not member
contents, modes, or paths; use the same `SOURCE_DATE_EPOCH` for reproducible
release hashes.

Before publishing, extract both artifacts and compare the release-critical
files byte-for-byte with the checkout. In the extracted core package files,
verify authenticated filesystem-spool atomic publish and a
`network={enabled=false` Codex profile. Then install only the wheel in a fresh
virtual environment and smoke-test
`ctf-os --help`, model routing, mock-safe `init`, and `doctor`.
