# CTF-OS team deployment

Each member runs CTF-OS locally. Pulling `main` distributes the code, but does
not distribute or overwrite another member's configuration, SQLite state,
contest input, output, TeamSync ledger, Codex login, or Docker containers.

## Update an existing node

Commit or stash unrelated source edits before updating. Local runtime files are
Git-ignored and remain on the member's machine.

```bash
git pull --ff-only origin main
scripts/deploy_ctf_os.sh --config config.yaml
uv run ctf-os doctor --config config.yaml --non-mock
```

The deployment script is idempotent. It performs `uv sync --frozen`, opens the
configured local SQLite database to run the repository's ordered transactional
migrations, builds `ctf-os-sandbox:latest` only when it is absent, and always
runs the sandbox smoke test. The smoke test verifies the installed CTF tools,
shared image ID, 16 GiB hard memory limit, zero memory reservation, 2 vCPU
quota, and no CPU pinning. `ctf-os run` never builds the image automatically.

To intentionally replace an existing image after the Dockerfile changes:

```bash
scripts/deploy_ctf_os.sh --config config.yaml --rebuild-image
```

For a machine that is temporarily unable to use Docker, install and migrate
only with `--skip-image`. This does not make the node ready for real solver
attempts; run the normal command later to build and verify the image.

```bash
scripts/deploy_ctf_os.sh --config config.yaml --skip-image
```

## First installation

Create the member-local configuration before asking the deployment script to
migrate state. Review `config.example.yaml` and use the member's own identity
and owned categories.

```bash
uv sync --frozen
uv run ctf-os init "CONTEST NAME" --config config.yaml
# Review config.yaml and incoming/CONTEST NAME/contest.md.
scripts/deploy_ctf_os.sh --config config.yaml
uv run ctf-os doctor --config config.yaml --non-mock
```

Do not commit `config.yaml`, `incoming/`, `output/`, `sync/`, SQLite files,
logs, credentials, keys, or flags. The script does not delete, reset, copy, or
publish any of those paths.

## Separate verification steps

The operations can also be run independently:

```bash
uv sync --frozen
uv run ctf-os state migrate --config config.yaml
docker build -f sandbox/Dockerfile.sandbox -t ctf-os-sandbox:latest .
scripts/verify_sandbox_image.sh ctf-os-sandbox:latest
```

The explicit `docker build` command is a one-time node setup operation, not a
challenge or attempt lifecycle action.
