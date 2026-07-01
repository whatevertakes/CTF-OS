# WSL2 Setup

This is the stage 1 setup path for team members running Codex on Ubuntu WSL2.
It installs only the baseline dependencies needed to collect reproducible CTF
solve data for later Level 3 design work.

## Clone

```bash
git clone git@github.com:whatevertakes/ctf_workspace.git
cd ctf_workspace
```

Do not work directly on `main`. Use a data branch for challenge outputs:

```bash
git switch -c data/<github-user>/<challenge-or-run-id>
```

## Bootstrap

Run the bootstrap script from the repository root:

```bash
tools/bootstrap_wsl2.sh
```

The script installs the team-parity Ubuntu, Python, Ruby, MCP, and reversing
tool surface, creates `.venv`, installs `requirements.txt`, rewrites
`.codex/config.toml` absolute paths for the local clone, and runs:

```bash
python3 tools/preflight_check.py --strict-optional
```

If system packages are already managed separately:

```bash
tools/bootstrap_wsl2.sh --skip-apt
```

If Python dependencies are already installed:

```bash
tools/bootstrap_wsl2.sh --skip-python
```

For a lightweight baseline only, without the full parity toolchain:

```bash
tools/bootstrap_wsl2.sh --minimal
```

## Docker

Docker is part of the baseline because many challenge replays depend on local
service topology. If `docker info` fails with a permission error after install:

```bash
sudo usermod -aG docker "$USER"
```

Then restart the WSL2 shell and rerun:

```bash
. .codex/env.sh
python3 tools/preflight_check.py
```

## Expected Output

`tools/preflight_check.py --strict-optional` should end with zero failures. The
team parity check should also pass:

```bash
python3 tools/check_team_parity.py
```

## Data Goal

Stage 1 does not ask runners to change framework files. The goal is only to
make every runner produce comparable challenge data:

```text
challenges/<event>/<category>/<challenge>/state.json
challenges/<event>/<category>/<challenge>/notes.md
challenges/<event>/<category>/<challenge>/replay.sh
challenges/<event>/<category>/<challenge>/evidence/*.summary.md
benchmarks/*_SANITIZED_BENCHMARK_REPORT.md
```
