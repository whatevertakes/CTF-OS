# CTF Workspace

This repository is the canonical CTF execution workspace for the
`whatevertakes` team project.

The architecture is intentionally fixed. The owner maintains the framework,
skills, tools, documentation, benchmark definitions, and repository policy.
Benchmark runners execute assigned CTF cases and submit only sanitized run data.

## Roles

- Owner: `jiwoongchoi-norun`
  - Owns `main`.
  - Reviews and merges all changes.
  - May edit framework files, tools, skills, docs, templates, and benchmark
    definitions.
- Benchmark runners:
  - Clone the repository and keep the same workspace layout.
  - Run assigned benchmark CTF problems.
  - Submit sanitized benchmark data only.
  - Do not edit framework architecture, tools, skills, templates, reference
    indexes, or policy files.

## Clone And Setup

Use the same repository layout locally:

```bash
git clone git@github.com:whatevertakes/ctf_workspace.git
cd ctf_workspace
```

Run the WSL2 bootstrap:

```bash
tools/bootstrap_wsl2.sh
```

This installs the baseline Ubuntu packages, creates `.venv`, installs
`requirements.txt`, rewrites local Codex absolute paths in `.codex/config.toml`,
and runs the preflight check. See [docs/SETUP_WSL2.md](docs/SETUP_WSL2.md) for
the detailed team setup flow.

If you need to install pieces manually, use commands and package managers, not
vendored dependencies:

```bash
sudo apt-get update
sudo apt-get install -y bash binutils binutils-avr build-essential ca-certificates curl docker.io file gdb gcc-avr git jq libffi-dev libssl-dev netcat-openbsd nodejs npm pkg-config python3 python3-pip python3-venv unzip xz-utils avr-libc
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -r requirements.txt
```

Validate the workspace:

```bash
python3 tools/preflight_check.py
python3 tools/evaluate_corpus.py
```

## Workspace Layout

Keep every challenge under the standard contract:

```text
challenges/<event>/<category>/<challenge>/
  state.json
  notes.md
  replay.sh
  evidence/
  dist/
  work/
```

- `dist/`: original challenge handouts.
- `work/`: local scratch files, extracted files, build output, probes, and
  temporary dependency checkouts. Do not submit broad vendored dependencies or
  local build trees.
- `evidence/`: replay summaries and sanitized proof outputs.
- `state.json`, `notes.md`, `replay.sh`: durable benchmark run metadata.

## Benchmark Runner Workflow

Run an assigned challenge:

```bash
python3 tools/benchmark_runner.py run challenges/<event>/<category>/<challenge>
```

Re-check corpus consistency:

```bash
python3 tools/evaluate_corpus.py
```

If raw logs or outputs contain flags, tokens, keys, or challenge secrets,
sanitize them before submitting:

```bash
python3 tools/report_sanitize.py challenges/<event>/<category>/<challenge>/evidence/<raw-log>.log --check
```

## Submission Policy

Benchmark runners may submit only data paths:

```text
benchmarks/*_SANITIZED_BENCHMARK_REPORT.md
challenges/<event>/<category>/<challenge>/state.json
challenges/<event>/<category>/<challenge>/notes.md
challenges/<event>/<category>/<challenge>/replay.sh
challenges/<event>/<category>/<challenge>/evidence/*.summary.md
```

The following paths are owner-only:

```text
AGENTS.md
.codex/
.github/
tools/
templates/
skills/
capabilities/
docs/
benchmarks/corpus.yaml
references.yaml
references.lock.json
```

Do not submit:

```text
flags, tokens, private keys, .env files
raw replay logs containing secrets
work/extracted/
work/docker_pinned/
work/pinned_build/
work/simavr*/
local virtualenvs, caches, node_modules, or build output
```

## Git Workflow

The canonical repository is owner-controlled. Runners should not push to
`main`.

Use a data branch or fork branch:

```bash
git switch -c data/<github-user>/<benchmark-id>/<run-id>
git add benchmarks/*_SANITIZED_BENCHMARK_REPORT.md \
  challenges/<event>/<category>/<challenge>/state.json \
  challenges/<event>/<category>/<challenge>/notes.md \
  challenges/<event>/<category>/<challenge>/replay.sh \
  challenges/<event>/<category>/<challenge>/evidence/*.summary.md
git commit -m "submit benchmark data for <benchmark-id>"
git push -u origin data/<github-user>/<benchmark-id>/<run-id>
```

Open a pull request to `main`, or attach the same sanitized files to a GitHub
issue when direct branch push is not available. The owner validates and merges
accepted data.

Before opening a pull request, run:

```bash
python3 tools/validate_data_submission.py --base origin/main
```

See [docs/TEAM_DATA_WORKFLOW.md](docs/TEAM_DATA_WORKFLOW.md) for the full
data-only submission flow.
