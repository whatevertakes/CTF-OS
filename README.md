# CTF-OS

CTF-OS is a local-first, multi-node CTF solver. Each teammate runs their own local Codex attempts and isolated Docker containers. TeamSync shares append-only status, findings, and challenge-owned flags; it does not control remote workers or auto-submit to CTFd.

## Quick start

```bash
git clone https://github.com/whatevertakes/ctf_workspace.git
cd ctf_workspace
uv sync --frozen
uv run ctf-os init "SCA CTF 2026" --config config.yaml
```

Edit `config.yaml` with your team's `contest.team_id`, your member name, and owned categories. Add the authorized contest and challenge metadata to `incoming/SCA CTF 2026/contest.md`.

Build the shared image once and migrate local state:

```bash
scripts/deploy_ctf_os.sh --config config.yaml
uv run ctf-os doctor --config config.yaml --non-mock
```

`ctf-os run` never builds the Docker image automatically.

## Run a local node

```bash
uv run ctf-os parse --config config.yaml
uv run ctf-os run --config config.yaml
uv run ctf-os run --once --config config.yaml
```

Inspect state and challenge-owned flags:

```bash
uv run ctf-os tui --config config.yaml
uv run ctf-os tui --plain --config config.yaml
```

Local controls affect only the current node:

```bash
uv run ctf-os pause <challenge> --config config.yaml
uv run ctf-os resume <challenge> --config config.yaml
uv run ctf-os retry <challenge> --config config.yaml
```

## Two teams in one contest

Each team must have a distinct `team_id`, SQLite output path, and TeamSync namespace. Do not reopen a database bound to another team.

```yaml
# config-sca-a.yaml
contest:
  name: "SCA CTF 2026"
  team_id: "sca-team-a"
paths:
  incoming: "incoming"
  output: "output/sca-team-a"
sync:
  root: "sync/sca-team-a"
  team_namespace: "sca-team-a"
```

For the other team, use `sca-team-b` consistently in all four values. Then migrate, parse, and inspect with the explicit config:

```bash
uv run ctf-os state migrate --config config-sca-a.yaml
uv run ctf-os parse --config config-sca-a.yaml
uv run ctf-os doctor --config config-sca-a.yaml --non-mock
```

### KISIA four-member example

One local-only team can use the shared `team_id` `sca-jiwoong-team` while
each member runs a separate node and owns only their assigned categories:

| Member | Example ownership |
| --- | --- |
| jiwoong | pwn, web |
| jueon | rev, crypto |
| hyunseok | forensics, misc |
| howon | cloud, web3 |

Each member has their own `member.name`, local SQLite database, containers,
and Codex login. TeamSync shares challenge-owned events only; it never starts
or stops another member's local process.

## Team update

```bash
git pull --ff-only origin main
scripts/deploy_ctf_os.sh --config config.yaml
```

Local `config.yaml`, contest input, SQLite databases, artifacts, TeamSync ledgers, credentials, keys, and flags must not be committed. See [team deployment](docs/CTF_OS_TEAM_DEPLOYMENT.md) for the complete deployment procedure.
