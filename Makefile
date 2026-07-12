.PHONY: test team-bundle benchmark-smoke benchmark-real benchmark-compare benchmark-compare-real validate-profiles smoke-profiles

test:
	uv run pytest -q

team-bundle:
	scripts/build_team_bundle.sh

validate-profiles:
	uv run python scripts/validate_profiles.py

smoke-profiles:
	uv run python scripts/smoke_profiles.py

benchmark-smoke:
	uv run python benchmarks/run.py --mode smoke

benchmark-real:
	uv run python benchmarks/run.py --mode real

benchmark-compare:
	uv run python benchmarks/run.py --mode compare

benchmark-compare-real:
	uv run python benchmarks/run.py --mode compare-real --challenge pwn-format
