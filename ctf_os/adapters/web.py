from __future__ import annotations

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


class WebAdapter(GenericAdapter):
    name = "web"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        # No remote request is launched during intake.  It must first be matched
        # to the per-challenge target allowlist.
        return (
            ExperimentSpec(
                "local_source_inventory",
                "map local routes, state transitions, and trust boundaries",
                ("find", "/challenge", "-maxdepth", "3", "-type", "f"),
                "route/state-transition candidates with source locators",
                "one authorization or state invariant can be stated",
                "no local source is provided",
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        return tuple(
            ProgressMarker(key, label, "HTTP/browser trace or exact source locator")
            for key, label in (
                ("endpoint_observed", "endpoint observed at runtime"),
                ("auth_state_captured", "role-scoped authentication state captured"),
                ("state_modeled", "state transition modeled"),
                ("invariant_identified", "security invariant identified"),
                ("preconditions_met", "exploit preconditions met"),
                ("exploit_demonstrated", "exploit demonstrated"),
                ("impact_verified", "impact independently verified"),
                ("flag_reached", "intended flag path reached"),
            )
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="remote_independent" if remote else "deterministic",
            clean_repetitions=1 if remote else 3,
            remote_repetitions=2 if remote else 0,
            notes="keep local and remote proof separate; obey host rate limits",
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "route_list_without_model",
            "missing_precondition",
            "authorization_assumption",
            "session_identity_crossover",
            "missing_runtime_timeline",
            "rate_limited",
            "remote_state_drift",
        )

    def captain_guidance(self) -> str:
        return (
            "Model state transitions and invariants before enumerating payloads. "
            "Record authentication and business preconditions. For dynamic Web "
            "work, run /opt/ctf-templates/web/request.py or ctf-browser with "
            "--session attacker|user|admin so both tools share isolated cookie "
            "jars and one redacted timeline. "
            "Inspect local SQLite artifacts with ctf-sqlite-readonly; exercise "
            "remote SQL behavior only through the allowlisted HTTP helpers. "
            "Never copy cookie or token values into prompts. Remote requests "
            "require an explicit target allowlist and shared host rate limit."
        )
