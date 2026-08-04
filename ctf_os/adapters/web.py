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
            "work in an ordinary managed command action, use the stateless "
            "canonical HTTP helper form "
            "`/opt/ctf-templates/web/request.py URL -X METHOD ...`; URL is the "
            "required positional argument, so never use `--url` (for example, "
            "`/opt/ctf-templates/web/request.py http://target/path -X GET`). "
            "When expected_observation, keep_if, or drop_if depends on response "
            "body text, add one `--observe-text HARMLESS_MARKER` per bounded, "
            "non-secret marker. The helper publishes only status, byte count, "
            "body/marker hashes, and marker presence; it never prints the body "
            "or marker in that summary. Managed remote Web commands fail closed "
            "if no canonical helper response summary reaches durable stdout. "
            "Omit `--session` from generic command actions because their shell "
            "execution path has no engine private-state boundary. Persistent "
            "`--session attacker|user|admin` roles are reserved for an "
            "engine-owned typed Web gate or another execution path that "
            "explicitly supplies that boundary; do not emulate them in a "
            "generic command. Use ctf-browser statelessly under the same rule. "
            "Inspect local SQLite artifacts with ctf-sqlite-readonly; exercise "
            "remote SQL behavior only through the allowlisted HTTP helpers. "
            "Never copy cookie or token values into prompts. Remote requests "
            "require an explicit target allowlist and shared host rate limit."
        )
