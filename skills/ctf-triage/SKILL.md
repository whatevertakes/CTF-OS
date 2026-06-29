purpose: Create and route a challenge workspace with minimal state, notes, replay, evidence, dist, and work structure.
when_to_use:
- A new challenge needs a local directory and initial category selection.
- Existing artifacts need to be normalized before solving.
when_not_to_use:
- A challenge workspace already exists and the next step is category-specific analysis.
inputs:
- Event, category, and challenge name.
- Initial files, service details, prompts, or URLs supplied by the user.
outputs:
- `challenges/<event>/<category>/<name>/` with notes, state, replay script, evidence, dist, and work directories.
- Initial routing recommendation to a category or hybrid skill.
dependencies:
- `tools/intake_challenge.py`
- `templates/challenge/`
evidence produced:
- Created challenge tree and initial `state.json`.
failure/blocker classes:
- Unsafe path component.
- Missing challenge artifacts.
- Ambiguous category requiring `ctf-misc` until evidence clarifies the domain.
future agent consumers:
- Category solvers.
- Proof and replay agents.
pointers:
- `docs/LEVEL2_CAPABILITY_MAP.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
