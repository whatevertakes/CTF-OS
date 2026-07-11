# Solve-rate-first solver design

This policy optimizes valid-flag solve rate, not prose quality, evidence volume,
or model cost. Safety and candidate verification remain hard constraints.

## Model roles

- **GPT-5.6 Sol** is the primary medium/hard solver, stalled-branch takeover,
  and final exploit solver at `max` effort. It is not held back as a reviewer.
- **GPT-5.6 Terra** runs complete independent alternative solves and tool-heavy
  branches. It is not merely an implementation subcontractor.
- **GPT-5.6 Luna** runs a complete fast independent solve on easy challenges.
  It is not used merely to summarize another solver.

This ordering follows OpenAI's published CTF results: Sol 96.7%, Terra 91.8%,
and Luna 85.2%, as well as the corresponding Terminal-Bench 2.1 results of
88.8%, 87.4%, and 84.7%. OpenAI identifies Sol as the flagship, Terra as the
balanced tier, Luna as the fastest tier, and documents `max` as a GPT-5.6
reasoning level. No public category-by-category comparison exists, so this
repository does not invent a claim that one tier is intrinsically a crypto,
pwn, or web specialist.

Sources:

- [OpenAI GPT-5.6 release and benchmark tables](https://openai.com/index/gpt-5-6/)
- [GPT-5.6 Sol API model documentation](https://developers.openai.com/api/docs/models/gpt-5.6-sol)
- [GPT-5.6 Terra API model documentation](https://developers.openai.com/api/docs/models/gpt-5.6-terra)
- [GPT-5.6 Luna API model documentation](https://developers.openai.com/api/docs/models/gpt-5.6-luna)

## Solver algorithm

`RacePlan` now maps each attempt to an executable category search direction.
Pwn uses mitigation/primitive/debugger/exploit loops; rev races static,
dynamic, emulation, and symbolic paths; crypto classifies parameters before
implementing competing attacks; web preserves sessions and branches by
endpoint and vulnerability class; forensics recursively extracts typed
artifacts; cloud traces effective identity/resource access; misc first runs a
bounded domain-classification portfolio.

Parallel attempts must differ in primitive, vulnerability family,
representation, or tool path. Every worker operates in a closed command-output
loop and pivots when a branch produces no new state, primitive, decoded bytes,
or constraint. Executable scripts, debuggers, supplied samples, round trips,
and challenge feedback outrank model confidence.

The design is grounded in:

- [EnIGMA](https://arxiv.org/abs/2409.16165), whose interactive tools,
  summarizer, and demonstrations each improved NYU CTF pass@1 in ablations.
- [EnIGMA implementation](https://github.com/SWE-agent/SWE-agent/tree/v0.7),
  including debugger and remote-interaction interfaces.
- [NYU CTF Bench (NeurIPS 2024)](https://nyu-llm-ctf.github.io/), the
  six-category, 200-challenge benchmark used for category solve rates.
- [InterCode](https://arxiv.org/abs/2306.14898), which evaluates multi-step
  action/feedback interaction in containerized environments.
- [Cybench](https://openreview.net/forum?id=tc90LV0yRL), which evaluates
  unguided solves on professional CTF challenges.
- [D-CIPHER reference agents](https://github.com/NYU-LLM-CTF/nyuctf_agents),
  supporting planner plus heterogeneous executor portfolios.
- [Scaling LLM test-time compute](https://arxiv.org/abs/2408.03314), supporting
  difficulty-adaptive search rather than equal compute for every branch.
- [AlphaCode](https://arxiv.org/abs/2203.07814), supporting diverse sampling,
  execution filtering, clustering, and reranking instead of duplicate samples.

## Performance gate

Architecture changes should be compared on a held-out, category-stratified CTF
set using valid-flag pass@1, fixed-budget pass@k, and time to first valid flag.
Subtask completion and report quality are diagnostics only. Category routing
must ultimately be calibrated from local blind solve rates rather than asserted
from model names.
