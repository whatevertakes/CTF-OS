# Claude Rescue Research and Knowledge Lane

External research is optional and policy-bound. A rescue packet records one of:

- `offline`: default when contest policy cannot be established; blocks WebSearch, WebFetch, and external research MCP tools
- `public-web`: permits WebSearch and WebFetch
- `public-web-and-mcp`: also permits already user-connected external research MCP servers

The operator selects the policy with `rescue-prepare --research-policy ...`. The project-local `ctf-rescue` MCP remains available in every policy. The runtime never discovers personal credentials or connects an external MCP server on the operator's behalf.

## Raw source evidence

`PreToolUse` enforces the policy. `PostToolUse` records bounded WebSearch, WebFetch, and external MCP source evidence in `KNOWLEDGE_SOURCES.jsonl`: query, tool, title, URL/resource ID, retrieval time, bounded excerpt, content digest, Claude session ID, and subagent ID. Long source bodies are not stored in the ledger or injected into main context.

## Typed attack hints

Search output is not attack truth. To use it, Claude calls `ctf_knowledge_hint_record` (or the CLI fallback) with:

```json
{
  "query": "...",
  "source_receipt_ids": ["..."],
  "atomic_attack_facts": ["..."],
  "applicability_conditions": ["..."],
  "current_challenge_matches": ["..."],
  "proposed_attack_path": "...",
  "decisive_experiment": {
    "argv_or_session_plan": {},
    "success_condition": "...",
    "kill_condition": "..."
  },
  "status": "CANDIDATE"
}
```

Every source ID must exist in the raw source ledger. A knowledge hint remains `CANDIDATE` until a command or session observation receipt supplies execution evidence. This lane is most useful for crypto constructions, version-specific pwn behavior, cloud IAM/provider semantics, AI tokenizer/serialization behavior, forensic formats, and new web frameworks.

## Typed subagent contract

Subagent tasks are stored in `RESCUE_TASKS.jsonl` with objective, role, success/kill condition, maximum turns, expected artifacts, allowed hypothesis family, and forbidden repeated paths. Results use `SUPPORTED`, `REFUTED`, `PARTIAL`, `INCONCLUSIVE`, or `ERROR` and must attach command/session receipts and artifact paths where they claim execution evidence.

A prose-only subagent summary is never adopted as attack truth. Generated agents are instructed to write through `ctf_task_result`, keep artifacts under `work/` or `artifacts/`, and avoid nesting. Claude Code `SubagentStart`, `SubagentStop`, `TaskCreated`, and `TaskCompleted` hooks add runtime linkage when the installed client provides those events.

