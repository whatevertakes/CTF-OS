# Misc playbook

## Scope and recon

Inventory every supplied file and the exact challenge text before choosing a category. Use local-only inspection first, record file types, encodings, protocols, puzzle rules, and prior failed approaches. Keep experiments in `/work` and durable evidence in `/artifacts`.

## Hypotheses and tooling

Favor the simplest evidence-backed explanation: encoding layers, archive nesting, scripting mistakes, data formats, esoteric languages, constrained search, or a cross-category handoff. Use short scripts with fixed inputs and explicit bounds. Split independent hypotheses so failures are informative rather than repetitive.

## Validation and replay

Check a solution against all stated constraints and independently rerun it from saved inputs. Save the minimal solver, command, outputs, and assumptions. If an approach repeats the same failure, write a SHIFT note and move to a different class of hypothesis.
