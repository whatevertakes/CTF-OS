# Reverse engineering attack playbook

## 1. Fast recon budget

Budget four observations: (1) `file`; (2) targeted strings/imports; (3) locate the likely input-validation path with one disassembly/decompiler query; (4) one dynamic differential between two inputs. Then start accepted-input construction, a solver, or a patch.

## 2. Highest-value exploit hypotheses

Prefer direct comparison recovery, encoded/hashed constant recovery, branch patch/oracle, compact symbolic constraints, or custom-VM logic only along the validation slice. Analyze only supplied binaries/bytecode/packages in the sandbox.

## 3. Cheapest decisive experiments

Breakpoint at the comparison, trace one candidate byte, patch one conditional branch, execute a tiny constraint subset, or compare two input traces. The experiment must confirm how accepted input is constructed or kill that route.

## 4. Immediate PoC criteria

A script producing an accepted input, a minimal patch demonstrating the validation condition, or a deterministic oracle extracting required bytes is a working PoC. Write the solver before cleaning decompiler output.

## 5. Remote transition criteria

Run a candidate against the provided validator or declared remote as soon as the validation slice is plausible. Do not reconstruct unrelated program meaning first.

## 6. Kill conditions

Kill when the located path is not flag validation, the differential contradicts the model, or a bounded symbolic/manual attempt does not reduce constraints. Switch between manual recovery, patch/oracle, and symbolic methods based on evidence.

## 7. Common research-drift traps

Do not recover full program semantics, rename every function, prettify decompiler output, lift an entire VM when one opcode slice suffices, or continue manual recovery when a direct solver/patch is already working. Do not start symbolic execution without an immediate advantage.

## 8. Flag fast path

Publish the validation primitive/solver first, verify only the target behavior needed for confidence, run it against the declared target when present, and surface a pattern-matching candidate without requiring complete explanation.
