# AI exploit-first playbook

## 1. Fast recon budget

Keep untrusted models inside the sandbox. Budget three observations: (1) identify artifact format plus shapes/tokenizer/preprocessing; (2) inspect only the likely output/validation boundary; (3) run one input/output differential or small inversion test. Then implement the leading attack.

## 2. Highest-value exploit hypotheses

Prefer concrete model/input weaknesses: preprocessing mismatch, exposed logits/embedding relation, adversarial boundary, inversion/reconstruction, tokenizer/config confusion, unsafe agent/tool trust, or narrowly evidenced model-file behavior. Never use `trust_remote_code=True`.

## 3. Cheapest decisive experiments

Change one feature/token/pixel, compare one logit/embedding, reconstruct a small known target, test one prompt/tool boundary, or inspect one graph/operator slice. The experiment must prove/kill the expected weakness.

## 4. Immediate PoC criteria

A short deterministic inference, adversarial, inversion, or agent-input script that produces the target behavior on a representative case is a working PoC. Scale it before documenting model architecture.

## 5. Remote transition criteria

Run against the declared inference/agent target once local behavior is plausible. Use scheduler/GPU planning only for genuinely long generation, search, inversion, or bounded fine-tuning—not for quick inference probes.

## 6. Kill conditions

Kill when preprocessing/output behavior disproves the weakness, the small test cannot improve the target metric, or a bounded long slice has no solver-linked progress. Switch the attack mechanism rather than adding architecture analysis.

## 7. Common research-drift traps

Do not document every layer/operator, benchmark the whole model, build a reusable adversarial framework, run broad hyperparameter searches without proximity signals, or download external models without explicit approval. Metadata alone is not progress.

## 8. Flag fast path

Publish solver-linked progress and `WORKING_POC` before reports. Preserve model/input hashes, minimal script, preprocessing, and exact target observation, then surface a matching flag before optional CPU replay.
