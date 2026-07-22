# Pwn attack playbook

## 1. Fast recon budget

Use only challenge binaries and declared remotes. Budget four observations: (1) `file` plus `checksec`; (2) imports/symbols/targeted strings; (3) one normal execution; (4) one targeted malformed-input or crash experiment. Stop earlier on control, leak, oracle, or crash. Then state the leading path, decisive experiment, kill condition, and PoC class.

## 2. Highest-value exploit hypotheses

Prefer directly evidenced ret2win, format disclosure/write, stack control, logic bypass, then leak-to-ROP. Consider heap only when the allocation/free path or corruption evidence demands it. Each hypothesis names the expected control primitive, not a vulnerability survey.

## 3. Cheapest decisive experiments

Use a cyclic pattern for offset/control, one format probe for disclosure/write, one debugger watchpoint for overwrite reachability, or one targeted input differential. Inspect only gadgets/symbols needed by the live chain.

## 4. Immediate PoC criteria

A minimal script/input that controls PC/RIP, leaks the required address, performs the required read/write, or deterministically reaches a privileged function is a working PoC. Convert it to pwntools or the smallest direct client immediately.

## 5. Remote transition criteria

Move to the declared remote when control/leak is plausible and the exploit can expose environment differences. Check remote libc/PIE/protocol behavior through the exploit path instead of delaying for perfect local repeatability.

## 6. Kill conditions

Kill a family when the decisive input cannot reach/control the target state, the assumed mitigation/environment is false, or one changed experiment still yields no proximity gain. Replace heap/ROP/format/race with a genuinely different evidenced mechanism.

## 7. Common research-drift traps

Do not collect every gadget, study the full heap without heap evidence, continue crash research after working RIP/PC control, decompile unrelated functions, catalog every mitigation implication, or polish a reusable exploitation framework.

## 8. Flag fast path

Publish `PRIMITIVE` after the first useful executed observation and strike immediately. Publish `WORKING_POC`, run it on the declared remote, preserve the exact output and exploit artifact, and surface a matching flag without waiting for clean replay.
