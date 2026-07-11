# angr quick sheet

Use symbolic execution only after identifying an input and success condition in a local challenge binary. Constrain stdin length and character set, avoid unconstrained exploration, and save the script with the original binary hash.

Validate any model by replaying it in the unmodified program. Treat a solver timeout as a reason to simplify the hypothesis, not to increase scope.
