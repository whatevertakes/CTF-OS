# radare2 quick sheet

For a supplied binary: `r2 -A /work/chall`, then use `afl` for functions, `pdf @ sym.main` for a function, `iz` for strings, `axt @ address` for xrefs, and `px` for bytes.

Record binary hash, function addresses, and the original architecture. Confirm decompiler assumptions dynamically or with disassembly before deriving an input.
