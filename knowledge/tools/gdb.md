# gdb quick sheet

Use a local challenge copy, never a host process. Start with `gdb -q ./chall`, `set pagination off`, `run`, `bt`, `info registers`, `x/16gx $rsp`, and `disassemble /m function`.

Set a breakpoint on an evidenced input handler, inspect the comparison path, and save a command file plus binary hash. Validate a crash offset with a repeatable local input before using it in an exploit hypothesis.
