# pwntools quick sheet

Use `pwntools` only for supplied binaries and authorized CTF remotes. Set `context.binary`, keep host/port values from `contest.md`, and save deterministic scripts under `/artifacts`.

```python
from pwn import ELF, process
elf = ELF("/work/chall", checksec=False)
io = process(elf.path)
io.sendlineafter(b"> ", b"test")
print(io.recvline(timeout=1))
```

Validate offsets and leaks locally before one scoped remote replay. Record architecture, libc assumptions, and exact bytes sent.
