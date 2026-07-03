#!/usr/bin/env python3
import base64, struct, sys, os, tempfile, subprocess

def parse_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]

def parse_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def parse_u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]

def check(data):
    # ELF64 x86_64
    if len(data) < 64:
        return "Too small"
    if data[:4] != b'\x7fELF':
        return "Not ELF"
    if data[4] != 2:
        return "Not 64-bit"
    if parse_u16(data, 18) != 0x3e:
        return "Not x86_64"

    # Section headers: check SHF_EXECINSTR (0x4)
    e_shoff = parse_u64(data, 40)
    e_shentsize = parse_u16(data, 58)
    e_shnum = parse_u16(data, 60)

    if e_shoff != 0:
        if e_shentsize < 64 or e_shoff + e_shentsize > len(data):
            return "Bad section headers"
        shnum = e_shnum
        if shnum == 0 or shnum >= 0xff00:
            shnum = parse_u64(data, e_shoff + 32)  # sh_size of section 0
        if shnum > 65536:
            return "Too many sections"
        if e_shoff + shnum * e_shentsize > len(data):
            return "Section headers out of bounds"
        for i in range(shnum):
            sh_flags = parse_u64(data, e_shoff + i * e_shentsize + 8)
            if sh_flags & 0x4:
                return "Executable section found"

    # Program headers: check PF_X (0x1)
    e_phoff = parse_u64(data, 32)
    e_phentsize = parse_u16(data, 54)
    e_phnum = parse_u16(data, 56)

    if e_phoff != 0 and e_phnum > 0:
        if e_phentsize < 56 or e_phoff + e_phnum * e_phentsize > len(data):
            return "Bad program headers"
        for i in range(e_phnum):
            p_flags = parse_u32(data, e_phoff + i * e_phentsize + 4)
            if p_flags & 0x1:
                return "Executable segment found"

    return None

def main():
    print("Send me a base64-encoded x86_64 ELF binary.")
    print("If it has no executable sections or segments, I'll run it!")
    sys.stdout.flush()

    try:
        data = base64.b64decode(input().strip())
    except Exception:
        print("Bad base64")
        return

    if len(data) > 1024 * 1024:
        print("Too large")
        return

    err = check(data)
    if err:
        print(f"Rejected: {err}")
        return

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        fname = f.name

    os.chmod(fname, 0o755)
    try:
        r = subprocess.run([fname], capture_output=True, timeout=5)
        sys.stdout.buffer.write(r.stdout)
        sys.stdout.buffer.write(r.stderr)
        sys.stdout.flush()
    except subprocess.TimeoutExpired:
        print("Timeout")
    finally:
        os.unlink(fname)

if __name__ == '__main__':
    main()
