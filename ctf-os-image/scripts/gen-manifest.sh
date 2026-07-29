#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: gen-manifest.sh [--help]

Inspect the current image and write a deterministic schema_version=1 tool
manifest to stdout.  No network access or stdin is used.
EOF
}

if (($#)); then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
fi

export LC_ALL=C
catalog_file=$(mktemp "${TMPDIR:-/tmp}/ctf-tool-catalog.XXXXXX")
resolved_file=$(mktemp "${TMPDIR:-/tmp}/ctf-tool-resolved.XXXXXX")
cleanup() {
  rm -f -- "${catalog_file}" "${resolved_file}"
}
trap cleanup EXIT

# category|name|probe|description|aliases|tags
cat >"${catalog_file}" <<'CATALOG'
crypto|RsaCtfTool|RsaCtfTool|Automated attacks and recovery for weak RSA keys|rsactftool|rsa,public-key
crypto|age|age|Modern file encryption utility||encryption
crypto|bitlocker2john|bitlocker2john|Extract BitLocker hashes for John the Ripper||password,converter
crypto|cado-nfs|cado-nfs|Number field sieve factorization suite|cado|factorization
crypto|ciphey|ciphey|Automatic classical cipher and encoding detector|ares|decoder,cipher
crypto|crypto-python|crypto-python|Python runtime with fpylll and gf2bv|fpylll,gf2bv|lattice,bitvector
crypto|ecm|ecm|Elliptic-curve integer factorization||factorization
crypto|flatter|flatter|Fast lattice reduction for large matrices||lattice
crypto|gp|gp|PARI/GP computer algebra shell|pari-gp|math
crypto|gpg|gpg|OpenPGP encryption and signature utility|gnupg|encryption
crypto|hash_extender|hash_extender|Merkle-Damgard hash length-extension utility|hash-extender|hash
crypto|hashcat|hashcat|OpenCL password and hash recovery||password,hash
crypto|hashid|hashid|Hash type identifier||hash
crypto|hccap2john|hccap2john|Convert wireless captures for John the Ripper||password,converter,wifi
crypto|john|john|John the Ripper jumbo password recovery||password,hash
crypto|keepass2john|keepass2john|Extract KeePass hashes for John the Ripper||password,converter
crypto|office2john.py|office2john.py|Extract Microsoft Office hashes for John the Ripper|office2john|password,converter,office
crypto|openssl|openssl|TLS and general cryptographic command line utility||crypto,tls
crypto|pdf2john.py|pdf2john.py|Extract PDF hashes for John the Ripper|pdf2john|password,converter,pdf
crypto|rar2john|rar2john|Extract RAR hashes for John the Ripper||password,converter,archive
crypto|sage|sage|SageMath computer algebra environment|sagemath|math,lattice
crypto|sage-python|sage-python|Sage Python runtime with cuso and PyCryptodome|cuso|coppersmith,lattice
crypto|ssh2john.py|ssh2john.py|Extract SSH private-key hashes for John the Ripper|ssh2john|password,converter,ssh
crypto|xortool|xortool|Repeating-key XOR analysis utility||xor
crypto|zip2john|zip2john|Extract ZIP hashes for John the Ripper||password,converter,archive
forensic|bulk_extractor|bulk_extractor|Bulk feature extraction from disk images||disk
forensic|binwalk|binwalk|Firmware analysis and embedded file extraction||firmware,carving
forensic|blkcat|blkcat|Display filesystem data-unit contents||disk,sleuthkit
forensic|blkls|blkls|List or extract filesystem data units||disk,sleuthkit
forensic|clamscan|clamscan|ClamAV file scanner||malware
forensic|dcfldd|dcfldd|Forensic disk imaging with hashing support||disk,imaging
forensic|dwarf2json|dwarf2json|Generate Volatility symbol data from DWARF||memory,symbols
forensic|evtxexport|evtxexport|Export Windows EVTX records as XML||windows,event-log
forensic|evtxinfo|evtxinfo|Inspect Windows EVTX file metadata||windows,event-log
forensic|exiftool|exiftool|Metadata extraction and editing||metadata
forensic|ffind|ffind|Find filesystem names that reference an inode||disk,sleuthkit
forensic|fls|fls|List deleted and allocated filesystem names||disk,sleuthkit
forensic|foremost|foremost|Signature-based file carving||carving
forensic|fsstat|fsstat|Display filesystem metadata||disk,sleuthkit
forensic|hwp5odt|hwp5odt|Convert HWP version 5 documents to OpenDocument||hwp,korean
forensic|hwp5proc|hwp5proc|Inspect HWP version 5 document structure||hwp,korean
forensic|hwp5txt|hwp5txt|Extract text from HWP version 5 documents||hwp,korean
forensic|icat|icat|Extract a file from a disk image by inode||disk,sleuthkit
forensic|img_stat|img_stat|Display disk-image format details||disk,sleuthkit
forensic|istat|istat|Display filesystem inode metadata||disk,sleuthkit
forensic|mmls|mmls|Display disk partition layouts||disk,sleuthkit
forensic|msoffcrypto-tool|msoffcrypto-tool|Decrypt password-protected Microsoft Office documents|msoffcrypto|office
forensic|ngrep|ngrep|Search packet payloads with regular expressions||network,pcap
forensic|oleid|oleid|Identify characteristics of OLE files||office
forensic|oleobj|oleobj|Extract embedded objects from OLE files||office,embedded
forensic|olevba|olevba|Extract and analyze VBA macros||office,macro
forensic|pdfdetach|pdfdetach|List and extract embedded PDF attachments||pdf,extract
forensic|pdfid|pdfid|Scan PDF names and suspicious features||pdf
forensic|pdfimages|pdfimages|Extract raster images from PDF files||pdf,extract
forensic|pdftotext|pdftotext|Extract text and layout from PDF files||pdf,extract
forensic|peepdf|peepdf|Analyze and inspect PDF files||pdf
forensic|photorec|photorec|Recover files by signatures||recovery
forensic|qemu-img|qemu-img|Inspect and convert QCOW2 VHDX and other disk images||disk,virtualization
forensic|qpdf|qpdf|Inspect repair decrypt and transform PDF files||pdf
forensic|regfexport|regfexport|Export Windows Registry hive records||windows,registry
forensic|regfinfo|regfinfo|Inspect Windows Registry hive metadata||windows,registry
forensic|rtfobj|rtfobj|Extract embedded objects from RTF files||office,rtf
forensic|scalpel|scalpel|High-performance file carving||carving
forensic|ssdeep|ssdeep|Context-triggered piecewise hashing||hash
forensic|tesseract|tesseract|OCR engine with Korean language assets||ocr,korean
forensic|testdisk|testdisk|Partition and filesystem recovery||recovery
forensic|tcpdump|tcpdump|Noninteractive packet capture and inspection||network,pcap
forensic|tshark|tshark|Noninteractive packet capture analysis||network,pcap
forensic|unsquashfs|unsquashfs|Extract SquashFS firmware filesystems||firmware,filesystem
forensic|vol|vol|Volatility 3 memory forensics CLI|volatility3|memory
forensic|zeek|zeek|Network security monitoring and protocol analysis||network,pcap
korean|ktext|ktext|Extract UTF-8 and UTF-16 strings containing Hangul||korean,text
misc|ciphey|ciphey|Automatic decoding and classical-cipher solver|ares|decoder
misc|bkcrack|bkcrack|Known-plaintext attack against legacy ZipCrypto||archive,zip,crypto
misc|ffmpeg|ffmpeg|Audio and video conversion and inspection||media
misc|identify|identify|ImageMagick image identification||image
misc|jpeginfo|jpeginfo|Validate and inspect JPEG images||image
misc|minimodem|minimodem|Encode and decode FSK audio modem signals||audio,fsk
misc|ml-python|ml-python|Python interpreter with PyTorch and Transformers||ml
misc|multimon-ng|multimon-ng|Decode AFSK and other radio audio protocols||audio,afsk
misc|outguess|outguess|Steganography extraction and embedding||stego
misc|pngcheck|pngcheck|Validate and inspect PNG files||image
misc|qrencode|qrencode|Generate QR codes||qr
misc|sox|sox|Audio processing and inspection||audio
misc|steghide|steghide|Steganography for common media formats||stego
misc|stegseek|stegseek|Fast steghide passphrase recovery||stego,password
misc|stegoveritas|stegoveritas|Automated image steganography analysis||stego,image
misc|zbarimg|zbarimg|Decode barcodes and QR codes from images||qr,barcode
misc|zsteg|zsteg|Detect hidden data in PNG and BMP files||stego,image
orchestration|ctf-bg|ctf-bg|Start a managed background job||job
orchestration|ctf-flag|ctf-flag|Search work files and logs for flag candidates||flag
orchestration|ctf-idle|ctf-idle|Signal-aware idle PID 1 and orphan process reaper||pid1,reaper
orchestration|ctf-jobs|ctf-jobs|List managed background jobs||job
orchestration|ctf-kill|ctf-kill|Terminate a managed background job||job
orchestration|ctf-log|ctf-log|Read bounded managed-job logs||job,log
orchestration|ctf-tools|ctf-tools|Query the installed tool manifest||manifest
orchestration|ctfwrap|ctfwrap|Run a bounded foreground command with artifacts||runner
orchestration|ghidra-decompile|ghidra-decompile|Run headless Ghidra and export C decompilation||rev,decompiler
pwn|ROPgadget|ROPgadget|Search binaries for ROP gadgets|ropgadget|rop
pwn|angr-python|angr-python|Python interpreter with angr installed||symbolic
pwn|checksec|checksec|Inspect executable hardening properties||elf
pwn|extract-vmlinux|extract-vmlinux|Extract vmlinux from compressed kernel images||kernel
pwn|gdb|gdb|GNU debugger configured with pwndbg||debugger
pwn|gdb-multiarch|gdb-multiarch|GNU debugger with multiple architectures||debugger
pwn|gdbserver|gdbserver|Remote GNU debugger server||debugger,remote
pwn|libc-find|libc-find|Search the offline libc database||libc
pwn|libc-identify|libc-identify|Identify libc from leaked symbols||libc
pwn|ltrace|ltrace|Trace dynamic library calls without an interactive UI||trace
pwn|objdump|objdump|Display and disassemble object files||elf,disassembler
pwn|one_gadget|one_gadget|Find one-shot execve gadgets in libc||rop,libc
pwn|pahole|pahole|Inspect DWARF types and kernel structure layouts||kernel,dwarf
pwn|patchelf|patchelf|Modify ELF interpreter and dynamic dependencies||elf
pwn|pwn|pwn|Pwntools command-line utilities||pwntools
pwn|pwninit|pwninit|Prepare pwn challenges with matching libc and loader||elf,libc
pwn|qemu-system-aarch64|qemu-system-aarch64|Emulate complete AArch64 systems||kernel,emulator
pwn|qemu-system-arm|qemu-system-arm|Emulate complete 32-bit ARM systems||kernel,emulator
pwn|qemu-system-mips|qemu-system-mips|Emulate complete MIPS systems||kernel,emulator
pwn|qemu-system-x86_64|qemu-system-x86_64|Emulate complete x86-64 systems||kernel,emulator
pwn|readelf|readelf|Display ELF metadata||elf
pwn|ropr|ropr|Fast ROP gadget search for large binaries||rop
pwn|ropper|ropper|Search and filter ROP gadgets||rop
pwn|seccomp-tools|seccomp-tools|Inspect and assemble seccomp BPF filters||seccomp
pwn|socat|socat|Bidirectional socket and process relay||network
pwn|strace|strace|Trace system calls without an interactive UI||trace
pwn|valgrind|valgrind|Dynamic memory and execution analysis||debugger,memory
pwn|vmlinux-to-elf|vmlinux-to-elf|Recover ELF files from raw vmlinux images||kernel
rev|GoReSym|GoReSym|Recover symbols from stripped Go binaries|goresym|go,symbols
rev|apktool|apktool|Decode and rebuild Android APK resources||android
rev|capa|capa|Identify executable capabilities from code patterns||malware
rev|cfr|cfr|Decompile Java class and JAR files||java,decompiler
rev|floss|floss|Extract obfuscated strings from binaries||strings,malware
rev|frida|frida|Dynamic instrumentation CLI||dynamic
rev|frida-trace|frida-trace|Trace dynamically instrumented functions||dynamic,trace
rev|ghidra-decompile|ghidra-decompile|Headless Ghidra decompiler wrapper|ghidra|decompiler
rev|ilspycmd|ilspycmd|Command-line .NET decompiler||dotnet,decompiler
rev|jadx|jadx|Command-line Android DEX and APK decompiler||android,decompiler
rev|mono|mono|Execute managed .NET Framework assemblies||dotnet,runtime
rev|objection|objection|Runtime mobile exploration toolkit||dynamic
rev|pydisasm|pydisasm|Disassemble versioned Python bytecode|xdis|python,disassembler
rev|pycdas|pycdas|Disassemble Python bytecode||python
rev|pycdc|pycdc|Decompile Python bytecode||python,decompiler
rev|pyinstxtractor.py|pyinstxtractor.py|Extract bundled PyInstaller applications|pyinstxtractor|python
rev|r2|r2|Radare2 reverse-engineering CLI|radare2|disassembler
rev|rabin2|rabin2|Inspect binary metadata with Radare2||binary
rev|radiff2|radiff2|Compare binary files with Radare2||binary,diff
rev|rustfilt|rustfilt|Demangle Rust symbols||rust,symbols
rev|strings|strings|Extract printable strings from binary files||strings
rev|uncompyle6|uncompyle6|Decompile supported legacy Python bytecode||python,decompiler
rev|upx|upx|Pack and unpack executable files||packer
rev|wasm-opt|wasm-opt|Optimize and transform WebAssembly modules|binaryen|wasm
rev|wasm2wat|wasm2wat|Convert WebAssembly binary modules to text|wabt|wasm
rev|wine|wine|Execute 32-bit and 64-bit Windows PE programs||windows,runtime
rev|wine64|wine64|Execute 64-bit Windows PE programs||windows,runtime
rev|yara|yara|Match files using YARA rules||malware,signature
system|7z|7z|Read and write common archive formats|7za|archive
system|curl|curl|Transfer data over network protocols||http
system|fd|fd|Fast filesystem path search||search
system|file|file|Identify file formats||format
system|jq|jq|Process and transform JSON||json
system|nmap|nmap|Network discovery and port scanner||network
system|rg|rg|Fast recursive text search|ripgrep|search
system|tree|tree|Render directory trees||filesystem
system|xxd|xxd|Hex dump and binary patch utility||hex
system|yara|yara|Pattern matching for files and processes||signature
web|curl|curl|HTTP and general protocol client||http
web|ctf-browser|ctf-browser|Bounded headless Chromium navigation and artifact capture|browser|browser,automation
web|dalfox|dalfox|XSS parameter analysis and scanner||xss
web|feroxbuster|feroxbuster|Recursive HTTP content discovery||fuzzing
web|ffuf|ffuf|Fast web fuzzer||fuzzing
web|gobuster|gobuster|Directory DNS and virtual-host enumeration||fuzzing
web|http|http|HTTPie command-line HTTP client|httpie|http
web|jwt_tool|jwt_tool|Inspect and test JSON Web Tokens||jwt
web|masscan|masscan|High-speed TCP port scanner||network
web|mitmdump|mitmdump|Noninteractive mitmproxy entrypoint||proxy
web|nmap|nmap|Network discovery and service scanner||network
web|nuclei-run|nuclei-run|Offline-safe nuclei wrapper with bundled templates|nuclei|scanner
web|php|php|PHP CLI with curl XML mbstring and GD extensions||php,runtime
web|playwright|playwright|Install and inspect the bundled headless Chromium runtime||browser
web|phpggc|phpggc|PHP unserialize gadget-chain generator||deserialization
web|pw-python|pw-python|Python interpreter with Playwright and bundled Chromium||browser,automation
web|web-python|web-python|Python runtime with BeautifulSoup lxml HTTP/2 and WebSockets|bs4,h2,h2spacex,websockets|parser,http2,websocket
web|ysoserial|ysoserial|Java deserialization payload generator||deserialization
CATALOG

while IFS='|' read -r category name probe description aliases tags; do
  [[ -n "${category}" && -n "${name}" && -n "${probe}" ]] || continue
  path=$(command -v -- "${probe}" 2>/dev/null || true)
  available=false
  if [[ -n "${path}" && -x "${path}" ]]; then
    available=true
  else
    path=''
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${category}" "${name}" "${path}" "${available}" \
    "${description}" "${aliases}" "${tags}" >>"${resolved_file}"
done <"${catalog_file}"

failed_path=${CTF_FAILED_TOOLS_FILE:-/tools/failed.txt}
python3 - "${resolved_file}" "${failed_path}" <<'PY'
import json
import os
import pathlib
import stat
import sys

resolved_path = pathlib.Path(sys.argv[1])
failed_path = pathlib.Path(sys.argv[2])
max_failed_bytes = 1024 * 1024
tools = []
seen = set()
for line_number, raw_line in enumerate(
    resolved_path.read_text(encoding="utf-8").splitlines(), start=1
):
    fields = raw_line.split("\t")
    if len(fields) != 7:
        raise SystemExit(f"invalid resolved catalog line {line_number}")
    category, name, path, available, description, aliases, tags = fields
    key = (category.casefold(), name.casefold())
    if key in seen:
        raise SystemExit(
            f"duplicate catalog category/name at line {line_number}: "
            f"{category}/{name}"
        )
    seen.add(key)
    is_available = available == "true"
    if is_available and (not path or not pathlib.Path(path).is_absolute()):
        raise SystemExit(
            f"available catalog entry has invalid path at line {line_number}: "
            f"{category}/{name}"
        )
    if not is_available and path:
        raise SystemExit(
            f"unavailable catalog entry unexpectedly has a path at line {line_number}: "
            f"{category}/{name}"
        )
    tools.append(
        {
            "category": category,
            "name": name,
            "path": path,
            "available": is_available,
            "description": description,
            "aliases": [item for item in aliases.split(",") if item],
            "tags": [item for item in tags.split(",") if item],
        }
    )

tools.sort(key=lambda item: (item["category"].casefold(), item["name"].casefold()))

def read_failed_lines(path):
    try:
        resolved = path.resolve(strict=True)
        before = resolved.stat(follow_symlinks=False)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise SystemExit(f"cannot inspect failed-tools file {path}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"failed-tools path must be a regular file: {path}")
    if before.st_size > max_failed_bytes:
        raise SystemExit(
            f"failed-tools file exceeds {max_failed_bytes} byte limit: {path}"
        )

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise SystemExit(
                    f"failed-tools path must be a regular file: {path}"
                )
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise SystemExit(f"failed-tools file changed while opening: {path}")
            if opened.st_size > max_failed_bytes:
                raise SystemExit(
                    f"failed-tools file exceeds {max_failed_bytes} byte limit: {path}"
                )
            chunks = []
            remaining = max_failed_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise SystemExit(f"cannot read failed-tools file {path}: {exc}") from exc
    data = b"".join(chunks)
    if len(data) > max_failed_bytes:
        raise SystemExit(
            f"failed-tools file exceeds {max_failed_bytes} byte limit: {path}"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise SystemExit(f"failed-tools file is not UTF-8: {path}") from exc
    return sorted({line.strip() for line in text.splitlines() if line.strip()})


failed = read_failed_lines(failed_path)

json.dump(
    {
        "schema_version": 1,
        "tools": tools,
        "failed": failed,
    },
    sys.stdout,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
)
sys.stdout.write("\n")
PY
