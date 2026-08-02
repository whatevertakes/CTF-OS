#!/usr/bin/env python3
"""Regression tests for the bounded networkless QEMU system recipe."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "templates" / "pwn" / "qemu-headless.sh"


def invoke(
    *arguments: object,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *(str(value) for value in arguments)],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )


with tempfile.TemporaryDirectory(prefix="ctf-qemu-headless-") as directory:
    root = pathlib.Path(directory)
    stub_bin = root / "bin"
    stub_bin.mkdir()
    stub = stub_bin / "qemu-system-x86_64"
    stub.write_text(
        "#!/bin/sh\nprintf '<%s>\\n' \"$@\"\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{stub_bin}:/usr/bin:/bin",
    }

    no_args = invoke(environment=environment)
    assert no_args.returncode == 2, no_args
    assert "usage:" in no_args.stderr.casefold(), no_args.stderr

    allowed = invoke(
        "--timeout",
        3,
        "qemu-system-x86_64",
        "-machine",
        "q35",
        "-kernel",
        "/challenge/bzImage",
        environment=environment,
    )
    assert allowed.returncode == 0, allowed
    assert allowed.stdout.splitlines() == [
        "<-display>",
        "<none>",
        "<-monitor>",
        "<none>",
        "<-serial>",
        "<stdio>",
        "<-no-reboot>",
        "<-net>",
        "<none>",
        "<-accel>",
        "<tcg>",
        "<-machine>",
        "<q35>",
        "<-kernel>",
        "</challenge/bzImage>",
    ], allowed.stdout

    for unsafe in (
        ("-netdev", "user,id=n0"),
        ("-nic=user",),
        ("-enable-kvm",),
        ("-machine", "q35,accel=kvm"),
        ("-machine", "q35,accel=xen"),
        ("-daemonize",),
        ("-mon", "stdio,mode=readline"),
        ("-qmp", "tcp:127.0.0.1:4444,server=on"),
        ("-qmp-pretty", "tcp:127.0.0.1:4444,server=on"),
        ("-serial", "tcp:127.0.0.1:4444,server=on"),
        ("-parallel", "tcp:127.0.0.1:4444,server=on"),
        ("-debugcon", "udp:127.0.0.1:4444"),
        ("-readconfig", "/challenge/qemu.cfg"),
        ("-plugin", "/challenge/host-code.so"),
        ("-audio", "pa,server=example.test"),
        ("-blockdev", "driver=nbd,server.type=inet,server.host=example.test"),
        ("-drive", "file.driver=nbd,file.server.type=inet"),
        (
            "-drive",
            'file=json:{"driver": "nbd", "server": {"type": "inet"}}',
        ),
        ("-drive", "file=https://example.test/disk.raw"),
        ("-drive", "file=HTTP://example.test/disk.raw"),
        ("nbd:example.test:10809",),
    ):
        denied = invoke(
            "qemu-system-x86_64",
            *unsafe,
            environment=environment,
        )
        assert denied.returncode == 2, (unsafe, denied)
        assert "unsafe or conflicting" in denied.stderr, (unsafe, denied.stderr)

    unsupported = invoke(
        "qemu-system-sparc",
        "-machine",
        "SS-5",
        environment=environment,
    )
    assert unsupported.returncode == 2, unsupported
    assert "unsupported QEMU" in unsupported.stderr, unsupported.stderr

print("pwn QEMU headless recipe regressions: ok")
