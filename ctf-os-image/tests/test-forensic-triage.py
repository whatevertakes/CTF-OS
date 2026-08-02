#!/usr/bin/env python3
"""Dispatch and output-safety regressions for forensic/triage.sh."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TRIAGE = REPO_ROOT / "templates" / "forensic" / "triage.sh"

triage_source = TRIAGE.read_text(encoding="utf-8")
assert '/opt/ctf-templates/forensic/browser_timeline.py "$target" \\' in triage_source
assert '--output-dir "$output_dir"' in triage_source


def invoke(
    arguments: list[object],
    *,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(TRIAGE), *(str(value) for value in arguments)],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )


with tempfile.TemporaryDirectory(prefix="ctf-forensic-triage-") as directory:
    root = pathlib.Path(directory)
    stub_bin = root / "bin"
    stub_bin.mkdir()
    stub = "#!/bin/sh\nprintf '%s' \"${0##*/}\"\nprintf ' <%s>' \"$@\"\nprintf '\\n'\n"
    tools = {
        "7z",
        "binwalk",
        "ctf-sqlite-readonly",
        "evtxexport",
        "evtxinfo",
        "ewfinfo",
        "ewfverify",
        "exiftool",
        "ktext",
        "oleid",
        "olevba",
        "pdfdetach",
        "pdfid",
        "qemu-img",
        "qpdf",
        "regfexport",
        "regfinfo",
        "sccainfo",
        "tshark",
    }
    for tool in tools:
        path = stub_bin / tool
        path.write_text(stub, encoding="utf-8")
        path.chmod(0o755)
    environment = {
        **os.environ,
        "LC_ALL": "C.UTF-8",
        "PATH": f"{stub_bin}:/usr/bin:/bin",
    }

    no_args = invoke([], environment=environment)
    assert no_args.returncode == 2, no_args
    assert "usage:" in no_args.stderr.casefold(), no_args.stderr

    cases = {
        "Security.EVTX": ("evtx-info.txt", "evtx-records.xml"),
        "NTUSER.DAT": ("registry-info.txt", "registry-export.txt"),
        "disk.E01": ("ewf-info.txt", "ewf-verify.txt"),
        "CMD.EXE-12345678.PF": ("prefetch-info.txt",),
        "invoice.docm": ("office-indicators.txt", "office-vba.txt"),
        "document.pdf": (
            "pdf-indicators.txt",
            "pdf-check.txt",
            "pdf-attachments.txt",
        ),
        "History.sqlite": ("sqlite-schema.json",),
        "traffic.pcapng": ("pcap-protocols.txt",),
        "machine.vmdk": ("virtual-disk-info.json",),
        "bundle.zip": ("archive-list.txt",),
    }
    for ordinal, (name, expected_artifacts) in enumerate(cases.items()):
        evidence = root / name
        evidence.write_bytes(f"fixture-{ordinal}".encode("ascii"))
        output = root / "outputs" / str(ordinal)
        output.parent.mkdir(exist_ok=True)
        result = invoke(
            ["--output-dir", output, evidence],
            environment=environment,
        )
        assert result.returncode == 0, (name, result)
        assert result.stdout == f"forensic triage saved: {output}/summary.txt\n"
        assert (output / "summary.txt").is_file(), name
        assert (output / "metadata.json").is_file(), name
        assert (output / "binwalk.txt").is_file(), name
        for artifact in expected_artifacts:
            path = output / artifact
            assert path.is_file(), (name, artifact)
            assert path.stat().st_size > 0, (name, artifact)

    evidence = root / "ordinary.bin"
    evidence.write_bytes(b"ordinary")
    linked_input = root / "linked.bin"
    linked_input.symlink_to(evidence)
    rejected_input = invoke(
        ["--output-dir", root / "linked-output", linked_input],
        environment=environment,
    )
    assert rejected_input.returncode == 2, rejected_input
    assert "non-symlink" in rejected_input.stderr, rejected_input.stderr

    attacked = root / "attacked"
    attacked.mkdir()
    outside = root / "outside"
    outside.write_text("preserve", encoding="utf-8")
    (attacked / "summary.txt").symlink_to(outside)
    rejected_output = invoke(
        ["--output-dir", attacked, evidence],
        environment=environment,
    )
    assert rejected_output.returncode == 1, rejected_output
    assert outside.read_text(encoding="utf-8") == "preserve"

print("forensic triage dispatch and output-safety regressions: ok")
