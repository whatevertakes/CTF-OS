from __future__ import annotations

import json
import subprocess

from ctf_os.sandbox.resources import sandbox_gc


def test_sandbox_gc_removes_only_stopped_validated_sandboxes() -> None:
    calls: list[list[str]] = []
    records = {
        "current": {
            "Name": "/current-box",
            "Config": {"Labels": {
                "org.ctf-os.managed": "true",
                "org.ctf-os.kind": "sandbox",
            }},
            "State": {"Running": False, "Status": "exited"},
        },
        "legacy": {
            "Name": "/legacy-box",
            "Config": {"Labels": {"ctf-os": "true", "ctf-os.kind": "sandbox"}},
            "State": {"Running": False, "Status": "exited"},
        },
        "running": {
            "Name": "/running-box",
            "Config": {"Labels": {
                "org.ctf-os.managed": "true",
                "org.ctf-os.kind": "sandbox",
            }},
            "State": {"Running": True, "Status": "running"},
        },
        "service": {
            "Name": "/service-box",
            "Config": {"Labels": {
                "org.ctf-os.managed": "true",
                "org.ctf-os.kind": "service",
            }},
            "State": {"Running": False, "Status": "exited"},
        },
    }

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["ps", "--all"]:
            label = argv[argv.index("--filter") + 1]
            output = "current\nrunning\nservice\n" if "org.ctf-os" in label else "legacy\n"
            return subprocess.CompletedProcess(argv, 0, output, "")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, json.dumps([records[argv[2]]]), "")
        if argv[1] == "rm":
            return subprocess.CompletedProcess(argv, 0, argv[2], "")
        raise AssertionError(argv)

    result = sandbox_gc(runner=runner)

    assert result["removed"] == ["current-box", "legacy-box"]
    assert {row["container"] for row in result["skipped"]} == {"running-box", "service-box"}
    assert [call for call in calls if call[1] == "rm"] == [
        ["docker", "rm", "current"],
        ["docker", "rm", "legacy"],
    ]
