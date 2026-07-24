"""H2 (compose dangerous fields) and RH2 (Dockerfile parser) preflight regressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_os.preflight import detect_service
from ctf_os.service import _scan_resolved_config


def _plan_for_compose(tmp_path: Path, body: str) -> dict:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(body, encoding="utf-8")
    (input_root / "Dockerfile").write_text(
        "FROM ctf-os-sandbox:base\nEXPOSE 8000\n",
        encoding="utf-8",
    )
    return detect_service(input_root, "web")


def test_build_privileged_is_blocked(tmp_path: Path) -> None:
    plan = _plan_for_compose(
        tmp_path,
        "services:\n  chall:\n    build:\n      context: .\n      privileged: true\n    expose: [8000]\n",
    )
    assert plan["safe"] is False
    assert any("privileged" in reason for reason in plan["review_reasons"])


def test_build_extra_hosts_is_blocked(tmp_path: Path) -> None:
    plan = _plan_for_compose(
        tmp_path,
        "services:\n  chall:\n    build:\n      context: .\n"
        "      extra_hosts: ['host.docker.internal:host-gateway']\n    expose: [8000]\n",
    )
    assert plan["safe"] is False
    assert any("extra_hosts" in reason for reason in plan["review_reasons"])


def test_build_registry_cache_source_is_blocked(tmp_path: Path) -> None:
    plan = _plan_for_compose(
        tmp_path,
        "services:\n"
        "  chall:\n"
        "    build:\n"
        "      context: .\n"
        "      cache_from: [type=registry,ref=registry.invalid/cache]\n"
        "    expose: [8000]\n",
    )
    assert plan["safe"] is False
    assert any("cache_from" in reason for reason in plan["review_reasons"])


def test_lifecycle_hook_privileged_is_blocked(tmp_path: Path) -> None:
    plan = _plan_for_compose(
        tmp_path,
        "services:\n  chall:\n    image: demo\n    expose: [8000]\n"
        "    post_start:\n      - command: whoami\n        privileged: true\n",
    )
    assert plan["safe"] is False
    assert any("post_start" in reason for reason in plan["review_reasons"])


def _plan_for_dockerfile(tmp_path: Path, body: str, category: str = "web") -> dict:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "Dockerfile").write_text(body, encoding="utf-8")
    return detect_service(input_root, category)


def test_dockerfile_remote_add_is_blocked(tmp_path: Path) -> None:
    plan = _plan_for_dockerfile(
        tmp_path,
        "FROM ctf-os-sandbox:base\nADD https://undeclared.invalid/x /x\nEXPOSE 8000\n",
    )
    assert plan["safe"] is False
    assert any("remote URL" in reason for reason in plan["review_reasons"])


def test_dockerfile_continued_remote_add_is_blocked(tmp_path: Path) -> None:
    plan = _plan_for_dockerfile(
        tmp_path,
        "FROM ctf-os-sandbox:base\n"
        "ADD \\\n"
        "  https://undeclared.invalid/payload /payload\n"
        "EXPOSE 8000\n",
    )
    assert plan["safe"] is False
    assert any("remote URL" in reason for reason in plan["review_reasons"])


def test_dockerfile_json_remote_add_is_blocked(tmp_path: Path) -> None:
    plan = _plan_for_dockerfile(
        tmp_path,
        'FROM ctf-os-sandbox:base\n'
        'ADD ["https://undeclared.invalid/payload", "/payload"]\n'
        "EXPOSE 8000\n",
    )
    assert plan["safe"] is False
    assert any("remote URL" in reason for reason in plan["review_reasons"])


def test_dockerfile_external_copy_from_is_blocked(tmp_path: Path) -> None:
    plan = _plan_for_dockerfile(
        tmp_path,
        "FROM ctf-os-sandbox:base\nCOPY --from=alpine:latest /bin/busybox /busybox\nEXPOSE 8000\n",
    )
    assert plan["safe"] is False
    assert any("external image" in reason for reason in plan["review_reasons"])


def test_dockerfile_internal_stage_copy_is_allowed(tmp_path: Path) -> None:
    plan = _plan_for_dockerfile(
        tmp_path,
        "FROM ctf-os-sandbox:base AS builder\nRUN true\n"
        "FROM ctf-os-sandbox:base\nCOPY --from=builder /app /app\nEXPOSE 8000\n",
    )
    assert plan["safe"] is True
    assert plan["review_reasons"] == []


def test_plain_dockerfile_service_still_safe(tmp_path: Path) -> None:
    plan = _plan_for_dockerfile(
        tmp_path,
        "FROM ctf-os-sandbox:base\nCOPY app /app\nEXPOSE 8000\nCMD ['/app']\n",
    )
    assert plan["safe"] is True
    assert plan["review_reasons"] == []


def test_dockerfile_parser_directive_is_fail_closed(tmp_path: Path) -> None:
    plan = _plan_for_dockerfile(
        tmp_path,
        "# syntax=docker/dockerfile:1\n"
        "FROM ctf-os-sandbox:base\n"
        "EXPOSE 8000\n",
    )
    assert plan["safe"] is False
    assert any("parser directive" in reason for reason in plan["review_reasons"])


@pytest.mark.parametrize(
    ("run_option", "expected"),
    (
        ("--mount=type=cache,target=/root/.cache", "persistent/credential"),
        ("--device=vendor.example/device", "device"),
    ),
)
def test_dockerfile_unsafe_buildkit_run_options_are_blocked(
    tmp_path: Path,
    run_option: str,
    expected: str,
) -> None:
    plan = _plan_for_dockerfile(
        tmp_path,
        "FROM ctf-os-sandbox:base\n"
        f"RUN {run_option} true\n"
        "EXPOSE 8000\n",
    )
    assert plan["safe"] is False
    assert any(expected in reason for reason in plan["review_reasons"])


# H2 final-config gate: fail-closed scan of the fully-resolved compose config.
def test_resolved_config_flags_host_escapes() -> None:
    dangerous = {
        "services": {
            "chall": {
                "privileged": True,
                "network_mode": "host",
                "cap_add": ["SYS_ADMIN"],
                "devices": ["/dev/kvm"],
                "security_opt": ["seccomp=unconfined"],
                "extra_hosts": ["host.docker.internal:host-gateway"],
                "volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}],
            }
        }
    }
    reasons = _scan_resolved_config(dangerous)
    for token in ("privileged", "host/shared", "capabilities", "device", "security_opt", "host-gateway", "Docker socket"):
        assert any(token in reason for reason in reasons), token


def test_resolved_config_allows_hardened_service() -> None:
    hardened = {
        "services": {
            "chall": {
                "image": "ctf-os-sandbox:base",
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "networks": {"ctf_os_race": {}},
                "volumes": [{"type": "volume", "source": "data", "target": "/data"}],
            }
        },
        "networks": {"ctf_os_race": {"external": True, "name": "ctf-os-net-abc"}},
        "volumes": {"data": {}},
    }
    assert _scan_resolved_config(hardened) == []
