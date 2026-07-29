"""Run the CTF-OS tool image with host acceleration and debug access.

The launcher keeps host-specific device wiring out of the image. It prefers
native NVIDIA CDI and falls back to the configured NVIDIA Docker runtime.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ctf_os.docker_mount import bind_mount_spec

DEFAULT_IMAGE = "ctf-os:core"
DEFAULT_NETWORK = "bridge"
NVIDIA_DRIVER_CAPABILITIES = "compute,utility"
NETWORK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class CLIError(Exception):
    """An expected launcher failure with a stable process exit code."""

    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class GPUPlan:
    mode: str
    detail: str
    docker_flags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunConfig:
    image: str
    command: tuple[str, ...]
    name: str | None = None
    network: str = DEFAULT_NETWORK
    challenge: Path | None = None
    work: Path | None = None
    gpu_policy: str = "auto"
    kvm_policy: str = "auto"
    ptrace: bool = True
    interactive: bool = False
    tty: bool = False
    detach: bool = False


def _run_capture(
    runner: Runner,
    command: Sequence[str],
    *,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        return subprocess.CompletedProcess(command, 127, "", str(error))
    except subprocess.TimeoutExpired as error:
        return subprocess.CompletedProcess(command, 124, "", str(error))
    except OSError as error:
        return subprocess.CompletedProcess(command, 126, "", str(error))


def _is_character_device(path: Path) -> bool:
    try:
        return stat.S_ISCHR(path.stat().st_mode)
    except OSError:
        return False


def _native_cdi_plan(
    *,
    runner: Runner,
    which: Callable[[str], str | None],
) -> GPUPlan | None:
    nvidia_ctk = which("nvidia-ctk")
    if not nvidia_ctk:
        return None
    result = _run_capture(runner, [nvidia_ctk, "cdi", "list"])
    if result.returncode != 0:
        return None
    if "nvidia.com/gpu=all" not in result.stdout:
        return None
    return GPUPlan(
        mode="cdi",
        detail="NVIDIA CDI device nvidia.com/gpu=all",
        docker_flags=(
            "--device",
            "nvidia.com/gpu=all",
            "--env",
            f"NVIDIA_DRIVER_CAPABILITIES={NVIDIA_DRIVER_CAPABILITIES}",
        ),
    )


def _native_runtime_plan(*, runner: Runner) -> GPUPlan | None:
    result = _run_capture(
        runner, ["docker", "info", "--format", "{{json .Runtimes}}"]
    )
    if result.returncode != 0:
        return None
    try:
        runtimes = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(runtimes, dict) or "nvidia" not in runtimes:
        return None
    return GPUPlan(
        mode="nvidia-runtime",
        detail="Docker NVIDIA runtime",
        docker_flags=(
            "--gpus",
            "all",
            "--env",
            f"NVIDIA_DRIVER_CAPABILITIES={NVIDIA_DRIVER_CAPABILITIES}",
        ),
    )


def detect_gpu_plan(
    *,
    policy: str,
    runner: Runner = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
) -> GPUPlan | None:
    if policy == "off":
        return None
    for detector in (
        lambda: _native_cdi_plan(runner=runner, which=which),
        lambda: _native_runtime_plan(runner=runner),
    ):
        plan = detector()
        if plan is not None:
            return plan
    if policy == "required":
        raise CLIError(
            "GPU가 필요하지만 NVIDIA CDI 또는 Docker NVIDIA runtime을 "
            "사용할 수 없습니다."
        )
    return None


def detect_kvm(
    *,
    policy: str,
    device: Path = Path("/dev/kvm"),
    is_character_device: Callable[[Path], bool] = _is_character_device,
) -> bool:
    if policy == "off":
        return False
    available = is_character_device(device)
    if not available and policy == "required":
        raise CLIError("KVM이 필요하지만 호스트 /dev/kvm 장치가 없습니다.")
    return available


def _validated_directory(path: Path, label: str, *, create: bool) -> Path:
    resolved = path.expanduser().resolve()
    if create:
        try:
            resolved.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise CLIError(f"{label} 디렉터리를 만들 수 없습니다: {error}") from error
    if not resolved.is_dir():
        raise CLIError(f"{label} 경로가 디렉터리가 아닙니다: {resolved}")
    return resolved


def _validate_network(network: str) -> str:
    if not NETWORK_NAME.fullmatch(network):
        raise CLIError(f"유효하지 않은 Docker 네트워크 이름입니다: {network!r}")
    return network


def build_docker_run_argv(
    config: RunConfig,
    *,
    gpu_plan: GPUPlan | None,
    kvm_available: bool,
    docker: str = "docker",
) -> list[str]:
    if not config.command:
        raise CLIError("'--' 뒤에 실행할 명령을 지정하세요.")

    argv = [
        docker,
        "run",
        "--rm",
        "--init",
        "--shm-size",
        "1g",
        "--network",
        _validate_network(config.network),
    ]
    if config.interactive:
        argv.append("--interactive")
    if config.tty:
        argv.append("--tty")
    if config.detach:
        argv.append("--detach")
    if config.name:
        argv.extend(["--name", config.name])
    if config.ptrace:
        argv.extend(
            [
                "--cap-add",
                "SYS_PTRACE",
                "--security-opt",
                "seccomp=unconfined",
            ]
        )
    if kvm_available:
        argv.extend(["--device", "/dev/kvm"])
    if gpu_plan is not None:
        argv.extend(gpu_plan.docker_flags)
    if config.challenge is not None:
        argv.extend(
            [
                "--mount",
                bind_mount_spec(
                    config.challenge,
                    "/challenge",
                    readonly=True,
                ),
            ]
        )
    if config.work is not None:
        argv.extend(
            [
                "--mount",
                bind_mount_spec(config.work, "/work"),
            ]
        )
    argv.append(config.image)
    argv.extend(config.command)
    return argv


def _run_config_from_args(args: argparse.Namespace) -> RunConfig:
    command = tuple(args.command)
    if command and command[0] == "--":
        command = command[1:]
    challenge = (
        _validated_directory(args.challenge, "challenge", create=False)
        if args.challenge is not None
        else None
    )
    work = (
        _validated_directory(args.work, "work", create=True)
        if args.work is not None
        else None
    )
    return RunConfig(
        image=args.image,
        command=command,
        name=args.name,
        network=args.network,
        challenge=challenge,
        work=work,
        gpu_policy=args.gpu,
        kvm_policy=args.kvm,
        ptrace=args.ptrace,
        interactive=args.interactive,
        tty=args.tty,
        detach=args.detach,
    )


def _capability_summary(
    *,
    gpu_plan: GPUPlan | None,
    kvm_available: bool,
) -> dict[str, object]:
    return {
        "gpu": {
            "available": gpu_plan is not None,
            "mode": gpu_plan.mode if gpu_plan else "cpu-fallback",
            "detail": gpu_plan.detail if gpu_plan else "GPU passthrough unavailable",
        },
        "kvm": {
            "available": kvm_available,
            "device": "/dev/kvm" if kvm_available else None,
        },
        "ptrace": {
            "enabled_by_default": True,
            "flags": [
                "--cap-add",
                "SYS_PTRACE",
                "--security-opt",
                "seccomp=unconfined",
            ],
        },
        "network": {
            "default": DEFAULT_NETWORK,
            "external_access": True,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-container",
        description=(
            "GPU, KVM, ptrace 권한을 자동 연결해 CTF-OS 도구 이미지를 실행합니다."
        ),
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    doctor = subparsers.add_parser(
        "doctor", help="호스트에서 자동 연결 가능한 기능을 JSON으로 표시합니다."
    )
    doctor.add_argument(
        "--gpu", choices=("auto", "off", "required"), default="auto"
    )
    doctor.add_argument(
        "--kvm", choices=("auto", "off", "required"), default="auto"
    )

    run = subparsers.add_parser(
        "run", help="자동 권한이 적용된 일회성 컨테이너에서 명령을 실행합니다."
    )
    run.add_argument("--image", default=DEFAULT_IMAGE)
    run.add_argument("--name")
    run.add_argument("--network", default=DEFAULT_NETWORK)
    run.add_argument("--challenge", type=Path)
    run.add_argument("--work", type=Path)
    run.add_argument(
        "--gpu", choices=("auto", "off", "required"), default="auto"
    )
    run.add_argument(
        "--kvm", choices=("auto", "off", "required"), default="auto"
    )
    run.add_argument(
        "--ptrace",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    run.add_argument("-i", "--interactive", action="store_true")
    run.add_argument("-t", "--tty", action="store_true")
    run.add_argument("-d", "--detach", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner = subprocess.run,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        gpu_plan = detect_gpu_plan(policy=args.gpu, runner=runner)
        kvm_available = detect_kvm(policy=args.kvm)

        if args.action == "doctor":
            print(
                json.dumps(
                    _capability_summary(
                        gpu_plan=gpu_plan,
                        kvm_available=kvm_available,
                    ),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0

        config = _run_config_from_args(args)
        command = build_docker_run_argv(
            config,
            gpu_plan=gpu_plan,
            kvm_available=kvm_available,
        )
        try:
            result = runner(command, check=False)
        except FileNotFoundError as error:
            raise CLIError("docker 실행 파일을 찾을 수 없습니다.", 127) from error
        except OSError as error:
            raise CLIError(f"Docker 컨테이너를 실행할 수 없습니다: {error}", 126) from error
        return result.returncode
    except CLIError as error:
        print(f"오류: {error}", file=sys.stderr)
        return error.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
