#!/opt/venvs/pw/bin/python
"""Bounded, noninteractive Chromium navigation starter for web challenges."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import os
import secrets
import signal
import sys
import time
from pathlib import Path

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright
from safe_output import atomic_write, open_output_dir
from session_state import (
    PersistentWebSession,
    SESSION_NAMES,
    WebSessionStateError,
    normalize_cookies,
    redact_headers,
    sanitize_url,
)

OUTPUT_DIR = Path("/work/web")
HARD_MAX_DEADLINE = 300.0
HARD_MAX_HTML_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FULL_PAGE_HEIGHT = 16_384
HARD_MAX_FULL_PAGE_HEIGHT = 32_768
DEFAULT_MAX_SCREENSHOT_PIXELS = 32 * 1024 * 1024
HARD_MAX_SCREENSHOT_PIXELS = 64 * 1024 * 1024
DEFAULT_MAX_SCREENSHOT_BYTES = 64 * 1024 * 1024
HARD_MAX_SCREENSHOT_BYTES = 128 * 1024 * 1024
CLEANUP_GRACE_SECONDS = 0.5
FORCE_KILL_WAIT_SECONDS = 0.25
SUPERVISOR_POLL_SECONDS = 0.01
RUN_TOKEN_ENV = "CTF_BROWSER_RUN_TOKEN"
MAX_EVENT_COUNT = 100
MAX_EVENT_BYTES = 2048


class BrowserDeadlineExceeded(TimeoutError):
    pass


class BrowserCleanupDeadlineExceeded(TimeoutError):
    pass


class ScreenshotLimitExceeded(RuntimeError):
    def __init__(self, message: str, **details: int) -> None:
        super().__init__(message)
        self.details = details


class SupervisorInterrupted(InterruptedError):
    def __init__(self, signal_number: int) -> None:
        super().__init__(f"browser supervisor interrupted by signal {signal_number}")
        self.signal_number = signal_number


def header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("header must use NAME: VALUE")
    name, raw_value = value.split(":", 1)
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError("header name cannot be empty")
    return name, raw_value.strip()


def viewport(value: str) -> tuple[int, int]:
    try:
        width_text, height_text = value.lower().split("x", 1)
        width, height = int(width_text), int(height_text)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("viewport must use WIDTHxHEIGHT") from exc
    if not 320 <= width <= 7680 or not 200 <= height <= 4320:
        raise argparse.ArgumentTypeError(
            "viewport must be between 320x200 and 7680x4320"
        )
    return width, height


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Open one URL in bundled headless Chromium and save bounded artifacts "
            "under /work/web."
        )
    )
    parser.add_argument("url", help="absolute http:// or https:// URL")
    parser.add_argument(
        "-H", "--header", action="append", default=[], type=header, metavar="NAME: VALUE"
    )
    parser.add_argument(
        "--session",
        choices=SESSION_NAMES,
        help=(
            "persist an isolated attacker, user, or admin cookie jar and append "
            "a redacted HTTP/browser timeline"
        ),
    )
    parser.add_argument("--insecure", action="store_true", help="ignore TLS errors")
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="whole-operation deadline in seconds (default: 20, max: 300)",
    )
    parser.add_argument(
        "--wait-until",
        choices=("commit", "domcontentloaded", "load", "networkidle"),
        default="domcontentloaded",
        help="navigation completion event (default: domcontentloaded)",
    )
    parser.add_argument(
        "--wait-ms",
        type=int,
        default=0,
        help="additional post-navigation wait (default: 0, max: 10000)",
    )
    parser.add_argument(
        "--viewport",
        type=viewport,
        default=(1280, 720),
        metavar="WIDTHxHEIGHT",
    )
    parser.add_argument("--user-agent", help="override the browser user agent")
    parser.add_argument(
        "--screenshot",
        action="store_true",
        help="save /work/web/browser.png",
    )
    parser.add_argument(
        "--full-page",
        action="store_true",
        help="capture the full document when --screenshot is used",
    )
    parser.add_argument(
        "--max-full-page-height",
        type=int,
        default=DEFAULT_MAX_FULL_PAGE_HEIGHT,
        help=(
            "maximum full-page screenshot height in CSS pixels "
            "(default: 16384, max: 32768)"
        ),
    )
    parser.add_argument(
        "--max-screenshot-pixels",
        type=int,
        default=DEFAULT_MAX_SCREENSHOT_PIXELS,
        help=(
            "maximum screenshot pixels "
            "(default: 33554432, max: 67108864)"
        ),
    )
    parser.add_argument(
        "--max-screenshot-bytes",
        type=int,
        default=DEFAULT_MAX_SCREENSHOT_BYTES,
        help=(
            "maximum encoded screenshot bytes "
            "(default: 64 MiB, max: 128 MiB)"
        ),
    )
    parser.add_argument(
        "--max-html-bytes",
        type=int,
        default=16 * 1024 * 1024,
        help="maximum rendered HTML bytes to save (default: 16 MiB, max: 64 MiB)",
    )
    args = parser.parse_args()
    if not args.url.startswith(("http://", "https://")):
        parser.error("url must start with http:// or https://")
    if len(args.url) > 8192:
        parser.error("url must not exceed 8192 characters")
    if not 0.1 <= args.timeout <= HARD_MAX_DEADLINE:
        parser.error("--timeout must be between 0.1 and 300 seconds")
    if not 0 <= args.wait_ms <= 10_000:
        parser.error("--wait-ms must be between 0 and 10000")
    if not 1 <= args.max_html_bytes <= HARD_MAX_HTML_BYTES:
        parser.error("--max-html-bytes must be between 1 byte and 64 MiB")
    if not 1 <= args.max_full_page_height <= HARD_MAX_FULL_PAGE_HEIGHT:
        parser.error("--max-full-page-height must be between 1 and 32768")
    if not 1 <= args.max_screenshot_pixels <= HARD_MAX_SCREENSHOT_PIXELS:
        parser.error("--max-screenshot-pixels must be between 1 and 67108864")
    if not 1 <= args.max_screenshot_bytes <= HARD_MAX_SCREENSHOT_BYTES:
        parser.error("--max-screenshot-bytes must be between 1 byte and 128 MiB")
    if args.full_page and not args.screenshot:
        parser.error("--full-page requires --screenshot")
    return args


def bounded_text(value: object, limit: int = MAX_EVENT_BYTES) -> str:
    encoded = str(value).encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return encoded.decode("utf-8")
    return encoded[:limit].decode("utf-8", errors="replace")


def bounded_headers(headers: dict[str, str]) -> dict[str, str]:
    return redact_headers({
        bounded_text(name, 256): bounded_text(value, 4096)
        for name, value in list(headers.items())[:100]
    })


def playwright_cookie_input(
    cookies: list[dict[str, object]],
) -> list[dict[str, object]]:
    converted: list[dict[str, object]] = []
    for cookie in cookies:
        item: dict[str, object] = {
            "name": cookie["name"],
            "value": cookie["value"],
            "domain": cookie["domain"],
            "path": cookie["path"],
            "expires": (
                float(cookie["expires"])
                if cookie["expires"] is not None
                else -1
            ),
            "httpOnly": cookie["http_only"],
            "secure": cookie["secure"],
        }
        if cookie["same_site"] is not None:
            item["sameSite"] = cookie["same_site"]
        converted.append(item)
    return converted


def normalize_playwright_cookies(
    cookies: list[dict[str, object]],
) -> list[dict[str, object]]:
    return normalize_cookies(
        [
            {
                "name": cookie.get("name"),
                "value": cookie.get("value"),
                "domain": cookie.get("domain", ""),
                "path": cookie.get("path", "/"),
                "expires": cookie.get("expires"),
                "http_only": cookie.get("httpOnly", False),
                "secure": cookie.get("secure", False),
                "same_site": cookie.get("sameSite"),
            }
            for cookie in cookies
        ]
    )


def notify_supervisor(control_descriptor: int | None, event: bytes) -> None:
    if control_descriptor is None:
        return
    try:
        os.write(control_descriptor, event)
    except OSError:
        pass


def write_error(
    output_descriptor: int,
    error: dict[str, object],
    control_descriptor: int | None = None,
) -> None:
    payload = (json.dumps(error, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    atomic_write(output_descriptor, "browser-error.json", payload)
    print(json.dumps(error, ensure_ascii=False), flush=True)
    notify_supervisor(control_descriptor, b"E")


def positive_ceil(value: object, field: str) -> int:
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ScreenshotLimitExceeded(
            f"browser returned an invalid {field}", **{field: 0}
        ) from exc
    if not math.isfinite(numeric) or numeric <= 0:
        raise ScreenshotLimitExceeded(
            f"browser returned an invalid {field}", **{field: 0}
        )
    return math.ceil(numeric)


def full_page_dimensions(metrics: object) -> tuple[int, int]:
    if not isinstance(metrics, dict):
        raise ScreenshotLimitExceeded(
            "browser did not return usable full-page dimensions",
            screenshot_width=0,
            screenshot_height=0,
        )
    content = metrics.get("cssContentSize") or metrics.get("contentSize")
    viewport_metrics = metrics.get("cssLayoutViewport") or metrics.get(
        "layoutViewport"
    )
    if not isinstance(content, dict) or not isinstance(viewport_metrics, dict):
        raise ScreenshotLimitExceeded(
            "browser did not return usable full-page dimensions",
            screenshot_width=0,
            screenshot_height=0,
        )
    width = positive_ceil(
        max(
            float(content.get("width", 0)),
            float(viewport_metrics.get("clientWidth", 0)),
        ),
        "screenshot_width",
    )
    height = positive_ceil(
        max(
            float(content.get("height", 0)),
            float(viewport_metrics.get("clientHeight", 0)),
        ),
        "screenshot_height",
    )
    return width, height


def capture_screenshot(
    page: object, args: argparse.Namespace
) -> tuple[bytes, dict[str, int]]:
    session = None
    if args.full_page:
        session = page.context.new_cdp_session(page)
        try:
            width, height = full_page_dimensions(
                session.send("Page.getLayoutMetrics")
            )
        except BaseException:
            session.detach()
            raise
    else:
        width, height = args.viewport

    pixels = width * height
    details = {
        "screenshot_width": width,
        "screenshot_height": height,
        "screenshot_pixels": pixels,
        "max_full_page_height": args.max_full_page_height,
        "max_screenshot_pixels": args.max_screenshot_pixels,
        "max_screenshot_bytes": args.max_screenshot_bytes,
    }
    if args.full_page and height > args.max_full_page_height:
        session.detach()
        raise ScreenshotLimitExceeded(
            (
                f"full-page screenshot height {height} exceeds "
                f"{args.max_full_page_height}"
            ),
            **details,
        )
    if pixels > args.max_screenshot_pixels:
        if session is not None:
            session.detach()
        raise ScreenshotLimitExceeded(
            f"screenshot pixel count {pixels} exceeds {args.max_screenshot_pixels}",
            **details,
        )

    if args.full_page:
        try:
            capture = session.send(
                "Page.captureScreenshot",
                {
                    "format": "png",
                    "fromSurface": True,
                    "captureBeyondViewport": True,
                    "clip": {
                        "x": 0,
                        "y": 0,
                        "width": width,
                        "height": height,
                        "scale": 1,
                    },
                },
            )
        finally:
            session.detach()
        encoded = capture.get("data") if isinstance(capture, dict) else None
        if not isinstance(encoded, str):
            raise ScreenshotLimitExceeded(
                "browser did not return an encoded screenshot",
                **details,
                screenshot_bytes=0,
            )
        padding = len(encoded) - len(encoded.rstrip("="))
        encoded_size = (
            len(encoded) // 4 * 3 - padding
            if len(encoded) % 4 == 0 and padding <= 2
            else None
        )
        if (
            encoded_size is not None
            and encoded_size > args.max_screenshot_bytes
        ):
            raise ScreenshotLimitExceeded(
                (
                    f"encoded screenshot size {encoded_size} exceeds "
                    f"{args.max_screenshot_bytes}"
                ),
                **details,
                screenshot_bytes=encoded_size,
            )
        try:
            screenshot = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ScreenshotLimitExceeded(
                "browser returned an invalid encoded screenshot",
                **details,
                screenshot_bytes=0,
            ) from exc
    else:
        screenshot = page.screenshot()
    if len(screenshot) > args.max_screenshot_bytes:
        raise ScreenshotLimitExceeded(
            (
                f"encoded screenshot size {len(screenshot)} exceeds "
                f"{args.max_screenshot_bytes}"
            ),
            **details,
            screenshot_bytes=len(screenshot),
        )
    return screenshot, {"width": width, "height": height, "pixels": pixels}


def remove_artifact(output_descriptor: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=output_descriptor)
    except FileNotFoundError:
        pass


def run_browser(
    args: argparse.Namespace,
    output_descriptor: int,
    started: float,
    control_descriptor: int | None,
) -> int:
    deadline = started + args.timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        write_error(
            output_descriptor,
            {
                "ok": False,
                "error": "BrowserDeadlineExceeded",
                "message": "whole-browser deadline exceeded before startup",
                "deadline_seconds": args.timeout,
                "elapsed_seconds": round(time.monotonic() - started, 6),
            },
            control_descriptor,
        )
        return 2

    previous_alarm_handler = signal.getsignal(signal.SIGALRM)

    def deadline_alarm(_signum: int, _frame: object) -> None:
        raise BrowserDeadlineExceeded("whole-browser deadline exceeded")

    console_events: list[dict[str, str]] = []
    page_errors: list[str] = []
    browser = None
    playwright = None
    web_session: PersistentWebSession | None = None
    cookies_before: list[dict[str, object]] = []
    cookies_after: list[dict[str, object]] = []
    signal.signal(signal.SIGALRM, deadline_alarm)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        session_name = getattr(args, "session", None)
        if session_name is not None:
            web_session = PersistentWebSession(OUTPUT_DIR, session_name)
            web_session.__enter__()
            cookies_before = web_session.load_cookies()
        playwright = sync_playwright().start()
        browser = playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        width, height = args.viewport
        context_options: dict[str, object] = {
            "ignore_https_errors": args.insecure,
            "viewport": {"width": width, "height": height},
            "service_workers": "block",
        }
        if args.user_agent:
            context_options["user_agent"] = args.user_agent
        if web_session is not None:
            context_options["storage_state"] = {
                "cookies": playwright_cookie_input(cookies_before),
                "origins": [],
            }
        context = browser.new_context(**context_options)
        if args.header:
            context.set_extra_http_headers(dict(args.header))
        page = context.new_page()

        def record_console(message: object) -> None:
            if len(console_events) < MAX_EVENT_COUNT:
                console_events.append(
                    {
                        "type": bounded_text(getattr(message, "type", "console"), 64),
                        "text": bounded_text(getattr(message, "text", message)),
                    }
                )

        def record_page_error(error: object) -> None:
            if len(page_errors) < MAX_EVENT_COUNT:
                page_errors.append(bounded_text(error))

        page.on("console", record_console)
        page.on("pageerror", record_page_error)
        response = page.goto(
            args.url,
            wait_until=args.wait_until,
            timeout=max(1, int(args.timeout * 1000)),
        )
        if args.wait_ms:
            page.wait_for_timeout(args.wait_ms)

        rendered = page.content().encode("utf-8", errors="replace")
        html_truncated = len(rendered) > args.max_html_bytes
        rendered = rendered[: args.max_html_bytes]
        atomic_write(output_descriptor, "browser.html", rendered)

        files = {
            "html": str(OUTPUT_DIR / "browser.html"),
            "metadata": str(OUTPUT_DIR / "browser.json"),
        }
        screenshot_metadata = None
        if args.screenshot:
            remove_artifact(output_descriptor, "browser.png")
            screenshot, screenshot_metadata = capture_screenshot(page, args)
            atomic_write(output_descriptor, "browser.png", screenshot)
            files["screenshot"] = str(OUTPUT_DIR / "browser.png")

        if web_session is not None:
            cookies_after = normalize_playwright_cookies(context.cookies())
            web_session.save_cookies(cookies_after)
            web_session.record_exchange(
                source="browser",
                method="GET",
                url=args.url,
                status=response.status if response is not None else None,
                cookies_before=cookies_before,
                cookies_after=cookies_after,
                request_headers=dict(args.header),
                response_headers=(
                    dict(response.headers) if response is not None else {}
                ),
                artifact=str(OUTPUT_DIR / "browser.json"),
            )

        metadata = {
            "ok": True,
            "request": {
                **sanitize_url(args.url),
                "wait_until": args.wait_until,
                "wait_ms": args.wait_ms,
                "full_page": args.full_page,
            },
            "deadline_seconds": args.timeout,
            "limits": {
                "max_full_page_height": args.max_full_page_height,
                "max_screenshot_pixels": args.max_screenshot_pixels,
                "max_screenshot_bytes": args.max_screenshot_bytes,
            },
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "response": {
                "status": response.status if response is not None else None,
                **sanitize_url(page.url),
                "headers": (
                    bounded_headers(response.headers) if response is not None else {}
                ),
                "title": bounded_text(page.title(), 4096),
                "saved_html_bytes": len(rendered),
                "html_truncated": html_truncated,
            },
            "console": console_events,
            "page_errors": page_errors,
            "files": files,
        }
        if web_session is not None:
            metadata["session"] = {
                "name": web_session.session_name,
                "cookie_count": len(cookies_after),
                "timeline": str(web_session.timeline_path),
            }
        if screenshot_metadata is not None:
            metadata["screenshot"] = {
                **screenshot_metadata,
                "saved_bytes": len(screenshot),
            }
        atomic_write(
            output_descriptor,
            "browser.json",
            (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode(
                "utf-8"
            ),
        )
        print(
            json.dumps(
                {
                    "ok": True,
                    "status": metadata["response"]["status"],
                    "url": metadata["response"]["url"],
                    "title": metadata["response"]["title"],
                    "saved_html_bytes": len(rendered),
                    "html_truncated": html_truncated,
                    "files": files,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        return 0
    except (BrowserDeadlineExceeded, PlaywrightTimeoutError) as exc:
        write_error(
            output_descriptor,
            {
                "ok": False,
                "error": "BrowserDeadlineExceeded",
                "message": bounded_text(exc),
                "deadline_seconds": args.timeout,
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "cleanup_grace_seconds": CLEANUP_GRACE_SECONDS,
            },
            control_descriptor,
        )
        return 2
    except ScreenshotLimitExceeded as exc:
        write_error(
            output_descriptor,
            {
                "ok": False,
                "error": "ScreenshotLimitExceeded",
                "message": bounded_text(exc),
                "elapsed_seconds": round(time.monotonic() - started, 6),
                **exc.details,
            },
            control_descriptor,
        )
        return 2
    except WebSessionStateError as exc:
        write_error(
            output_descriptor,
            {
                "ok": False,
                "error": type(exc).__name__,
                "message": bounded_text(exc),
                "elapsed_seconds": round(time.monotonic() - started, 6),
            },
            control_descriptor,
        )
        return 2
    except PlaywrightError as exc:
        write_error(
            output_descriptor,
            {
                "ok": False,
                "error": type(exc).__name__,
                "message": "browser operation failed",
                "request": sanitize_url(args.url),
                "elapsed_seconds": round(time.monotonic() - started, 6),
            },
            control_descriptor,
        )
        return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

        def cleanup_alarm(_signum: int, _frame: object) -> None:
            raise BrowserCleanupDeadlineExceeded(
                "browser cleanup deadline exceeded"
            )

        signal.signal(signal.SIGALRM, cleanup_alarm)
        signal.setitimer(signal.ITIMER_REAL, CLEANUP_GRACE_SECONDS)
        try:
            if browser is not None:
                try:
                    browser.close()
                except PlaywrightError:
                    pass
            if playwright is not None:
                try:
                    playwright.stop()
                except PlaywrightError:
                    pass
            if web_session is not None:
                web_session.close()
        except BrowserCleanupDeadlineExceeded:
            pass
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_alarm_handler)


def process_identity(pid: int) -> tuple[str, int, int]:
    stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = stat_text[stat_text.rfind(")") + 2 :].split()
    return fields[0], int(fields[3]), int(fields[19])


def process_has_run_token(pid: int, encoded_token: bytes) -> bool:
    try:
        with open(f"/proc/{pid}/environ", "rb", buffering=0) as environment:
            data = environment.read(1024 * 1024 + 1)
    except OSError:
        return False
    return encoded_token in data.split(b"\0")


def signal_worker_processes(
    worker_pid: int,
    worker_start_ticks: int,
    run_token: str,
    signal_number: int,
) -> list[int]:
    encoded_token = f"{RUN_TOKEN_ENV}={run_token}".encode("ascii")
    targets: list[int] = []
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        entries = []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            state, session_id, start_ticks = process_identity(pid)
        except (OSError, ValueError, IndexError):
            continue
        if state in {"Z", "X", "x"} or start_ticks < worker_start_ticks:
            continue
        if (
            pid == worker_pid
            or session_id == worker_pid
            or process_has_run_token(pid, encoded_token)
        ):
            targets.append(pid)

    targets.sort(key=lambda pid: pid == worker_pid)
    for pid in targets:
        try:
            os.kill(pid, signal_number)
        except ProcessLookupError:
            pass
    return targets


def drain_control(control_descriptor: int) -> bytes:
    events = bytearray()
    while True:
        try:
            chunk = os.read(control_descriptor, 4096)
        except BlockingIOError:
            break
        if not chunk:
            break
        events.extend(chunk)
    return bytes(events)


def reap_worker(worker_pid: int) -> tuple[bool, int | None]:
    try:
        waited_pid, status = os.waitpid(worker_pid, os.WNOHANG)
    except ChildProcessError:
        return True, None
    return waited_pid == worker_pid, status if waited_pid == worker_pid else None


def kill_worker_group(worker_pid: int) -> None:
    try:
        os.killpg(worker_pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.kill(worker_pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def force_stop_worker(
    worker_pid: int,
    worker_start_ticks: int,
    run_token: str,
) -> tuple[bool, list[int]]:
    deadline = time.monotonic() + FORCE_KILL_WAIT_SECONDS
    reaped = False
    status = None
    survivors: list[int] = []
    while True:
        kill_worker_group(worker_pid)
        survivors = signal_worker_processes(
            worker_pid,
            worker_start_ticks,
            run_token,
            signal.SIGKILL,
        )
        if not reaped:
            reaped, status = reap_worker(worker_pid)
        if reaped and not survivors:
            return True, []
        if time.monotonic() >= deadline:
            return reaped, survivors
        time.sleep(SUPERVISOR_POLL_SECONDS)


def child_process(
    args: argparse.Namespace,
    output_descriptor: int,
    started: float,
    control_descriptor: int,
    run_token: str,
) -> None:
    status = 2
    try:
        os.environ[RUN_TOKEN_ENV] = run_token
        os.setsid()
        notify_supervisor(control_descriptor, b"R")
        status = run_browser(
            args,
            output_descriptor,
            started,
            control_descriptor,
        )
    except BaseException as exc:
        try:
            write_error(
                output_descriptor,
                {
                    "ok": False,
                    "error": "BrowserWorkerError",
                    "message": bounded_text(exc),
                    "elapsed_seconds": round(time.monotonic() - started, 6),
                },
                control_descriptor,
            )
        except BaseException:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "BrowserWorkerError",
                        "message": bounded_text(exc),
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
    finally:
        try:
            os.close(output_descriptor)
        except OSError:
            pass
        try:
            os.close(control_descriptor)
        except OSError:
            pass
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(status)


def supervise_browser(
    args: argparse.Namespace,
    output_descriptor: int,
    started: float,
) -> int:
    control_read, control_write = os.pipe()
    os.set_blocking(control_read, False)
    run_token = secrets.token_hex(16)
    worker_pid = os.fork()
    if worker_pid == 0:
        os.close(control_read)
        child_process(
            args,
            output_descriptor,
            started,
            control_write,
            run_token,
        )
        os._exit(2)
    os.close(control_write)

    worker_start_ticks = 0
    for _ in range(100):
        try:
            _state, _session_id, worker_start_ticks = process_identity(worker_pid)
            break
        except (OSError, ValueError, IndexError):
            time.sleep(0.001)

    events = bytearray()
    hard_deadline = started + args.timeout + CLEANUP_GRACE_SECONDS
    interrupted_signal: int | None = None
    previous_handlers: dict[int, object] = {}

    def interrupt_supervisor(signal_number: int, _frame: object) -> None:
        kill_worker_group(worker_pid)
        raise SupervisorInterrupted(signal_number)

    for signal_number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        previous_handlers[signal_number] = signal.getsignal(signal_number)
        signal.signal(signal_number, interrupt_supervisor)

    try:
        while True:
            events.extend(drain_control(control_read))
            reaped, status = reap_worker(worker_pid)
            if reaped:
                if status is None:
                    return 2
                exit_code = os.waitstatus_to_exitcode(status)
                if exit_code >= 0:
                    return exit_code
                if b"E" not in events:
                    write_error(
                        output_descriptor,
                        {
                            "ok": False,
                            "error": "BrowserWorkerTerminated",
                            "message": f"browser worker exited on signal {-exit_code}",
                            "elapsed_seconds": round(
                                time.monotonic() - started, 6
                            ),
                        },
                    )
                return 2
            if time.monotonic() >= hard_deadline:
                break
            time.sleep(
                min(
                    SUPERVISOR_POLL_SECONDS,
                    max(0.0, hard_deadline - time.monotonic()),
                )
            )
    except SupervisorInterrupted as exc:
        interrupted_signal = exc.signal_number
    finally:
        _reaped, survivors = force_stop_worker(
            worker_pid,
            worker_start_ticks,
            run_token,
        )
        events.extend(drain_control(control_read))
        os.close(control_read)
        for signal_number, previous_handler in previous_handlers.items():
            signal.signal(signal_number, previous_handler)

    if interrupted_signal is not None:
        return 128 + interrupted_signal
    if b"E" not in events:
        write_error(
            output_descriptor,
            {
                "ok": False,
                "error": "BrowserDeadlineExceeded",
                "message": "browser worker exceeded its cleanup deadline",
                "deadline_seconds": args.timeout,
                "cleanup_grace_seconds": CLEANUP_GRACE_SECONDS,
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "cleanup_complete": not survivors,
                "surviving_pids": survivors[:20],
            },
        )
    return 2


def main() -> int:
    args = parse_args()
    try:
        output_descriptor = open_output_dir(OUTPUT_DIR)
    except OSError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "UnsafeOutputDirectory",
                    "message": bounded_text(exc),
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        return 2

    started = time.monotonic()
    try:
        return supervise_browser(args, output_descriptor, started)
    finally:
        os.close(output_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
