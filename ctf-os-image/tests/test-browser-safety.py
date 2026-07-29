#!/usr/bin/env python3
"""Focused regressions for ctf-browser process and screenshot bounds."""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import signal
import sys
import tempfile
import time
import types
from types import SimpleNamespace


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB_TEMPLATES = REPO_ROOT / "templates" / "web"


playwright_package = types.ModuleType("playwright")
playwright_sync_api = types.ModuleType("playwright.sync_api")


class FakePlaywrightError(Exception):
    pass


class FakePlaywrightTimeoutError(FakePlaywrightError):
    pass


playwright_sync_api.Error = FakePlaywrightError
playwright_sync_api.TimeoutError = FakePlaywrightTimeoutError
playwright_sync_api.sync_playwright = lambda: None
playwright_package.sync_api = playwright_sync_api
sys.modules.setdefault("playwright", playwright_package)
sys.modules.setdefault("playwright.sync_api", playwright_sync_api)
sys.path.insert(0, str(WEB_TEMPLATES))

browser_spec = importlib.util.spec_from_file_location(
    "ctf_browser_under_test", WEB_TEMPLATES / "browser.py"
)
assert browser_spec is not None and browser_spec.loader is not None
browser = importlib.util.module_from_spec(browser_spec)
browser_spec.loader.exec_module(browser)


def parse_browser_args(arguments: list[str]) -> SimpleNamespace:
    previous_arguments = sys.argv
    sys.argv = ["browser.py", *arguments]
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return browser.parse_args()
    finally:
        sys.argv = previous_arguments


accepted = parse_browser_args(
    [
        "http://example.test/",
        "--screenshot",
        "--full-page",
        "--max-full-page-height",
        str(browser.HARD_MAX_FULL_PAGE_HEIGHT),
        "--max-screenshot-pixels",
        str(browser.HARD_MAX_SCREENSHOT_PIXELS),
        "--max-screenshot-bytes",
        str(browser.HARD_MAX_SCREENSHOT_BYTES),
    ]
)
assert accepted.max_full_page_height == browser.HARD_MAX_FULL_PAGE_HEIGHT
assert accepted.max_screenshot_pixels == browser.HARD_MAX_SCREENSHOT_PIXELS
assert accepted.max_screenshot_bytes == browser.HARD_MAX_SCREENSHOT_BYTES

for rejected in (
    ["http://example.test/", "--full-page"],
    ["http://example.test/", "--screenshot", "--max-full-page-height", "0"],
    [
        "http://example.test/",
        "--screenshot",
        "--max-full-page-height",
        str(browser.HARD_MAX_FULL_PAGE_HEIGHT + 1),
    ],
    ["http://example.test/", "--screenshot", "--max-screenshot-pixels", "0"],
    [
        "http://example.test/",
        "--screenshot",
        "--max-screenshot-pixels",
        str(browser.HARD_MAX_SCREENSHOT_PIXELS + 1),
    ],
    ["http://example.test/", "--screenshot", "--max-screenshot-bytes", "0"],
    [
        "http://example.test/",
        "--screenshot",
        "--max-screenshot-bytes",
        str(browser.HARD_MAX_SCREENSHOT_BYTES + 1),
    ],
):
    try:
        parse_browser_args(rejected)
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError({"accepted_unsafe_arguments": rejected})


class FakeCdpSession:
    def __init__(self, width: float, height: float, payload: bytes) -> None:
        self.width = width
        self.height = height
        self.payload = payload
        self.detached = False
        self.calls: list[tuple[str, object | None]] = []

    def send(
        self, method: str, parameters: object | None = None
    ) -> dict[str, object]:
        self.calls.append((method, parameters))
        if method == "Page.getLayoutMetrics":
            return {
                "cssContentSize": {
                    "x": 0,
                    "y": 0,
                    "width": self.width,
                    "height": self.height,
                },
                "cssLayoutViewport": {
                    "clientWidth": 1280,
                    "clientHeight": 720,
                },
            }
        assert method == "Page.captureScreenshot"
        return {"data": base64.b64encode(self.payload).decode("ascii")}

    def detach(self) -> None:
        self.detached = True


class FakeScreenshotContext:
    def __init__(self, session: FakeCdpSession) -> None:
        self.session = session

    def new_cdp_session(self, _page: object) -> FakeCdpSession:
        return self.session


class FakeScreenshotPage:
    def __init__(self, width: float, height: float, payload: bytes = b"png") -> None:
        self.session = FakeCdpSession(width, height, payload)
        self.context = FakeScreenshotContext(self.session)
        self.payload = payload
        self.calls: list[dict[str, object]] = []

    def screenshot(self, **kwargs: object) -> bytes:
        self.calls.append(kwargs)
        return self.payload


def screenshot_args(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "full_page": True,
        "viewport": (1280, 720),
        "max_full_page_height": 4096,
        "max_screenshot_pixels": 8_000_000,
        "max_screenshot_bytes": 1024,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


# An oversized document must be rejected before Chromium allocates a bitmap.
oversized_page = FakeScreenshotPage(1280, 4097)
try:
    browser.capture_screenshot(oversized_page, screenshot_args())
except browser.ScreenshotLimitExceeded as exc:
    assert exc.details["screenshot_height"] == 4097
    assert exc.details["max_full_page_height"] == 4096
else:
    raise AssertionError("oversized full-page screenshot was accepted")
assert oversized_page.calls == []
assert oversized_page.session.detached

# Width and height may each be acceptable while their product is not.
excessive_pixels_page = FakeScreenshotPage(10_000, 1000)
try:
    browser.capture_screenshot(excessive_pixels_page, screenshot_args())
except browser.ScreenshotLimitExceeded as exc:
    assert exc.details["screenshot_pixels"] == 10_000_000
    assert exc.details["max_screenshot_pixels"] == 8_000_000
else:
    raise AssertionError("oversized full-page pixel count was accepted")
assert excessive_pixels_page.calls == []
assert excessive_pixels_page.session.detached

# The capture uses a fixed, prevalidated clip. A page that grows after the
# metrics call therefore cannot turn the operation back into an unbounded
# full_page=True capture.
bounded_page = FakeScreenshotPage(1000.1, 2000.1, payload=b"small-png")
image, dimensions = browser.capture_screenshot(
    bounded_page, screenshot_args(max_screenshot_pixels=3_000_000)
)
assert image == b"small-png"
assert dimensions == {"width": 1280, "height": 2001, "pixels": 2_561_280}
assert bounded_page.calls == []
capture_method, capture_parameters = bounded_page.session.calls[1]
assert capture_method == "Page.captureScreenshot"
assert capture_parameters == {
    "format": "png",
    "fromSurface": True,
    "captureBeyondViewport": True,
    "clip": {
        "x": 0,
        "y": 0,
        "width": 1280,
        "height": 2001,
        "scale": 1,
    },
}

# Encoded output is checked before publication, independently of the pixel cap.
high_entropy_page = FakeScreenshotPage(100, 100, payload=b"x" * 1025)
try:
    browser.capture_screenshot(
        high_entropy_page,
        screenshot_args(max_screenshot_bytes=1024),
    )
except browser.ScreenshotLimitExceeded as exc:
    assert exc.details["screenshot_bytes"] == 1025
    assert exc.details["max_screenshot_bytes"] == 1024
else:
    raise AssertionError("oversized encoded screenshot was accepted")


def process_state(pid: int) -> str | None:
    try:
        fields = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    except FileNotFoundError:
        return None
    return fields[2]


with tempfile.TemporaryDirectory(prefix="ctf-browser-supervisor-") as temporary:
    temporary_path = pathlib.Path(temporary)
    descendant_pid_path = temporary_path / "cleanup-descendant.pid"

    class HangingPage:
        def on(self, _event: str, _callback: object) -> None:
            pass

        def goto(self, *_args: object, **_kwargs: object) -> None:
            time.sleep(10)

    class HangingContext:
        def set_extra_http_headers(self, _headers: object) -> None:
            pass

        def new_page(self) -> HangingPage:
            return HangingPage()

    class HangingBrowser:
        def new_context(self, **_kwargs: object) -> HangingContext:
            return HangingContext()

        def close(self) -> None:
            descendant = os.fork()
            if descendant == 0:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                while True:
                    time.sleep(10)
            descendant_pid_path.write_text(str(descendant), encoding="ascii")
            while True:
                time.sleep(10)

    class FakeChromium:
        def launch(self, **_kwargs: object) -> HangingBrowser:
            return HangingBrowser()

    class HangingPlaywright:
        chromium = FakeChromium()

        def stop(self) -> None:
            while True:
                time.sleep(10)

    class FakeStarter:
        def start(self) -> HangingPlaywright:
            return HangingPlaywright()

    browser.sync_playwright = FakeStarter
    browser.CLEANUP_GRACE_SECONDS = 0.2
    args = SimpleNamespace(
        url="http://127.0.0.1:1/",
        insecure=False,
        viewport=(1280, 720),
        user_agent=None,
        header=[],
        wait_until="domcontentloaded",
        timeout=0.1,
        wait_ms=0,
        max_html_bytes=1024,
        screenshot=False,
        full_page=False,
        max_full_page_height=4096,
        max_screenshot_pixels=8_000_000,
        max_screenshot_bytes=1024,
    )
    output_descriptor = browser.open_output_dir(temporary_path)
    started = time.monotonic()
    result = browser.supervise_browser(args, output_descriptor, started)
    elapsed = time.monotonic() - started
    os.close(output_descriptor)

    assert result == 2
    assert elapsed < 1.5, elapsed
    error = json.loads((temporary_path / "browser-error.json").read_text())
    assert error["error"] == "BrowserDeadlineExceeded"
    assert error["message"] == "whole-browser deadline exceeded"
    assert descendant_pid_path.is_file()
    descendant_pid = int(descendant_pid_path.read_text(encoding="ascii"))
    for _ in range(100):
        state = process_state(descendant_pid)
        if state in (None, "Z"):
            break
        time.sleep(0.01)
    else:
        raise AssertionError(
            {"cleanup_descendant_still_alive": descendant_pid, "state": state}
        )

print("browser deadline and screenshot safety regressions: ok")
