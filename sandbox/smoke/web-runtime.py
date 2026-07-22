#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess
import tempfile

from playwright.sync_api import sync_playwright


if os.geteuid() == 0:
    raise SystemExit("web runtime smoke must run as the non-root ctf user")

with tempfile.TemporaryDirectory(prefix="ctf-os-web-") as directory:
    fixture = Path(directory) / "fixture.html"
    fixture.write_text(
        "<!doctype html><title>CTF OS Browser</title>"
        "<main id='result'>CTF_OS_PLAYWRIGHT_OK</main>",
        encoding="utf-8",
    )
    direct = subprocess.run(
        [
            "/usr/bin/chromium", "--headless", "--no-sandbox", "--disable-gpu",
            "--disable-dev-shm-usage", "--dump-dom", fixture.as_uri(),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if "CTF_OS_PLAYWRIGHT_OK" not in direct.stdout:
        raise SystemExit("system Chromium did not read the local fixture")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path="/usr/bin/chromium",
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        page = browser.new_page()
        page.goto(fixture.as_uri())
        assert page.title() == "CTF OS Browser"
        assert page.locator("#result").inner_text() == "CTF_OS_PLAYWRIGHT_OK"
        browser.close()

print("chromium=HEADLESS_LOCAL_OK")
print("playwright=SYSTEM_CHROMIUM_OK")
