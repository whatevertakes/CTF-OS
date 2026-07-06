#!/usr/bin/env python3
"""Run strict deep-tool checks for every supported CTF category."""

from __future__ import annotations

from preflight_check import (
    Reporter,
    check_avr_toolchain,
    check_deep_category_tools,
    requires_avr_toolchain,
)


CATEGORIES = (
    "web",
    "pwn",
    "rev",
    "crypto",
    "forensics",
    "misc",
    "programming",
    "jail",
    "stego",
    "osint",
    "mobile",
    "malware",
    "web3",
    "cloud",
    "container",
    "ai-ml",
    "hardware-rf",
    "side-channel",
    "hybrid",
)


def main() -> int:
    total_failures = 0
    total_warnings = 0
    for category in CATEGORIES:
        print(f"CATEGORY {category}")
        reporter = Reporter()
        if requires_avr_toolchain(category, []):
            check_avr_toolchain(reporter)
        check_deep_category_tools(reporter, category, strict=True)
        print(
            f"CATEGORY_SUMMARY {category} "
            f"failures={reporter.failures} warnings={reporter.warnings}"
        )
        total_failures += reporter.failures
        total_warnings += reporter.warnings
    print(
        f"ALL_CATEGORY_SUMMARY failures={total_failures} "
        f"warnings={total_warnings}"
    )
    return 1 if total_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
