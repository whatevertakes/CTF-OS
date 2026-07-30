#!/usr/bin/env python3
"""Focused regressions for isolated Web identities and redacted timelines."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import stat
import sys
import tempfile
import types


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB_TEMPLATES = REPO_ROOT / "templates" / "web"
sys.path.insert(0, str(WEB_TEMPLATES))

session_spec = importlib.util.spec_from_file_location(
    "ctf_web_session_state_under_test",
    WEB_TEMPLATES / "session_state.py",
)
assert session_spec is not None and session_spec.loader is not None
session_state = importlib.util.module_from_spec(session_spec)
session_spec.loader.exec_module(session_state)


def cookie(
    name: str,
    value: str,
    *,
    domain: str = "example.test",
    path: str = "/",
    secure: bool = True,
) -> dict[str, object]:
    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "expires": None,
        "http_only": True,
        "secure": secure,
        "same_site": "Lax",
    }


with tempfile.TemporaryDirectory(prefix="ctf-web-session-") as temporary:
    output_root = pathlib.Path(temporary) / "web"
    output_root.mkdir()
    first = [
        cookie("sessionid", "session-secret-a"),
        cookie("csrf_token", "csrf-secret-a", secure=False),
    ]
    second = [
        cookie("sessionid", "session-secret-b"),
        cookie("csrf_token", "csrf-secret-a", secure=False),
        cookie("preference", "dark"),
    ]
    normalized_first = session_state.normalize_cookies(first)
    normalized_second = session_state.normalize_cookies(second)

    with session_state.PersistentWebSession(
        output_root, "attacker"
    ) as attacker:
        assert attacker.load_cookies() == []
        assert attacker.save_cookies(first) == normalized_first
        event_one = attacker.record_exchange(
            source="http",
            method="POST",
            url=(
                "https://alice:password@example.test/login"
                "/0123456789abcdef0123456789abcdef"
                "?username=alice&password=credential#private"
            ),
            status=302,
            cookies_before=[],
            cookies_after=normalized_first,
            request_headers={
                "Authorization": "Bearer authorization-secret",
                "X-CSRF-Token": "csrf-header-secret",
                "Content-Type": "application/json",
            },
            response_headers={
                "Set-Cookie": "sessionid=session-secret-a",
                "Location": "/account",
            },
            artifact="/work/web/response.json",
        )
        attacker.save_cookies(second)
        event_two = attacker.record_exchange(
            source="browser",
            method="GET",
            url="https://example.test/account?view=private",
            status=200,
            cookies_before=normalized_first,
            cookies_after=normalized_second,
            request_headers={"Cookie": "sessionid=session-secret-a"},
            response_headers={},
            artifact="/work/web/browser.json",
        )

        assert event_one["ordinal"] == 1
        assert event_two["ordinal"] == 2
        assert event_one["request"]["url"] == (
            "https://example.test/login/<redacted-segment>"
            "?password=<redacted>&username=<redacted>"
        )
        assert event_one["request"]["query_names"] == [
            "password",
            "username",
        ]
        assert event_one["request"]["had_userinfo"] is True
        assert event_one["request"]["fragment_removed"] is True
        assert event_one["request"]["path_segment_redacted"] is True
        transition = event_two["cookie_transition"]
        assert [item["name"] for item in transition["created"]] == [
            "preference"
        ]
        assert [item["name"] for item in transition["rotated"]] == [
            "sessionid"
        ]
        assert transition["removed"] == []
        assert {
            (item["kind"], item["name"], item["action"])
            for item in transition["security_material"]
        } == {("session", "sessionid", "rotated")}

    cookie_path = (
        output_root / "sessions" / "attacker" / "cookies.json"
    )
    timeline_path = output_root / "timeline.json"
    assert stat.S_IMODE(cookie_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(timeline_path.stat().st_mode) == 0o600
    cookie_text = cookie_path.read_text(encoding="utf-8")
    timeline_text = timeline_path.read_text(encoding="utf-8")
    assert "session-secret-b" in cookie_text
    for secret in (
        "session-secret-a",
        "session-secret-b",
        "csrf-secret-a",
        "authorization-secret",
        "csrf-header-secret",
        "credential",
        "password@example",
    ):
        assert secret not in timeline_text
    timeline = json.loads(timeline_text)
    assert [item["session"] for item in timeline["events"]] == [
        "attacker",
        "attacker",
    ]
    assert [item["source"] for item in timeline["events"]] == [
        "http",
        "browser",
    ]
    assert timeline["events"][0]["security_headers"] == [
        {
            "kind": "authorization",
            "location": "request",
            "name": "authorization",
        },
        {"kind": "csrf", "location": "request", "name": "x-csrf-token"},
        {"kind": "cookie", "location": "response", "name": "set-cookie"},
    ]

    # Named identities never inherit each other's cookies.
    with session_state.PersistentWebSession(output_root, "user") as user:
        assert user.load_cookies() == []
        user_cookie = [cookie("sessionid", "different-user-secret")]
        user.save_cookies(user_cookie)
        event_three = user.record_exchange(
            source="http",
            method="GET",
            url="https://example.test/profile",
            status=200,
            cookies_before=[],
            cookies_after=user_cookie,
            request_headers={},
            response_headers={},
            artifact="/work/web/response.json",
        )
        assert event_three["ordinal"] == 3
    with session_state.PersistentWebSession(output_root, "admin") as admin:
        assert admin.load_cookies() == []
    combined_timeline = json.loads(timeline_path.read_text(encoding="utf-8"))
    assert [item["session"] for item in combined_timeline["events"]] == [
        "attacker",
        "attacker",
        "user",
    ]

    # Existing jars are read without following a replacement symlink.
    cookie_path.unlink()
    outside = pathlib.Path(temporary) / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    cookie_path.symlink_to(outside)
    try:
        with session_state.PersistentWebSession(
            output_root, "attacker"
        ) as attacker:
            attacker.load_cookies()
    except OSError:
        pass
    else:
        raise AssertionError("symlink cookie jar was followed")


# Metadata header redaction is independent from session persistence.
redacted = session_state.redact_headers(
    {
        "Set-Cookie": "sessionid=secret",
        "Authorization": "Bearer secret",
        "X-CSRF-Token": "secret",
        "X-API-Key": "api-secret",
        "Content-Type": "text/plain",
    }
)
assert redacted == {
    "Set-Cookie": "<redacted>",
    "Authorization": "<redacted>",
    "X-CSRF-Token": "<redacted>",
    "X-API-Key": "<redacted>",
    "Content-Type": "text/plain",
}
for invalid_url in (
    "https://example.test:99999/path",
    "https://[::1/path",
    "/relative/path",
):
    try:
        session_state.sanitize_url(invalid_url)
    except session_state.WebSessionStateError:
        pass
    else:
        raise AssertionError("structurally invalid URL was accepted")


# Both HTTP and browser adapters consume the exact normalized cookie schema.
request_spec = importlib.util.spec_from_file_location(
    "ctf_web_request_under_test",
    WEB_TEMPLATES / "request.py",
)
assert request_spec is not None and request_spec.loader is not None
request_tool = importlib.util.module_from_spec(request_spec)
request_spec.loader.exec_module(request_tool)
requests_session = request_tool.requests.Session()
request_tool.load_requests_cookies(
    requests_session,
    [cookie("sessionid", "roundtrip-secret")],
)
requests_roundtrip = request_tool.dump_requests_cookies(requests_session)
assert requests_roundtrip[0]["name"] == "sessionid"
assert requests_roundtrip[0]["value"] == "roundtrip-secret"
requests_session.close()

playwright_package = types.ModuleType("playwright")
playwright_sync_api = types.ModuleType("playwright.sync_api")


class FakePlaywrightError(Exception):
    pass


playwright_sync_api.Error = FakePlaywrightError
playwright_sync_api.TimeoutError = FakePlaywrightError
playwright_sync_api.sync_playwright = lambda: None
playwright_package.sync_api = playwright_sync_api
sys.modules.setdefault("playwright", playwright_package)
sys.modules.setdefault("playwright.sync_api", playwright_sync_api)
browser_spec = importlib.util.spec_from_file_location(
    "ctf_web_browser_session_under_test",
    WEB_TEMPLATES / "browser.py",
)
assert browser_spec is not None and browser_spec.loader is not None
browser_tool = importlib.util.module_from_spec(browser_spec)
browser_spec.loader.exec_module(browser_tool)
browser_cookie = browser_tool.playwright_cookie_input(
    [cookie("sessionid", "browser-secret")]
)[0]
assert browser_cookie["httpOnly"] is True
assert browser_cookie["sameSite"] == "Lax"
assert browser_tool.normalize_playwright_cookies([browser_cookie])[0][
    "value"
] == "browser-secret"

print("web isolated session and redacted timeline regressions: ok")
