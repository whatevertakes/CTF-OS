from __future__ import annotations

import os

import pytest

from ctf_os.doctor import PROFILES, _image_probe


pytestmark = pytest.mark.skipif(
    os.environ.get("CTF_OS_LIVE_IMAGE_TESTS") != "1",
    reason="live image probe opt-in",
)


@pytest.mark.parametrize("profile", PROFILES)
def test_built_profile_passes_real_operation_probe(profile: str) -> None:
    result = _image_probe(profile)
    assert result.returncode == 0, (
        f"{profile} image probe failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
