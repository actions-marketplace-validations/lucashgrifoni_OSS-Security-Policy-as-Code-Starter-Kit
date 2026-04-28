"""v4.0.0: custom profiles must not reference removed control IDs."""

from __future__ import annotations

import pytest

from oss_policy_kit.application.loader import load_profile
from oss_policy_kit.domain.errors import ProfileLoadError


@pytest.mark.parametrize("removed_id", ("SEC-AUDIT-016", "CI-SBOM-017"))
def test_load_fails_with_clear_message(tmp_path, removed_id: str) -> None:
    bad = tmp_path / "bad.yaml"
    body = f"id: custom-local\ntitle: Broken\ncontrols:\n  - {removed_id}\n"
    bad.write_text(body, encoding="ascii")
    with pytest.raises(ProfileLoadError, match="v4.0.0|migration"):
        load_profile(bad)
