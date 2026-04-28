from __future__ import annotations

from pathlib import Path

import pytest
from scripts import consumer_smoke, twine_check_dist


def _write_pyproject(repo_root: Path, version: str = "3.3.0") -> None:
    (repo_root / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'name = "oss-policy-kit"',
                f'version = "{version}"',
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_consumer_smoke_resolves_only_current_version_wheel(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "oss_policy_kit-3.2.0-py3-none-any.whl").write_text("old", encoding="utf-8")
    expected = dist / "oss_policy_kit-3.3.0-py3-none-any.whl"
    expected.write_text("current", encoding="utf-8")

    wheel = consumer_smoke.resolve_wheel(tmp_path)

    assert wheel == expected


def test_consumer_smoke_fails_when_current_version_wheel_is_ambiguous(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "oss_policy_kit-3.3.0-py3-none-any.whl").write_text("one", encoding="utf-8")
    (dist / "oss_policy_kit-3.3.0-py312-none-any.whl").write_text("two", encoding="utf-8")

    with pytest.raises(SystemExit, match="Expected exactly one wheel"):
        consumer_smoke.resolve_wheel(tmp_path)


def test_twine_check_dist_uses_only_current_version_artifacts(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "oss_policy_kit-3.2.0.tar.gz").write_text("old-sdist", encoding="utf-8")
    (dist / "oss_policy_kit-3.2.0-py3-none-any.whl").write_text("old-wheel", encoding="utf-8")
    expected_sdist = dist / "oss_policy_kit-3.3.0.tar.gz"
    expected_wheel = dist / "oss_policy_kit-3.3.0-py3-none-any.whl"
    expected_sdist.write_text("new-sdist", encoding="utf-8")
    expected_wheel.write_text("new-wheel", encoding="utf-8")

    resolved = twine_check_dist.resolve_dist_artifacts(tmp_path)

    assert resolved == [expected_sdist, expected_wheel]
