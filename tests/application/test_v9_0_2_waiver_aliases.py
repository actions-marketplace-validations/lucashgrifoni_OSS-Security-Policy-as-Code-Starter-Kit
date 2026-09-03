"""v9.0.2 regression: legacy ``reason``/``expires_on`` waiver keys are accepted.

The scaffolded ``waivers.yaml`` stub and remediation text historically documented
``reason`` and ``expires_on``, but the loader only read ``justification`` and
``expires_at`` -- so a waiver written per the kit's own docs was silently ignored
(state stayed FAIL, gate stayed red). The loader now accepts both spellings.
"""

from pathlib import Path

from oss_policy_kit.application.waivers import parse_waivers_file


def _yaml(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "w.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_legacy_reason_expires_on_parses_like_canonical(tmp_path: Path) -> None:
    """A ``reason``/``expires_on`` record parses identically to ``justification``/``expires_at``."""

    legacy = parse_waivers_file(
        _yaml(
            tmp_path,
            "waivers:\n"
            "  - control_id: GH-PIN-007\n"
            "    owner: appsec-team\n"
            "    reason: Pinned-by-tag is acceptable for internal-only repository.\n"
            "    expires_on: '2099-12-31'\n",
        )
    )

    canonical_dir = tmp_path / "canonical"
    canonical_dir.mkdir()
    canonical_path = canonical_dir / "w.yaml"
    canonical_path.write_text(
        "waivers:\n"
        "  - control_id: GH-PIN-007\n"
        "    owner: appsec-team\n"
        "    justification: Pinned-by-tag is acceptable for internal-only repository.\n"
        "    expires_at: '2099-12-31'\n",
        encoding="utf-8",
    )
    canonical = parse_waivers_file(canonical_path)

    legacy_rec = legacy.by_control["GH-PIN-007"]
    canonical_rec = canonical.by_control["GH-PIN-007"]

    # The legacy ``reason`` populates ``justification``; ``expires_on`` populates expiry.
    assert legacy_rec.justification == "Pinned-by-tag is acceptable for internal-only repository."
    assert legacy_rec.expires_at == canonical_rec.expires_at
    assert legacy_rec.expires_at is not None
    assert legacy_rec.status == "approved"
    assert legacy_rec == canonical_rec
    # The record is actually present (it waives the failing control, not silently dropped).
    assert not any("ignored" in w.lower() for w in legacy.warnings)


def test_canonical_keys_win_over_legacy_when_both_present(tmp_path: Path) -> None:
    """When both spellings are present, the canonical key takes precedence."""

    out = parse_waivers_file(
        _yaml(
            tmp_path,
            "waivers:\n"
            "  - control_id: GH-PIN-007\n"
            "    owner: appsec-team\n"
            "    justification: canonical wins\n"
            "    reason: legacy loses\n"
            "    expires_at: '2099-12-31'\n"
            "    expires_on: '2000-01-01'\n",
        )
    )

    rec = out.by_control["GH-PIN-007"]
    assert rec.justification == "canonical wins"
    assert rec.expires_at is not None
    assert rec.expires_at.isoformat() == "2099-12-31"
