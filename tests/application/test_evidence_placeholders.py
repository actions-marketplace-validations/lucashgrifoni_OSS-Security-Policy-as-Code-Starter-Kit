"""Tests for evidence placeholder detection."""

from __future__ import annotations

from oss_policy_kit.application.evidence_placeholders import (
    has_placeholder_values,
    is_placeholder_digest,
)


def test_placeholder_detection_finds_replace_me() -> None:
    data = {
        "attested_by": "REPLACE_ME_GITHUB_HANDLE",
        "branch": "main",
        "protections": {"require_pull_request_reviews": True},
    }
    result = has_placeholder_values(data)
    assert "REPLACE_ME" in result


def test_placeholder_detection_clean_data() -> None:
    data = {
        "attested_by": "alice",
        "branch": "main",
        "protections": {"require_pull_request_reviews": True},
    }
    result = has_placeholder_values(data)
    assert result == []


def test_placeholder_detection_yyyy_mm_dd() -> None:
    data = {"attested_at": "YYYY-MM-DDTHH:MM:SSZ"}
    result = has_placeholder_values(data)
    assert "YYYY-MM-DD" in result


def test_is_placeholder_digest_all_zeros() -> None:
    assert is_placeholder_digest("0" * 64) is True


def test_is_placeholder_digest_scaffold_template() -> None:
    assert is_placeholder_digest("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") is True


def test_is_placeholder_digest_realistic_hex_not_blocked() -> None:
    assert is_placeholder_digest("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9") is False
    assert is_placeholder_digest("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is False
