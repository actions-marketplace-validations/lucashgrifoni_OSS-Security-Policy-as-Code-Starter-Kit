"""v9.0.2 hotfix regressions: non-UTF-8 evidence/scorecard/config and config contract.

These guard the F6 bug group:

- A UTF-16 (non-UTF-8) evidence file must NOT crash an evaluator with an
  uncaught ``UnicodeDecodeError`` (a ``ValueError`` subclass). The shared
  evidence readers now degrade to the same manual-review / not-evaluated
  outcome the invalid-JSON path already used, so a report is still produced.
- A UTF-16 Scorecard JSON makes ``load_scorecard_json`` raise a domain
  ``LoadError`` (mapped to a clean exit, never a raw traceback).
- An oversize Scorecard JSON is refused via ``oversize_reason`` before any
  unbounded read.
- A persisted config with a removed ``report_json_contract`` (e.g. ``1.0``)
  is rejected with ``InvalidInputError`` (reports/2.0 is the only contract,
  ADR-043).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.adapters.scorecard_json import load_scorecard_json
from oss_policy_kit.application.config_loader import load_project_config
from oss_policy_kit.application.evaluators import _parse_branch_protection_evidence
from oss_policy_kit.application.evaluators_common import validate_json_evidence
from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES, oversize_reason
from oss_policy_kit.domain.errors import InvalidInputError, LoadError
from oss_policy_kit.domain.models import ControlStatus

# A well-formed JSON object whose UTF-16 encoding contains bytes that are not
# valid UTF-8 (the BOM + NUL-padded code units), forcing a ``UnicodeDecodeError``
# when read with ``encoding="utf-8"``.
_JSON_BODY = '{"schema_version": "branch-protection/v1", "branch": "main"}'


def _write_utf16(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-16")
    return path


def test_utf16_evidence_degrades_instead_of_crashing(tmp_path: Path) -> None:
    """A UTF-16 evidence file yields a manual-review outcome, not exit-3 crash."""

    evidence = _write_utf16(tmp_path / "branch-protection.json", _JSON_BODY)

    # Pre-fix this raised ``UnicodeDecodeError`` (escaping the OSError/JSONDecodeError
    # catch) and no outcome was returned. Post-fix it degrades cleanly.
    outcome = _parse_branch_protection_evidence(evidence)

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "unreadable or invalid JSON" in outcome.reason


def test_utf16_evidence_via_validate_json_evidence_returns_error(tmp_path: Path) -> None:
    """The shared validator returns an error string rather than raising."""

    evidence = _write_utf16(tmp_path / "evidence.json", _JSON_BODY)

    data, error, placeholders = validate_json_evidence(
        evidence,
        schema_loader=lambda: {"type": "object"},
        evidence_name="Example",
    )

    assert data is None
    assert error is not None
    assert "unreadable or invalid JSON" in error
    assert placeholders == []


def test_utf16_scorecard_json_raises_load_error(tmp_path: Path) -> None:
    """A non-UTF-8 Scorecard export surfaces a domain LoadError (clean exit 2)."""

    scorecard = _write_utf16(tmp_path / "scorecard-result.json", '{"score": 7.5}')

    with pytest.raises(LoadError):
        load_scorecard_json(scorecard)


def test_oversize_scorecard_json_is_refused(tmp_path: Path) -> None:
    """An oversize Scorecard JSON is caught by oversize_reason before reading."""

    big = tmp_path / "scorecard-result.json"
    big.write_bytes(b"{}" + b" " * (MAX_EVIDENCE_BYTES + 1))

    reason = oversize_reason(big, MAX_EVIDENCE_BYTES, label="Scorecard JSON")

    assert reason is not None
    assert "Scorecard JSON" in reason


def test_config_with_removed_report_contract_is_rejected(tmp_path: Path) -> None:
    """A config pinning a removed report_json_contract (1.0) is rejected (ADR-043)."""

    cfg = tmp_path / "oss-policy-kit.yaml"
    cfg.write_text(
        "\n".join(
            [
                "schema_version: oss-policy-kit/config/v1",
                "profile: github-level-1",
                "fail_on: fail",
                'output_dir: "./oss-policy-reports"',
                'report_json_contract: "1.0"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(InvalidInputError) as excinfo:
        load_project_config(cfg)

    assert "report_json_contract must be '2.0'" in str(excinfo.value)


def test_config_with_2_0_report_contract_is_accepted(tmp_path: Path) -> None:
    """The canonical reports/2.0 contract still loads cleanly."""

    cfg = tmp_path / "oss-policy-kit.yaml"
    cfg.write_text(
        "\n".join(
            [
                "schema_version: oss-policy-kit/config/v1",
                "profile: github-level-1",
                "fail_on: fail",
                'output_dir: "./oss-policy-reports"',
                'report_json_contract: "2.0"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = load_project_config(cfg)

    assert result.report_json_contract == "2.0"
