"""How the Pulumi / CloudFormation / Bicep controls read their scanner evidence.

These three families are built from the same factory, so they share one failure surface: a
missing evidence file, a corrupt one, one written by a different contract version, one whose
scan timed out, one that scanned nothing, and finally the clean and dirty verdicts. Only the
missing-file case had a test, which meant the kit could have silently mis-read its own
scanner output for three of its IaC families.

The distinction that matters here is *inconclusive* versus *clean*. A timed-out or truncated
scan must never read as a pass -- a control that says "no findings" because the scanner died
is worse than one that admits it does not know. Each case below asserts the status and that
the reason says why, so a future refactor cannot quietly collapse them into one another.

"No files scanned" is deliberately ``not-applicable`` rather than a pass: a repository with
no Pulumi programs has nothing to get right, and counting it as a pass would inflate the
score of every repository that does not use the technology.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from oss_policy_kit.application import (
    evaluators_iac_bicep as bicep,
)
from oss_policy_kit.application import (
    evaluators_iac_cfn as cfn,
)
from oss_policy_kit.application import (
    evaluators_iac_pulumi as pulumi,
)
from oss_policy_kit.domain.models import ControlStatus


class _Family:
    def __init__(self, name: str, module: Any, builder: Any, filename: str, prefix: str) -> None:
        self.name = name
        self.module = module
        self.builder = builder
        self.filename = filename
        self.prefix = prefix

    def __repr__(self) -> str:  # keeps pytest ids readable
        return self.name


_FAMILIES = [
    _Family("pulumi", pulumi, pulumi.build_iac_pulumi_evaluators, "iac-pulumi.json", pulumi._SCHEMA_PREFIX),
    _Family("cfn", cfn, cfn.build_iac_cfn_evaluators, "iac-cfn.json", cfn._SCHEMA_PREFIX),
    _Family("bicep", bicep, bicep.build_iac_bicep_evaluators, "iac-bicep.json", bicep._SCHEMA_PREFIX),
]


def _write(root: Path, family: _Family, payload: Any) -> None:
    d = root / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (d / family.filename).write_text(text, encoding="utf-8")


def _first_rule(family: _Family) -> tuple[str, Any]:
    """The first (rule_id, evaluator) the family exposes; they all share the factory."""

    evaluators = family.builder()
    rule_id = sorted(evaluators)[0]
    return rule_id, evaluators[rule_id]


def _ctx(root: Path) -> Any:
    return SimpleNamespace(repo_root=root)


def _evidence(family: _Family, *, status: str = "ok", files: list[str] | None = None, **extra: Any) -> dict:
    payload: dict[str, Any] = {
        "schema_version": family.prefix + "v1",
        "status": status,
        "files_scanned": ["infra/main.tf"] if files is None else files,
    }
    payload.update(extra)
    return payload


@pytest.mark.parametrize("family", _FAMILIES, ids=repr)
def test_missing_evidence_asks_for_a_scan_instead_of_guessing(family: _Family, tmp_path: Path) -> None:
    rule_id, evaluate = _first_rule(family)
    outcome = evaluate(_ctx(tmp_path))
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED, rule_id
    assert "evidence" in (outcome.reason or "").lower()


@pytest.mark.parametrize("family", _FAMILIES, ids=repr)
def test_unparseable_evidence_is_reported_not_raised(family: _Family, tmp_path: Path) -> None:
    """A truncated or hand-edited evidence file must not take the whole run down."""

    _write(tmp_path, family, '{"schema_version": "oss-policy')
    _, evaluate = _first_rule(family)
    outcome = evaluate(_ctx(tmp_path))
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "parse" in (outcome.reason or "").lower()


@pytest.mark.parametrize("family", _FAMILIES, ids=repr)
def test_evidence_from_a_different_contract_is_refused(family: _Family, tmp_path: Path) -> None:
    """Reading a foreign schema as if it were ours is how silently-wrong results happen."""

    _write(tmp_path, family, {"schema_version": "some-other-tool/v9", "status": "ok"})
    _, evaluate = _first_rule(family)
    outcome = evaluate(_ctx(tmp_path))
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "schema_version" in (outcome.reason or "")


@pytest.mark.parametrize("family", _FAMILIES, ids=repr)
@pytest.mark.parametrize("bad_status", ["timeout", "error"])
def test_an_inconclusive_scan_never_reads_as_clean(family: _Family, bad_status: str, tmp_path: Path) -> None:
    """The scanner did not finish, so the control must say so rather than pass."""

    _write(tmp_path, family, _evidence(family, status=bad_status, findings_by_rule={}))
    _, evaluate = _first_rule(family)
    outcome = evaluate(_ctx(tmp_path))
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert outcome.status is not ControlStatus.PASS
    assert bad_status in (outcome.reason or "")


@pytest.mark.parametrize("family", _FAMILIES, ids=repr)
def test_nothing_to_scan_is_not_applicable_rather_than_a_free_pass(family: _Family, tmp_path: Path) -> None:
    """A repo that does not use the technology must not collect credit for it."""

    _write(tmp_path, family, _evidence(family, files=[], findings_by_rule={}))
    _, evaluate = _first_rule(family)
    outcome = evaluate(_ctx(tmp_path))
    assert outcome.status is ControlStatus.NOT_APPLICABLE


@pytest.mark.parametrize("family", _FAMILIES, ids=repr)
def test_a_completed_scan_with_no_findings_passes(family: _Family, tmp_path: Path) -> None:
    rule_id, evaluate = _first_rule(family)
    _write(tmp_path, family, _evidence(family, findings_by_rule={rule_id: 0}))
    outcome = evaluate(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS


@pytest.mark.parametrize("family", _FAMILIES, ids=repr)
def test_findings_fail_the_control_and_name_the_files(family: _Family, tmp_path: Path) -> None:
    """The reason has to carry the offending file, or the fix has nowhere to start."""

    rule_id, evaluate = _first_rule(family)
    _write(
        tmp_path,
        family,
        _evidence(
            family,
            findings_by_rule={rule_id: 2},
            findings=[
                {"rule_id": rule_id, "file": "infra/bad.tpl"},
                {"rule_id": rule_id, "file": "infra/worse.tpl"},
            ],
        ),
    )
    outcome = evaluate(_ctx(tmp_path))
    assert outcome.status is ControlStatus.FAIL
    assert "infra/bad.tpl" in (outcome.reason or "")


@pytest.mark.parametrize("family", _FAMILIES, ids=repr)
def test_findings_without_file_attribution_still_fail(family: _Family, tmp_path: Path) -> None:
    """Counted findings with no `file` key: still a failure, just without the hint."""

    rule_id, evaluate = _first_rule(family)
    _write(tmp_path, family, _evidence(family, findings_by_rule={rule_id: 1}, findings=[]))
    outcome = evaluate(_ctx(tmp_path))
    assert outcome.status is ControlStatus.FAIL
    assert "Sources:" not in (outcome.reason or "")
