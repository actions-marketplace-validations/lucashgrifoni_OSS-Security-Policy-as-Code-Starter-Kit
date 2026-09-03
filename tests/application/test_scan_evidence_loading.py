"""Loading scanner evidence: four ways to refuse, and why none of them is a failing control.

The Kubernetes and Terraform evaluators each open a file `scan-k8s` / `scan-iac` wrote, and both
run the same four checks: is it there, does it parse, is it the contract this build understands,
and did the scan actually finish. Two copies of one gate, so both are asserted together.

Every refusal is `manual-review-required`, never `fail`, and that distinction is the point. A
missing or unreadable evidence file says nothing about the cluster or the infrastructure -- it
says the kit does not know. Reporting `fail` would put a red control in front of an adopter for
a problem that lives in their scan step, and reporting `pass` would be worse. The status check
exists for the same reason: a scan that timed out returns a well-formed file full of zero
findings, which is indistinguishable from a clean estate unless somebody reads `status`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

import pytest

from oss_policy_kit.application import evaluators_iac, evaluators_k8s
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome


class _Loader(Protocol):
    def __call__(self, repo_root: Path) -> tuple[dict[str, Any] | None, EvalOutcome | None]: ...


_MODULES = [
    ("k8s", evaluators_k8s, "k8s-baseline.json", "oss-policy-kit/evidence/k8s-baseline/1.0", "scan-k8s"),
    ("iac", evaluators_iac, "iac-terraform.json", "oss-policy-kit/evidence/iac-terraform/1.0", "scan-iac"),
]
_IDS = [name for name, *_rest in _MODULES]


def _write(root: Path, name: str, body: str) -> None:
    path = root / ".oss-policy-kit" / "evidence" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _load(module: Any, root: Path) -> tuple[dict[str, Any] | None, EvalOutcome | None]:
    loader: _Loader = module._load_evidence
    return loader(root)


@pytest.mark.parametrize(("label", "module", "filename", "schema", "command"), _MODULES, ids=_IDS)
def test_evidence_that_was_never_produced_asks_for_a_scan(
    label: str, module: Any, filename: str, schema: str, command: str, tmp_path: Path
) -> None:
    """Not knowing is not the same as failing, and the message names the command to run."""

    data, outcome = _load(module, tmp_path)

    assert data is None
    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert command in outcome.remediation


@pytest.mark.parametrize(("label", "module", "filename", "schema", "command"), _MODULES, ids=_IDS)
def test_evidence_that_will_not_parse_is_inconclusive(
    label: str, module: Any, filename: str, schema: str, command: str, tmp_path: Path
) -> None:
    _write(tmp_path, filename, "{ this is not json")
    data, outcome = _load(module, tmp_path)

    assert data is None
    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "Could not parse" in outcome.reason


@pytest.mark.parametrize(("label", "module", "filename", "schema", "command"), _MODULES, ids=_IDS)
def test_evidence_from_another_contract_is_refused_by_name(
    label: str, module: Any, filename: str, schema: str, command: str, tmp_path: Path
) -> None:
    """An adopter with a stale file needs to see which version they have and which is expected."""

    _write(tmp_path, filename, json.dumps({"schema_version": "some-other-tool/0.1", "status": "ok"}))
    data, outcome = _load(module, tmp_path)

    assert data is None
    assert outcome is not None
    assert "some-other-tool/0.1" in outcome.reason
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED


@pytest.mark.parametrize(("label", "module", "filename", "schema", "command"), _MODULES, ids=_IDS)
@pytest.mark.parametrize("status", ["timeout", "error", "TIMEOUT"])
def test_a_scan_that_did_not_finish_is_never_read_as_a_clean_estate(
    status: str, label: str, module: Any, filename: str, schema: str, command: str, tmp_path: Path
) -> None:
    """The file is well formed and holds zero findings; only `status` says why."""

    _write(tmp_path, filename, json.dumps({"schema_version": schema, "status": status, "findings": []}))
    data, outcome = _load(module, tmp_path)

    assert data is None
    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "inconclusive" in outcome.reason


@pytest.mark.parametrize(("label", "module", "filename", "schema", "command"), _MODULES, ids=_IDS)
def test_a_completed_scan_is_handed_back_for_the_rules_to_read(
    label: str, module: Any, filename: str, schema: str, command: str, tmp_path: Path
) -> None:
    """The counterpart: a gate that refused everything would leave every rule unevaluated."""

    _write(tmp_path, filename, json.dumps({"schema_version": schema, "status": "ok", "findings": []}))
    data, outcome = _load(module, tmp_path)

    assert outcome is None
    assert data is not None
    assert data["status"] == "ok"
