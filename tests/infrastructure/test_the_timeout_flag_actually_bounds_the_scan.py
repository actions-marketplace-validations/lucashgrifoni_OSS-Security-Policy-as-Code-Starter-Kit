"""``--timeout`` has to bound the scan, not just appear in ``--help``.

All six ``scan-*`` commands advertise the flag as "Wall-clock timeout for the parser, in
seconds". Only ``scan-sast`` honored it, because it hands the number to
``subprocess.run``. The five in-process parsers took the number and dropped it on the
floor -- ``_ = timeout_seconds``, one line in each.

Measured through the CLI on one lab holding a file for each scanner, ``--timeout 0``:

    scan-sast    timeout -- findings=0            <- honest
    scan-iac     ok      -- files=1 findings=4    <- the flag was discarded
    scan-k8s     ok      -- files=1 findings=8
    scan-cfn     ok      -- files=1 findings=3
    scan-bicep   ok      -- files=1 findings=2
    scan-pulumi  ok      -- files=1 findings=1

The state was never missing from the contract. Every one of the five published evidence
schemas already lists ``"timeout"`` in its ``status`` enum, every ``IAC-*``/``K8S-*``
evaluator already answers ``manual-review-required`` when it reads one, and
``finding_normalization`` already counts it a known scanner status. Only the producer was
missing, which is why nothing downstream had to change to accept it.

Both directions are asserted. A scanner hardwired to report ``timeout`` would satisfy the
first half and destroy the tool, so the same fixtures are held to a complete scan under
the default budget.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest
from tests.conftest import ROOT

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.iac import scanner as tf_scanner
from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep_scanner
from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn_scanner
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi_scanner
from oss_policy_kit.infrastructure.k8s import scanner as k8s_scanner
from oss_policy_kit.infrastructure.scan_deadline import ScanDeadline

_SCHEMAS = ROOT / "src" / "oss_policy_kit" / "data" / "schema"


@dataclass(frozen=True)
class _Lab:
    """One scanner plus a source file it is known to find something in."""

    name: str
    module: Any
    filename: str
    source: str
    schema: str


#: A finding on the default budget is what makes the timeout assertion mean anything: a
#: fixture the scanner ignores would report ``findings=0`` either way.
LABS: tuple[_Lab, ...] = (
    _Lab(
        "scan-iac",
        tf_scanner,
        "main.tf",
        'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n',
        "evidence-iac-terraform.schema.json",
    ),
    _Lab(
        "scan-k8s",
        k8s_scanner,
        "deploy.yaml",
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n  name: demo\n"
        "spec:\n  template:\n    spec:\n      containers:\n"
        "        - name: app\n          image: nginx:latest\n"
        "          securityContext:\n            privileged: true\n",
        "evidence-k8s-baseline.schema.json",
    ),
    _Lab(
        "scan-cfn",
        cfn_scanner,
        "stack.template",
        'AWSTemplateFormatVersion: "2010-09-09"\n'
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"
        "    Properties:\n      AccessControl: PublicRead\n",
        "evidence-iac-cfn.schema.json",
    ),
    _Lab(
        "scan-pulumi",
        pulumi_scanner,
        "__main__.py",
        "import pulumi\nimport pulumi_aws as aws\n\nbucket = aws.s3.Bucket('data', acl='public-read')\n",
        "evidence-iac-pulumi.schema.json",
    ),
    _Lab(
        "scan-bicep",
        bicep_scanner,
        "infra.bicep",
        "resource sa 'Microsoft.Storage/storageAccounts@2021-04-01' = {\n"
        "  name: 'demo'\n  location: 'eastus'\n"
        "  properties: {\n    supportsHttpsTrafficOnly: false\n  }\n}\n",
        "evidence-iac-bicep.schema.json",
    ),
)

_IDS = [lab.name for lab in LABS]


def _plant(lab: _Lab, tmp_path: Path) -> Path:
    (tmp_path / lab.filename).write_text(lab.source, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("lab", LABS, ids=_IDS)
def test_the_default_budget_still_completes_the_scan(lab: _Lab, tmp_path: Path) -> None:
    """The other half. A deadline checked in the wrong place stops a scan that had time."""

    outcome = lab.module.run_scan(_plant(lab, tmp_path))

    assert outcome.status == "ok", (
        f"{lab.name} reported {outcome.status!r} on the default {lab.module.DEFAULT_TIMEOUT_SECONDS}s budget"
    )
    assert outcome.findings, (
        f"{lab.name} found nothing in a fixture written to trip it. The timeout assertion "
        "below would then hold over a scanner that never reports anything."
    )


@pytest.mark.parametrize("lab", LABS, ids=_IDS)
def test_a_spent_budget_is_reported_as_timeout(lab: _Lab, tmp_path: Path) -> None:
    outcome = lab.module.run_scan(_plant(lab, tmp_path), timeout_seconds=0)

    assert outcome.status == "timeout", (
        f"{lab.name} reported {outcome.status!r} with no budget to spend. `--timeout 0` is "
        "the answer `scan-sast` has always given; five commands advertised the flag and "
        "discarded it."
    )
    assert outcome.findings == [], (
        "a scan that did not finish reported findings. Partial results carry per-rule "
        "counts of zero for rules that never ran, which reads as 'this rule found nothing'."
    )


@pytest.mark.parametrize("lab", LABS, ids=_IDS)
def test_the_timeout_evidence_is_valid_against_the_published_schema(lab: _Lab, tmp_path: Path) -> None:
    """The status is not a new state -- it is one the contract already declared."""

    repo = _plant(lab, tmp_path)
    payload = lab.module.render_evidence_payload(lab.module.run_scan(repo, timeout_seconds=0), target=repo)
    schema = json.loads((_SCHEMAS / lab.schema).read_text(encoding="utf-8"))

    assert "timeout" in schema["properties"]["status"]["enum"], (
        f"{lab.schema} no longer publishes 'timeout' as a status. The producer and the contract have to move together."
    )
    jsonschema.validate(payload, schema)
    assert payload["findings_total"] == 0


def test_an_empty_tree_with_no_budget_is_a_timeout_not_a_clean_bill(tmp_path: Path) -> None:
    """``scan-iac`` returns early when it finds no ``.tf``; that return skipped the check.

    "This repository has no Terraform" is a positive claim, and a scan with no budget is
    not in a position to make it. The other four reach the timeout return through an empty
    rule pass, so this branch is the only one that needed its own guard.
    """

    assert tf_scanner.run_scan(tmp_path, timeout_seconds=0).status == "timeout"
    assert tf_scanner.run_scan(tmp_path).status == "ok"


def test_a_timed_out_scan_is_manual_review_required_not_a_pass(tmp_path: Path) -> None:
    """The produced state has to reach a verdict, or emitting it changed nothing."""

    lab = LABS[0]
    repo = _plant(lab, tmp_path)
    payload = lab.module.render_evidence_payload(lab.module.run_scan(repo, timeout_seconds=0), target=repo)
    lab.module.write_evidence(payload, repo_root=repo, filename=lab.module.EVIDENCE_FILENAME)

    evaluator: Callable[[Any], Any] = EVALUATOR_REGISTRY["IAC-TF-001"]
    outcome = evaluator(SimpleNamespace(repo_root=repo))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED, (
        f"a control read timed-out evidence and answered {outcome.status}. A scan that did "
        "not run establishes nothing, so any other verdict is a claim the kit cannot make."
    )


class _TickingClock:
    """A clock that advances exactly one second per reading.

    A real budget small enough to expire mid-scan expires at a different point on every
    machine, which is a flaky test. Counting readings instead makes the moment exact.
    """

    def __init__(self) -> None:
        self.reads = 0

    def __call__(self) -> float:
        self.reads += 1
        return float(self.reads - 1)


#: With one source file each, all five scanners read the clock in the same order:
#: construction, the parse loop, the guard in front of the rule pass, the first rule, and
#: the check that decides the outcome. A three-second budget therefore runs out on the
#: first rule -- inside the loop, which is the branch this reaches and no other test does.
_READS_PER_RUN = 5
_BUDGET_THAT_EXPIRES_ON_THE_FIRST_RULE = 3


@pytest.mark.parametrize("lab", LABS, ids=_IDS)
def test_a_budget_that_runs_out_between_rules_stops_the_rule_pass(
    lab: _Lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Running out while the rules are running, not before they start.

    The parse phase is where a slow repository spends its time, but a rule pack is not
    free either -- this project already holds one scanner to a quadratic-work bound. So
    the budget is checked between rules too, and this is the case that exercises it.
    """

    clock = _TickingClock()
    monkeypatch.setattr("oss_policy_kit.infrastructure.scan_deadline.monotonic", clock)

    outcome = lab.module.run_scan(_plant(lab, tmp_path), timeout_seconds=_BUDGET_THAT_EXPIRES_ON_THE_FIRST_RULE)

    assert outcome.status == "timeout"
    assert outcome.findings == []
    assert clock.reads == _READS_PER_RUN, (
        f"{lab.name} read the clock {clock.reads} times, not {_READS_PER_RUN}. The budget "
        "above is sized so it runs out on the first rule; a different count means it now "
        "runs out somewhere else and this test no longer covers the rule pass."
    )


def test_a_budget_of_nothing_is_spent_on_arrival() -> None:
    """The boundary the five scanners are measured at, held at the unit."""

    assert ScanDeadline(0).expired() is True, (
        "a zero-second budget did not expire. On Windows `monotonic()` resolves to about "
        "15ms, so the two readings can be the same float -- which is why the comparison is "
        "`>=` and not `>`."
    )
    assert ScanDeadline(-1).expired() is True, "a negative budget is spent too, as `scan-sast` treats it"

    generous = ScanDeadline(3600)
    assert generous.expired() is False
    assert generous.expired() is False, "re-checking a live budget must not consume it"
