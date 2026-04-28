"""End-to-end snapshot of Azure/AWS profiles against ``examples/hardened-repo``.

These tests pin the observable evaluation shape of the bundled hardened fixture so maintainers
notice when a change silently shifts status counts or the mix of ``pass`` vs ``self-attested``.
They deliberately do **not** assert on exact counts so adding a new control does not break the
snapshot; they assert the invariants the docs and profile specs promise (no ``fail``, no
``manual-review-required``, and that strict tiers keep at least one ``self-attested`` row because
the fixture is synthetic and cannot be API-attested).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ExecutionReport


def _evaluate(repo: Path, profile_id: str) -> ExecutionReport:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    return evaluate_repository(
        repo_root=repo,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )


def _status_counts(report: ExecutionReport) -> Counter[str]:
    return Counter(r.status.value for r in report.results)


def test_aws_level_1_all_pass_on_hardened_repo() -> None:
    """``aws-level-1`` is the advertised daily baseline and must stay fully green on the fixture."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "aws-level-1"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 1
    # The fixture is deliberately designed to keep level-1 free of synthetic self-attested rows.
    assert counts.get("self-attested", 0) == 0


def test_azure_level_1_all_pass_on_hardened_repo() -> None:
    """``azure-level-1`` is the advertised daily baseline and must stay fully green on the fixture."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "azure-level-1"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 1
    assert counts.get("self-attested", 0) == 0


def test_aws_release_hardening_3_reaches_zero_fail_but_keeps_self_attested() -> None:
    """Strict tier: ``fail == 0`` is achievable on the synthetic fixture, but artifact/governance rows
    must stay ``self-attested`` because the fixture never runs ``collect-evidence``.

    If this invariant flips to all-pass, either the fixture silently received live evidence files
    (scope expansion) or the evaluator relaxed its hard-gate. Either case deserves review.
    """

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "aws-release-hardening-3"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 1
    assert counts.get("self-attested", 0) >= 1, "Synthetic fixture must not claim live-attested posture"


def test_azure_release_hardening_3_reaches_zero_fail_but_keeps_self_attested() -> None:
    """Same invariant as the AWS counterpart; guards against silent relaxation of azure-release-hardening-3."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "azure-release-hardening-3"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 1
    assert counts.get("self-attested", 0) >= 1, "Synthetic fixture must not claim live-attested posture"


def test_aws_level_3_hard_gate_keeps_at_least_one_self_attested_row() -> None:
    """``aws-level-3`` is the hard-gate tier — synthetic fixtures must not reach all-pass here."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "aws-level-3"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts.get("self-attested", 0) >= 1


def test_azure_level_3_hard_gate_keeps_at_least_one_self_attested_row() -> None:
    """``azure-level-3`` is the hard-gate tier — synthetic fixtures must not reach all-pass here."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "azure-level-3"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts.get("self-attested", 0) >= 1
