"""Docs/help-drift regression guards for the v10.0.1 hotfix (F6-docs).

These are lightweight string-presence checks over the committed docs so the
v10.0.1 doc corrections cannot silently regress:

- X8-2: ``findings-correlation.md`` re-runs claim is qualified (deterministic in
  content, byte-identical only when ``SOURCE_DATE_EPOCH`` is pinned).
- X8-4: ``cli-reference.md`` evaluate row lists ``--with-findings-summary``, and the
  correlate-findings row lists ``--waivers`` / ``--enrichment-file`` plus a
  path-resolution base note.
- X8-3 (doc side): ``cli-reference.md`` export-evidence row mentions ``--target``
  and ``--output`` (F3 adds the ``-t`` / ``-o`` aliases in code; the row is correct).
- ``reports-contract-v2.0.md`` documents the real ``extensions.findings_summary``
  embed keys, including the source-read tally.
- ``v10.0.0-migration-guide.md`` states export-evidence hard-rejects pre-2.0 reports.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_DOCS = Path(__file__).resolve().parents[2] / "docs"


def _read(name: str) -> str:
    return (_DOCS / name).read_text(encoding="utf-8")


# --- X8-2: findings-correlation re-run determinism claim is qualified -----------


def test_findings_correlation_reruns_claim_is_qualified() -> None:
    text = _read("findings-correlation.md")
    # The corrected wording distinguishes content-determinism from byte-identity.
    assert "deterministic in content" in text
    assert "SOURCE_DATE_EPOCH" in text
    assert "byte-identical" in text
    assert "generated_at" in text


def test_findings_correlation_drops_unqualified_bit_identical_claim() -> None:
    text = _read("findings-correlation.md")
    # The old unqualified "Re-runs ... are bit-identical." must not come back.
    assert "bit-identical" not in text


# --- X8-4: cli-reference evaluate + correlate-findings rows ----------------------


def test_cli_reference_evaluate_row_lists_with_findings_summary() -> None:
    text = _read("cli-reference.md")
    # Present on the evaluate row (the row is the line containing "| `evaluate` |").
    evaluate_row = next(line for line in text.splitlines() if line.startswith("| `evaluate` |"))
    assert "--with-findings-summary" in evaluate_row


def test_cli_reference_correlate_findings_row_lists_waivers_and_enrichment() -> None:
    text = _read("cli-reference.md")
    row = next(line for line in text.splitlines() if line.startswith("| `correlate-findings` |"))
    assert "--waivers" in row
    assert "--enrichment-file" in row
    # Resolution base note: waivers resolve against --target, enrichment against cwd.
    assert "resolves against `--target`" in row
    assert "current directory" in row


# --- X8-3 (doc side): export-evidence row mentions --target and --output ---------


def test_cli_reference_export_evidence_row_mentions_target_and_output() -> None:
    text = _read("cli-reference.md")
    row = next(line for line in text.splitlines() if line.startswith("| `export-evidence` |"))
    assert "--target" in row
    assert "--output" in row


# --- reports-contract-v2.0: findings_summary embed keys are documented -----------


@pytest.mark.parametrize(
    "key",
    [
        "findings_total",
        "correlated_groups",
        "by_severity",
        "kev_count",
        "high_epss_count",
        "artifact",
        "findings_digest",
        # F2's source-read tally.
        "sources_ok",
        "sources_total",
    ],
)
def test_reports_contract_documents_findings_summary_key(key: str) -> None:
    text = _read("reports-contract-v2.0.md")
    assert key in text, f"reports-contract-v2.0.md must document the findings_summary key {key!r}"


def test_reports_contract_findings_summary_stays_honest() -> None:
    text = _read("reports-contract-v2.0.md")
    # The additive/no-control-change honesty contract must stay stated.
    assert "in-process" in text
    assert "changes no control state" in text
    assert "source-derived" in text


# --- migration guide: export-evidence hard-rejects pre-2.0 reports ---------------


def test_migration_guide_states_export_evidence_hard_rejects_pre_2_0() -> None:
    text = _read("v10.0.0-migration-guide.md")
    assert "hard-reject" in text
    assert "export-evidence" in text
    # A pointer to the fix / remedy (convert first) is present.
    assert "reports/2.0" in text
