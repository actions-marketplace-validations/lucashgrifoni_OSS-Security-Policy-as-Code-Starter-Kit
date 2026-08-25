"""Which scanner a finding is credited to must not depend on run order.

A SARIF document holds a LIST of runs and each one names its own driver. The module's
contract is that "attribution follows the document, not the filename" -- but the foreign
driver was latched once, at document level, and then used to label every later run.

Measured on one drop holding an osv-scanner run and a Trivy run, the same two findings
both times, differing only in the order the runs appear:

    own run first     CVE-2026-33333 -> osv-scanner    CVE-2026-44444 -> Trivy
    foreign run first CVE-2026-33333 -> Trivy          CVE-2026-44444 -> Trivy

In the second document the artifact says Trivy found something osv-scanner produced. It
follows neither the document nor the filename -- it follows whichever run happened to be
written first.

The same latch moved `cross_tool_merges`, a published summary number: with both runs
credited to one tool, a genuine two-tool corroboration counted as zero.

The document-level flag stays: any foreign run still means the file is not what its name
claims, so the source record is still demoted and still states no version. That is
asserted below, because relaxing it would be an easy way to make the rest pass.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.finding_correlation import correlate
from oss_policy_kit.application.finding_sarif import normalize_sarif_sources

_SARIF_DIR = Path(".oss-policy-kit") / "evidence" / "sast"

#: The drop's filename claims this scanner; a run naming another one is a mis-file.
_SLOT = "osv-scanner.sarif.json"
_SLOT_TOOL = "osv-scanner"


def _run(driver: str, rule: str, purl: str, *, version: str = "9.9.9") -> dict[str, Any]:
    return {
        "tool": {"driver": {"name": driver, "version": version}},
        "results": [
            {
                "ruleId": rule,
                "level": "error",
                "message": {"text": f"{rule} affects {purl}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}}}],
                "properties": {"purl": purl},
            }
        ],
    }


def _drop(repo: Path, runs: list[dict[str, Any]], *, filename: str = _SLOT) -> Path:
    directory = repo / _SARIF_DIR
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(json.dumps({"version": "2.1.0", "runs": runs}), encoding="utf-8")
    return repo


def _attribution(repo: Path) -> dict[str, list[str]]:
    findings, _records = normalize_sarif_sources(repo)
    return {f.rule: sorted({s.tool for s in f.sources}) for f in findings}


_OWN = _run(_SLOT_TOOL, "CVE-2026-33333", "pkg:npm/lodash@4.17.20")
_FOREIGN = _run("Trivy", "CVE-2026-44444", "pkg:npm/express@4.18.0")

_EXPECTED = {"CVE-2026-33333": [_SLOT_TOOL], "CVE-2026-44444": ["Trivy"]}


def test_each_run_is_credited_to_the_driver_it_names(tmp_path: Path) -> None:
    assert _attribution(_drop(tmp_path, [_OWN, _FOREIGN])) == _EXPECTED


def test_the_answer_does_not_change_when_the_foreign_run_comes_first(tmp_path: Path) -> None:
    """The reproduction. Same two runs, reversed, and the credit used to move."""

    assert _attribution(_drop(tmp_path, [_FOREIGN, _OWN])) == _EXPECTED, (
        "putting the foreign run first re-credited the other run's findings to it. The "
        "artifact then names a scanner that did not produce them."
    )


def test_a_two_tool_corroboration_counts_the_same_in_either_order(tmp_path: Path) -> None:
    """`cross_tool_merges` is published; it must describe the document, not its ordering."""

    advisory, purl = "CVE-2026-55555", "pkg:npm/axios@1.0.0"
    own = _run(_SLOT_TOOL, advisory, purl)
    foreign = _run("Trivy", advisory, purl)

    counts = []
    for order in ([own, foreign], [foreign, own]):
        findings, _records = normalize_sarif_sources(_drop(tmp_path, order))
        result = correlate(findings)
        assert len(result.findings) == 1
        assert {s.tool for s in result.findings[0].sources} == {_SLOT_TOOL, "Trivy"}
        counts.append(result.cross_tool_merges)

    assert counts == [1, 1], (
        f"the same corroboration counted {counts} depending on run order. With both runs "
        "credited to one tool it is not a cross-tool merge any more."
    )


@pytest.mark.parametrize("order", [[_OWN, _FOREIGN], [_FOREIGN, _OWN]], ids=["foreign-last", "foreign-first"])
def test_a_mixed_document_is_still_demoted_and_still_states_no_version(
    order: list[dict[str, Any]], tmp_path: Path
) -> None:
    """The honesty flag is document-level on purpose and stays that way.

    One foreign run means the file is not what its name claims, whatever else it holds,
    and wherever in the document it sits. Crediting each run correctly does not make the
    drop trustworthy.

    Both orders, because a flag that tracked the LAST run instead of the first would
    answer "ok" for a mis-filed document whose native run happens to come last.
    """

    _drop(tmp_path, order)
    _findings, records = normalize_sarif_sources(tmp_path)
    record = next(r for r in records if r.path.endswith(_SLOT))

    assert record.status == "error", f"a drop holding a foreign run reported status {record.status!r}"
    assert record.tool_version is None, (
        f"the record states version {record.tool_version!r} for {record.tool!r}. A mis-filed "
        "drop must not have a version read off it and printed beside the slot's tool name."
    )


def test_a_single_foreign_run_is_still_credited_to_the_foreign_driver(tmp_path: Path) -> None:
    """Unchanged, and the reason the latch existed at all."""

    assert _attribution(_drop(tmp_path, [_FOREIGN])) == {"CVE-2026-44444": ["Trivy"]}


def test_a_driver_the_kit_cannot_place_leaves_the_slot_authoritative(tmp_path: Path) -> None:
    """An in-house wrapper name proves nothing, so the filename convention still holds."""

    wrapper = _run("acme-internal-scan-wrapper", "CVE-2026-66666", "pkg:npm/left-pad@1.0.0")

    assert _attribution(_drop(tmp_path, [wrapper])) == {"CVE-2026-66666": [_SLOT_TOOL]}

    _findings, records = normalize_sarif_sources(tmp_path)
    record = next(r for r in records if r.path.endswith(_SLOT))
    assert record.status == "ok", "an unrecognized driver name is not proof of a mis-file"
