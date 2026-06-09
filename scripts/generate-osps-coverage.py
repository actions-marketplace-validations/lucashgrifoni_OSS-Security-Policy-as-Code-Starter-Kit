#!/usr/bin/env python3
"""Regenerate docs/osps-baseline-2026-coverage.md from the OSPS coverage map.

The page is a single-source-of-truth, **advisory** view of how the bundled
``osps-baseline-2026-1`` controls map to the OpenSSF OSPS Baseline v2026.02.19
criteria, with honest per-level (L1/L2/L3) coverage and the real gaps.

The load + validate + compute logic lives in
:mod:`oss_policy_kit.application.osps_coverage` (the single source of truth,
shared with the ``osps-coverage`` CLI command); this script only renders the
Markdown. Run it whenever the OSPS map, the catalog, or the profile changes::

    python scripts/generate-osps-coverage.py

It writes ``docs/osps-baseline-2026-coverage.md`` in place. Pass ``--check`` to
fail (exit 1) if the file is out of date instead of rewriting it.

This is an advisory mapping, NOT a conformance certification: each row records a
clone-visible *signal toward* an OSPS criterion, never a guarantee of an OSPS
maturity level.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from oss_policy_kit.application.osps_coverage import OspsCoverage, load_osps_coverage

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOC_PATH = _REPO_ROOT / "docs" / "osps-baseline-2026-coverage.md"


def _build(cov: OspsCoverage | None = None) -> str:
    cov = cov if cov is not None else load_osps_coverage()

    lines: list[str] = []
    lines.append("# OSPS Baseline v2026.02.19 coverage (advisory)")
    lines.append("")
    lines.append(f"> **{cov.disclaimer}**")
    lines.append("")
    lines.append(
        "Generated from "
        "[`src/oss_policy_kit/data/frameworks/osps-baseline-2026.yaml`]"
        "(../src/oss_policy_kit/data/frameworks/osps-baseline-2026.yaml) and the bundled control "
        "catalog. Per-control assurance is read live from the catalog. Regenerate with "
        "`python scripts/generate-osps-coverage.py` whenever the map, catalog, or profile changes."
    )
    lines.append("")
    lines.append(
        "> For a quick terminal view of the same data, run `oss-policy-kit osps-coverage` "
        "(`--format json` for the full machine-readable map)."
    )
    lines.append("")
    lines.append(
        f"- **OSPS Baseline snapshot:** `{cov.version}` "
        f"([{cov.source_tag}]({cov.source}/releases/tag/{cov.source_tag}))"
    )
    lines.append(f"- **Aligned kit profile:** `{cov.profile}`")
    lines.append(f"- **Criteria in snapshot:** {len(cov.criteria)} across 8 families (AC, BR, DO, GV, LE, QA, SA, VM)")
    lines.append("")
    lines.append("## Coverage by maturity level")
    lines.append("")
    lines.append(
        '"With kit signal" counts OSPS criteria for which at least one bundled control provides a '
        "clone-visible signal. It is **not** a count of satisfied criteria and **not** a conformance "
        "level — a signal is necessary context, not proof."
    )
    lines.append("")
    lines.append("| OSPS level | Criteria in level | With kit signal | Not yet expressed |")
    lines.append("|---|---:|---:|---:|")
    for lc in cov.levels:
        lines.append(f"| L{lc.level} | {lc.total} | {lc.covered} | {lc.gaps} |")
    lines.append("")
    lines.append("## Per-criterion map")
    lines.append("")
    lines.append(
        "Every OSPS Baseline v2026.02.19 criterion, in upstream order. The **Kit signal** column "
        "lists the bundled control(s) that provide a clone-visible signal toward the criterion, with "
        "each control's catalog assurance class in parentheses; `-- not expressed` marks an honest gap."
    )
    lines.append("")
    lines.append("| Criterion | Levels | Objective | Kit signal (assurance) |")
    lines.append("|---|---|---|---|")
    for crit in cov.criteria:
        levels = ", ".join(str(level) for level in crit.levels)
        if crit.signals:
            rendered = ", ".join(f"`{s.control_id}` ({s.assurance})" for s in crit.signals)
        else:
            rendered = "_-- not expressed_"
        lines.append(f"| `{crit.id}` | {levels} | {crit.objective} | {rendered} |")
    lines.append("")
    lines.append("## Honest gaps")
    lines.append("")
    gaps = cov.gap_criteria
    lines.append(
        f"{len(gaps)} of {len(cov.criteria)} criteria have no clone-visible kit signal. These are real and "
        "intentional: the kit does not assess them from a clone (e.g. user-documentation quality, "
        "threat modeling, encrypted dev channels, contributor vetting). They are listed so adopters "
        "know what the kit does **not** cover."
    )
    lines.append("")
    families: dict[str, list[str]] = {}
    for crit in gaps:
        families.setdefault(crit.family, []).append(crit.id)
    lines.append("| Family | Uncovered criteria |")
    lines.append("|---|---|")
    for family in sorted(families):
        joined = ", ".join(f"`{cid}`" for cid in families[family])
        lines.append(f"| {family} | {joined} |")
    lines.append("")
    lines.append("## Aggregate conformance signal")
    lines.append("")
    for entry in cov.aggregate_controls:
        lines.append(f"- `{entry.control_id}` — {entry.note}")
    lines.append("")
    lines.append(
        "The aggregate control consumes an external OpenSSF Scorecard v6 OSPS conformance verdict when "
        "present; it is **not** counted toward per-criterion coverage above because it asserts the "
        "upstream verdict, not a specific clone-visible criterion. A machine-readable conformance "
        "renderer matching the Scorecard v6 `--format=osps` wire shape is intentionally deferred until "
        "that format reaches GA (see ADR-018)."
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the doc is out of date.")
    args = parser.parse_args(argv)

    content = _build()
    if args.check:
        current = _DOC_PATH.read_text(encoding="utf-8") if _DOC_PATH.is_file() else ""
        if current.strip() != content.strip():
            print(f"{_DOC_PATH} is out of date; run scripts/generate-osps-coverage.py", file=sys.stderr)
            return 1
        print(f"{_DOC_PATH} is up to date.")
        return 0
    _DOC_PATH.write_text(content + "\n", encoding="utf-8")
    print(f"Wrote {_DOC_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
