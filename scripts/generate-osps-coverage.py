#!/usr/bin/env python3
"""Regenerate docs/osps-baseline-2026-coverage.md from the OSPS coverage map.

The page is a single-source-of-truth, **advisory** view of how the bundled
``osps-baseline-2026-1`` controls map to the OpenSSF OSPS Baseline v2026.02.19
criteria, with honest per-level (L1/L2/L3) coverage and the real gaps.

The authoritative source is
``src/oss_policy_kit/data/frameworks/osps-baseline-2026.yaml`` (criteria +
control->criterion mappings). Per-control assurance is read live from the
control catalog, never duplicated. Run this whenever the OSPS map, the catalog,
or the profile changes::

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

import yaml

from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOC_PATH = _REPO_ROOT / "docs" / "osps-baseline-2026-coverage.md"
_LEVELS = (1, 2, 3)


def _load_map(root: Path) -> dict:
    path = root / "frameworks" / "osps-baseline-2026.yaml"
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _validate(data: dict, catalog: dict, profile_control_ids: set[str]) -> None:
    """Fail loudly on an inconsistent map (doubles as a data-integrity gate)."""
    criteria_ids = {c["id"] for c in data["criteria"]}
    if len(criteria_ids) != len(data["criteria"]):
        raise ValueError("Duplicate OSPS criterion id in osps-baseline-2026.yaml")
    seen_controls: set[str] = set()
    for entry in data["mappings"]:
        control = entry["control"]
        if control in seen_controls:
            raise ValueError(f"Duplicate mapping for control {control}")
        seen_controls.add(control)
        if control not in catalog:
            raise ValueError(f"Mapping control {control} is not in the control catalog")
        if control not in profile_control_ids:
            raise ValueError(f"Mapping control {control} is not in the osps-baseline-2026-1 profile")
        for crit in entry["criteria"]:
            if crit not in criteria_ids:
                raise ValueError(f"Mapping for {control} references unknown criterion {crit}")
    for entry in data.get("aggregate_controls", []):
        control = entry["control"]
        if control not in catalog:
            raise ValueError(f"Aggregate control {control} is not in the control catalog")


def _criteria_to_controls(data: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {c["id"]: [] for c in data["criteria"]}
    for entry in data["mappings"]:
        for crit in entry["criteria"]:
            out[crit].append(entry["control"])
    return out


def _build() -> str:
    root = bundled_kit_root()
    data = _load_map(root)
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, data["profile"])
    profile_control_ids = set(profile.control_ids)
    _validate(data, catalog, profile_control_ids)

    criteria = data["criteria"]
    crit_controls = _criteria_to_controls(data)
    touched = {cid for cid, controls in crit_controls.items() if controls}

    def in_level(crit: dict, level: int) -> bool:
        return level in crit["levels"]

    lines: list[str] = []
    lines.append("# OSPS Baseline v2026.02.19 coverage (advisory)")
    lines.append("")
    lines.append(f"> **{data['disclaimer'].strip()}**")
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
        f"- **OSPS Baseline snapshot:** `{data['version']}` "
        f"([{data['source_tag']}]({data['source']}/releases/tag/{data['source_tag']}))"
    )
    lines.append(f"- **Aligned kit profile:** `{data['profile']}`")
    lines.append(f"- **Criteria in snapshot:** {len(criteria)} across 8 families (AC, BR, DO, GV, LE, QA, SA, VM)")
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
    for level in _LEVELS:
        in_lvl = [c for c in criteria if in_level(c, level)]
        n_total = len(in_lvl)
        n_touched = sum(1 for c in in_lvl if c["id"] in touched)
        lines.append(f"| L{level} | {n_total} | {n_touched} | {n_total - n_touched} |")
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
    for crit in criteria:
        cid = crit["id"]
        levels = ", ".join(str(level) for level in crit["levels"])
        controls = crit_controls[cid]
        if controls:
            rendered = ", ".join(f"`{c}` ({catalog[c].assurance})" for c in controls if c in catalog)
        else:
            rendered = "_-- not expressed_"
        lines.append(f"| `{cid}` | {levels} | {crit['objective']} | {rendered} |")
    lines.append("")
    lines.append("## Honest gaps")
    lines.append("")
    gaps = [c for c in criteria if c["id"] not in touched]
    lines.append(
        f"{len(gaps)} of {len(criteria)} criteria have no clone-visible kit signal. These are real and "
        "intentional: the kit does not assess them from a clone (e.g. user-documentation quality, "
        "threat modeling, encrypted dev channels, contributor vetting). They are listed so adopters "
        "know what the kit does **not** cover."
    )
    lines.append("")
    families: dict[str, list[str]] = {}
    for crit in gaps:
        families.setdefault(crit["family"], []).append(crit["id"])
    lines.append("| Family | Uncovered criteria |")
    lines.append("|---|---|")
    for family in sorted(families):
        joined = ", ".join(f"`{cid}`" for cid in families[family])
        lines.append(f"| {family} | {joined} |")
    lines.append("")
    lines.append("## Aggregate conformance signal")
    lines.append("")
    for entry in data.get("aggregate_controls", []):
        lines.append(f"- `{entry['control']}` — {entry['note']}")
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
