#!/usr/bin/env python
"""ADR-028 control-impact analysis (v8.x adoption aid).

For a given target repository, evaluate every bundled profile twice — once with
the opt-in applicability engine and `--enable-attested` OFF (today's default), and
once ON — and report the per-control status deltas.

This is the "diff of affected controls" the ADR-028 rollout requires: it shows
exactly what would change if a profile adopted the opt-ins, so the eventual
v8.0.0 default flip is defensible. On a target with no Dockerfile and no verified
provenance evidence the delta is zero.

Usage:
    python scripts/v8-applicability-impact.py --target .
    python scripts/v8-applicability-impact.py --target ./repo --fail-on-drift
    python scripts/v8-applicability-impact.py --target . --profile github-level-3

Exit codes:
    0  Analysis complete (and, with --fail-on-drift, no control changed).
    1  --fail-on-drift set and at least one control changed status.
    2  Usage / IO error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from oss_policy_kit.application.engine import evaluate_repository  # noqa: E402
from oss_policy_kit.application.loader import (  # noqa: E402
    LoadError,
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)


def _profile_ids(kit_root: Path) -> list[str]:
    profiles_dir = kit_root / "profiles"
    return sorted(p.parent.name for p in profiles_dir.glob("*/profile.yaml"))


def _statuses(repo: Path, profile_id: str, kit_root: Path, catalog: dict, *, engine: bool) -> dict[str, str]:
    profile = load_profile_by_id(kit_root, profile_id)
    report = evaluate_repository(
        repo_root=repo,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        applicability_engine=engine,
        enable_attested=engine,
    )
    return {r.control_id: r.status.value for r in report.results}


def _diff_profile(repo: Path, profile_id: str, kit_root: Path, catalog: dict) -> list[tuple[str, str, str]]:
    off = _statuses(repo, profile_id, kit_root, catalog, engine=False)
    on = _statuses(repo, profile_id, kit_root, catalog, engine=True)
    return [(cid, off[cid], on[cid]) for cid in off if off[cid] != on.get(cid)]


def main() -> int:
    ap = argparse.ArgumentParser(description="ADR-028 control-impact analysis across bundled profiles.")
    ap.add_argument("--target", required=True, help="Path to the repository to analyse.")
    ap.add_argument("--profile", default=None, help="Limit to one profile id (default: all bundled profiles).")
    ap.add_argument("--fail-on-drift", action="store_true", help="Exit 1 if any control changes status.")
    args = ap.parse_args()

    repo = Path(args.target).resolve()
    if not repo.is_dir():
        sys.stderr.write(f"--target is not a directory: {repo}\n")
        return 2

    kit_root = bundled_kit_root()
    catalog = load_catalog(kit_root / "controls" / "catalog.yaml")
    profile_ids = [args.profile] if args.profile else _profile_ids(kit_root)

    total_changed = 0
    print(f"ADR-028 impact (applicability engine + --enable-attested) on {repo}\n")
    for pid in profile_ids:
        try:
            deltas = _diff_profile(repo, pid, kit_root, catalog)
        except LoadError as exc:
            sys.stderr.write(f"  {pid}: load error: {exc}\n")
            return 2
        if deltas:
            total_changed += len(deltas)
            print(f"  {pid}: {len(deltas)} control(s) change:")
            for cid, old, new in deltas:
                print(f"      {cid}: {old} -> {new}")

    n = len(profile_ids)
    if total_changed == 0:
        print(f"No control status changes across {n} profile(s) for this target.")
    else:
        print(f"\nTotal: {total_changed} control change(s) across {n} profile(s).")

    if args.fail_on_drift and total_changed > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
