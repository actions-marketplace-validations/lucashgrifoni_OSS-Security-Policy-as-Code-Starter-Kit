"""Integration checks for GitHub collect + evaluate (requires network and token)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict
from oss_policy_kit.infrastructure.collectors.github_collector import GitHubEvidenceCollector

pytestmark = pytest.mark.skipif(not os.environ.get("GITHUB_TOKEN"), reason="GITHUB_TOKEN not set")


def test_public_repo_collect_and_evaluate_schema_v02(tmp_path: Path) -> None:
    """Best-effort: collect from a public GitHub repo and ensure evaluate emits reports/0.3."""

    slug = "octocat/Hello-World"
    collector = GitHubEvidenceCollector(os.environ["GITHUB_TOKEN"])
    rows = collector.collect(slug)
    assert rows
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    for row in rows:
        (ev / f"{row.evidence_key}.json").write_text(
            json.dumps(row.data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-release-hardening-3")
    report = evaluate_repository(
        tmp_path,
        profile,
        catalog,
        waiver_outcome=None,
        scorecard=None,
        report_json_contract="0.3",
    )
    payload = report_to_dict(report)
    assert "reports/0.3" in payload["schema_version"]
    assert "live_collection" in payload
