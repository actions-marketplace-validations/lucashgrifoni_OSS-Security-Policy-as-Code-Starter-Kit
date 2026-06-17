"""v10 CISA Secure by Design Pledge readiness signals.

CISA-SBD-VDP-001 (published VDP, ISO/IEC 29147), CISA-SBD-CVE-003 (CWE-in-advisory
hygiene, ISO/IEC 30111), CISA-SBD-SECRETS-005 (default-credential / hardcoded-secret
hygiene composed from the gitleaks SARIF evidence). The MFA pledge goal stays with
ORG-MFA-001; these are "readiness" signals, never "pledge fulfilled".

Unit tests mirror test_cycle2_controls.py: SimpleNamespace contexts, fixtures in tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from oss_policy_kit.application.evaluators import (
    EVALUATOR_REGISTRY,
    eval_cisa_sbd_cve_003,
    eval_cisa_sbd_secrets_005,
    eval_cisa_sbd_vdp_001,
)
from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)
from oss_policy_kit.domain.models import ControlStatus

_NEW_SBD_CONTROLS = (
    "CISA-SBD-VDP-001",
    "CISA-SBD-CVE-003",
    "CISA-SBD-SECRETS-005",
)


def _ctx(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(repo_root=tmp_path)


# --- wiring invariants -----------------------------------------------------
def test_new_sbd_controls_present_in_catalog_and_registry() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for cid in _NEW_SBD_CONTROLS:
        assert cid in catalog, f"{cid} missing from catalog"
        assert cid in EVALUATOR_REGISTRY, f"{cid} missing from registry"
        assert catalog[cid].lifecycle == "experimental", cid
        assert catalog[cid].assurance in {"signal", "evidence-backed"}, cid


def test_new_sbd_controls_bundled_in_publish_readiness_profile() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "oss-publish-readiness-1")
    for cid in _NEW_SBD_CONTROLS:
        assert cid in spec.control_ids, f"oss-publish-readiness-1 should bundle {cid}"


# --- CISA-SBD-VDP-001: published VDP (ISO/IEC 29147) ----------------------
def test_vdp_pass_on_security_txt_with_contact(tmp_path: Path) -> None:
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "security.txt").write_text("Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n", "utf-8")
    assert eval_cisa_sbd_vdp_001(_ctx(tmp_path)).status is ControlStatus.PASS


def test_vdp_manual_on_security_txt_without_contact(tmp_path: Path) -> None:
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "security.txt").write_text("Expires: 2027-01-01T00:00:00Z\n", "utf-8")
    assert eval_cisa_sbd_vdp_001(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_vdp_pass_on_security_md_section(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text("# Security\n## Reporting a vulnerability\nEmail us.\n", "utf-8")
    assert eval_cisa_sbd_vdp_001(_ctx(tmp_path)).status is ControlStatus.PASS


def test_vdp_manual_when_absent(tmp_path: Path) -> None:
    assert eval_cisa_sbd_vdp_001(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --- CISA-SBD-CVE-003: CWE-in-advisory hygiene (ISO/IEC 30111) ------------
def test_cve_not_applicable_without_advisories(tmp_path: Path) -> None:
    assert eval_cisa_sbd_cve_003(_ctx(tmp_path)).status is ControlStatus.NOT_APPLICABLE


def test_cve_pass_when_advisory_has_cwe(tmp_path: Path) -> None:
    (tmp_path / "advisories.json").write_text(json.dumps({"id": "CVE-2025-1", "cwe": "CWE-79"}), "utf-8")
    assert eval_cisa_sbd_cve_003(_ctx(tmp_path)).status is ControlStatus.PASS


def test_cve_manual_when_advisory_lacks_cwe(tmp_path: Path) -> None:
    (tmp_path / "advisories.json").write_text(json.dumps({"id": "CVE-2025-2", "summary": "bug"}), "utf-8")
    assert eval_cisa_sbd_cve_003(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_cve_pass_on_csaf_directory_advisory(tmp_path: Path) -> None:
    csaf = tmp_path / ".well-known" / "csaf"
    csaf.mkdir(parents=True)
    (csaf / "2025-0001.json").write_text(json.dumps({"vulnerabilities": [{"cwe": {"id": "CWE-22"}}]}), "utf-8")
    assert eval_cisa_sbd_cve_003(_ctx(tmp_path)).status is ControlStatus.PASS


# --- CISA-SBD-SECRETS-005: secret-scan composition ------------------------
def _write_gitleaks_sarif(repo: Path, results: list[dict]) -> None:
    p = repo / ".oss-policy-kit" / "evidence" / "sast" / "gitleaks.sarif.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"runs": [{"results": results}]}), "utf-8")


def test_secrets_manual_when_no_evidence(tmp_path: Path) -> None:
    assert eval_cisa_sbd_secrets_005(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_secrets_pass_on_clean_scan(tmp_path: Path) -> None:
    _write_gitleaks_sarif(tmp_path, [])
    assert eval_cisa_sbd_secrets_005(_ctx(tmp_path)).status is ControlStatus.PASS


def test_secrets_fail_on_findings(tmp_path: Path) -> None:
    _write_gitleaks_sarif(tmp_path, [{"ruleId": "generic-api-key"}])
    assert eval_cisa_sbd_secrets_005(_ctx(tmp_path)).status is ControlStatus.FAIL


def test_secrets_manual_on_unparseable_evidence(tmp_path: Path) -> None:
    p = tmp_path / ".oss-policy-kit" / "evidence" / "sast" / "gitleaks.sarif.json"
    p.parent.mkdir(parents=True)
    p.write_text("not json", "utf-8")
    assert eval_cisa_sbd_secrets_005(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED
