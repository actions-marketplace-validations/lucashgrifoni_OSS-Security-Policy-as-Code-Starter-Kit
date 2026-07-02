"""Markdown and JSON report emission."""

from __future__ import annotations

import hashlib
import json
from io import StringIO
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from oss_policy_kit.application.drift import ControlDelta, DriftReport
from oss_policy_kit.application.evidence_projection import (
    EVIDENCE_PROVENANCE_VERSION,
    normalize_confidence,
    project_evidence,
)
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, LiveCollectionMetadata

REPORT_JSON_SCHEMA_URL_V2_0 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0"

REPORTS_V2_STATUS_MAP: dict[str, tuple[str, str | None]] = {
    "pass": ("PASS", None),
    "fail": ("FAIL", None),
    "degraded": ("FAIL", None),
    "manual-review-required": ("UNKNOWN", "manual-review-required"),
    "not-applicable": ("NOT_APPLICABLE", None),
    "skipped": ("UNKNOWN", "skipped-by-flag"),
    "error": ("UNKNOWN", "evaluator-error"),
    "attested": ("ATTESTED", None),
    "self-attested": ("SELF_ATTESTED", None),  # ADR-033: opt-in Insights self-reported evidence
    "waived": ("UNKNOWN", "waived"),
}


def _sanitize_target_path_for_payload(absolute: str, *, include_absolute: bool) -> str:
    """Sanitize the target path for inclusion in shareable report files (M-002).

    Default behavior is privacy-by-default: emit only the basename of the
    target directory. If the target is the current working directory, emit
    ``"."``. Reports that ship in PR artifacts, GitHub Releases, or vulnerability
    write-ups should not leak the auditor's home directory or username.

    Pass ``include_absolute=True`` to opt back into the raw absolute path
    (useful when integrating with downstream tooling that expects it).
    """

    if include_absolute:
        return absolute
    try:
        p = Path(absolute)
        cwd = Path.cwd().resolve()
        if p.resolve() == cwd:
            return "."
        return p.name or "."
    except (OSError, ValueError):
        # Fall back to the original string rather than leaking implementation errors.
        return Path(absolute).name or absolute


def _sanitize_embedded_path_in_text(text: str, *, include_absolute: bool) -> str:
    """Sanitize any absolute paths embedded in a free-text string (M-002).

    The scorecard supplemental ``explanation`` interpolates the raw scorecard
    path into prose (e.g. ``"Loaded N entries from <abs-path>."``). When
    ``include_absolute`` is False, replace each whitespace-delimited token that
    looks like a filesystem path with its sanitized basename so the surrounding
    sentence stays readable while the auditor's home directory / username does
    not leak into shareable reports.
    """

    if include_absolute or not text:
        return text
    out: list[str] = []
    for token in text.split(" "):
        # Strip a single trailing sentence punctuation char so "<path>." sanitizes cleanly.
        suffix = ""
        core = token
        if core and core[-1] in ".,;:":
            core, suffix = core[:-1], core[-1]
        if _looks_like_rooted_path(core):
            core = _sanitize_target_path_for_payload(core, include_absolute=False)
        out.append(core + suffix)
    return " ".join(out)


def _looks_like_rooted_path(token: str) -> bool:
    """Heuristic: is this whitespace-delimited token a rooted filesystem path?

    Only rooted (absolute or home-anchored) paths leak the auditor's home
    directory / username, so the embedded-path sanitizer targets exactly those
    and leaves prose fragments like ``entr(y/ies)`` untouched.
    """

    if not token:
        return False
    if token.startswith(("/", "\\", "~/", "~\\")):
        return True
    # Windows drive-rooted path: a drive letter, a colon, then a path separator.
    return len(token) >= 3 and token[1] == ":" and token[0].isalpha() and token[2] in "/\\"


def _sanitize_scorecard_supplemental(
    supplemental: dict[str, Any] | None, *, include_absolute: bool
) -> dict[str, Any] | None:
    """Return a copy of the scorecard supplemental with paths sanitized (M-002).

    Routes the embedded ``path`` and ``explanation`` through the privacy
    sanitizer so absolute paths only survive when ``include_absolute`` is True.
    """

    if supplemental is None:
        return None
    sanitized = dict(supplemental)
    raw_path = sanitized.get("path")
    if isinstance(raw_path, str):
        sanitized["path"] = _sanitize_target_path_for_payload(raw_path, include_absolute=include_absolute)
    explanation = sanitized.get("explanation")
    if isinstance(explanation, str):
        sanitized["explanation"] = _sanitize_embedded_path_in_text(explanation, include_absolute=include_absolute)
    return sanitized


def _map_status_to_reports_v2(status: str) -> tuple[str, str | None]:
    key = status.strip().lower()
    if key in REPORTS_V2_STATUS_MAP:
        return REPORTS_V2_STATUS_MAP[key]
    return ("UNKNOWN", "unmapped-source-status")


_GITHUB_PROFILE_PREFIX = "github-"
_GITLAB_PROFILE_PREFIX = "gitlab-"
_AZURE_PROFILE_PREFIX = "azure-"
_AWS_PROFILE_PREFIX = "aws-"


def _profile_family(pid: str) -> str | None:
    if pid.startswith(_GITHUB_PROFILE_PREFIX):
        return "github"
    if pid.startswith(_GITLAB_PROFILE_PREFIX):
        return "gitlab"
    if pid.startswith(_AZURE_PROFILE_PREFIX):
        return "azure"
    if pid.startswith(_AWS_PROFILE_PREFIX):
        return "aws"
    return None


def _profile_level(pid: str) -> str | None:
    for token in ("level-1", "level-2", "level-3"):
        if token in pid:
            return "L" + token.split("-", 1)[1]
    return None


def _profile_posture(pid: str) -> str | None:
    if pid.startswith(("github-aws-", "github-azure-")):
        return "multi_platform_advisory_hybrid"
    if pid.endswith("-level-1") or pid.endswith("release-hardening-1"):
        return "starter"
    if pid.endswith("-level-2"):
        return "advisory"
    if pid.endswith("-level-3") or pid.endswith("release-hardening-3"):
        return "hard_gate"
    if pid.endswith("release-hardening-2"):
        return "release_track"
    return None


def _recommended_gate(posture: str | None, is_release_track: bool) -> str | None:
    if posture in {"starter", "release_track", "hard_gate"} or is_release_track:
        return "--fail-on fail"
    if posture in {"advisory", "multi_platform_advisory_hybrid"}:
        return "--fail-on none"
    return None


def derive_profile_metadata(profile_id: str) -> dict[str, Any]:
    """Derive lightweight profile metadata from a profile id for reports/1.0.

    Falls back to ``None`` for fields that cannot be inferred from the id alone.
    Centralizing this in the reporting layer avoids coupling reports to the CLI
    profile-listing helpers.
    """

    pid = profile_id.strip()
    is_release_track = "release-hardening" in pid
    posture = _profile_posture(pid)
    return {
        "family": _profile_family(pid),
        "level": _profile_level(pid),
        "posture": posture,
        "is_release_track": is_release_track,
        "recommended_gate": _recommended_gate(posture, is_release_track),
    }


def compute_results_digest(results: list[ControlResult]) -> str:
    """Stable sha256 digest over canonical control-result fields.

    Covers the deterministic columns: ``control_id``, ``profile``, ``status``,
    ``lifecycle``, ``assurance``, ``weight``. Excludes free-form text (reason,
    remediation), evidence references, and timestamps so the digest is robust to
    cosmetic refactors and to evidence freshness changes.
    """

    canonical = []
    for r in sorted(results, key=lambda x: (x.profile, x.control_id)):
        canonical.append(
            {
                "control_id": r.control_id,
                "profile": r.profile,
                "status": r.status.value,
                "lifecycle": r.lifecycle,
                "assurance": r.assurance,
                "weight": r.weight,
            }
        )
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _live_collection_dict(lc: LiveCollectionMetadata | None) -> dict[str, Any] | None:
    if lc is None:
        return None
    return {
        "performed": lc.performed,
        "platform": lc.platform,
        "collected_at": lc.collected_at,
        "api_evidence_sources": list(lc.api_evidence_sources),
    }


def _structural_bucket(control_id: str) -> str:
    if control_id.startswith("GOV-") or control_id.startswith("REL-"):
        return "Governance and release artifacts (README, LICENSE, SECURITY, changelog)"
    if control_id.startswith("CI-") or control_id.startswith("GH-"):
        return "GitHub Actions CI/CD (workflows, permissions, pins)"
    if control_id.startswith("SEC-"):
        return "Security scanning and vulnerability management in CI"
    if control_id.startswith("PLAT-"):
        return "Platform settings (branch protection, .oss-policy-kit evidence)"
    if control_id.startswith("AZ-"):
        return "Azure Pipelines and related governance"
    if control_id.startswith("AWS-"):
        return "AWS CI/CD (buildspec, CodePipeline) and related governance"
    return "Other profile controls"


def compute_priority_insights(report: ExecutionReport) -> dict[str, Any]:
    """Derive grouped non-pass signals for Markdown / JSON consumers."""

    from collections import Counter

    actionable = [r for r in report.results if r.status in (ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED)]
    bucket_counts = Counter(_structural_bucket(r.control_id) for r in actionable)
    top_causes = [{"bucket": b, "count": n} for b, n in bucket_counts.most_common(5)]

    fails = [r for r in report.results if r.status in (ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED)]
    control_ids = {r.control_id for r in fails}
    actions: list[str] = []
    if "GOV-SEC-001" in control_ids:
        actions.append("Add SECURITY.md at the repo root with a monitored private reporting channel.")
    if "GOV-LIC-004" in control_ids:
        actions.append("Add a recognizable LICENSE file at the repository root.")
    if "GOV-CON-002" in control_ids:
        actions.append("Add CONTRIBUTING.md aligned with security expectations.")
    if "CI-WF-005" in control_ids:
        actions.append("Add workflows under .github/workflows for reproducible CI.")
    if "SEC-CODEQL-010" in control_ids:
        actions.append("Add SAST or code scanning in CI (CodeQL, Semgrep, Bandit, etc.).")
    if "CI-PERM-006" in control_ids:
        actions.append("Declare explicit permissions at the top of workflows.")
    if "CI-PIN-008" in control_ids:
        actions.append("Pin third-party actions to immutable SHAs or safe version tags.")
    if not actions and fails:
        actions.append("Address fail and manual-review-required controls in the detailed table below.")
    elif not fails:
        actions.append("Keep the repository aligned with the profile; review self-attested or not-observable items.")

    by_category: dict[str, list[str]] = {}
    for r in fails:
        by_category.setdefault(r.category, []).append(r.control_id)
    for k in by_category:
        by_category[k] = sorted(set(by_category[k]))

    return {
        "top_structural_causes": top_causes,
        "recommended_actions": actions[:5],
        "failing_controls_by_category": by_category,
    }


def _result_to_dict_v2_0(r: ControlResult) -> dict[str, Any]:
    state, reason = _map_status_to_reports_v2(r.status.value)
    payload: dict[str, Any] = {
        "id": r.control_id,
        "title": r.title,
        "category": r.category,
        "lifecycle": r.lifecycle,
        "profile": r.profile,
        "state": state,
        "assurance": r.assurance,
        "confidence": normalize_confidence(r.confidence),
        "weight": r.weight,
        "message": r.reason,
        "remediation": r.remediation,
        "evidence": project_evidence(r),
        "owner": r.owner,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        "waiver": None,
        "extra": dict(r.extra) if isinstance(r.extra, dict) else {},
        "finding_id": f"{r.control_id}@{r.profile}",
    }
    if reason is not None:
        payload["reason"] = reason
    if r.status.value == "degraded":
        payload["degraded"] = True
    if r.waiver:
        payload["waiver"] = {
            "control_id": r.waiver.control_id,
            "justification": r.waiver.justification,
            "owner": r.waiver.owner,
            "status": r.waiver.status,
            "expires_at": r.waiver.expires_at.isoformat() if r.waiver.expires_at else None,
            "applies_to": r.waiver.applies_to,
        }
    if r.deprecation_note is not None:
        payload["deprecation_note"] = r.deprecation_note
    return payload


def _summary_to_reports_v2(summary_by_status: dict[str, int]) -> dict[str, int]:
    mapped: dict[str, int] = {}
    for status, count in summary_by_status.items():
        state, _ = _map_status_to_reports_v2(status)
        mapped[state] = mapped.get(state, 0) + count
    return dict(sorted(mapped.items()))


def report_to_dict_v2_0(
    report: ExecutionReport,
    *,
    include_absolute_path: bool = False,
) -> dict[str, Any]:
    profile_meta = derive_profile_metadata(report.profile_id)
    profile_block = {
        "id": report.profile_id,
        "title": report.profile_title,
        "family": profile_meta["family"],
        "level": profile_meta["level"],
        "posture": profile_meta["posture"],
        "is_release_track": profile_meta["is_release_track"],
        "recommended_gate": profile_meta["recommended_gate"],
    }

    weighted_score_block: dict[str, Any] | None = None
    if report.weighted_score is not None:
        weighted_score_block = {
            "earned": report.weighted_score.earned,
            "possible": report.weighted_score.possible,
            "percent": report.weighted_score.percent,
        }

    controls = [_result_to_dict_v2_0(r) for r in report.results]
    return {
        "schema_version": REPORT_JSON_SCHEMA_URL_V2_0,
        "contract_version": "reports/2.0",
        "evidence_provenance_version": EVIDENCE_PROVENANCE_VERSION,
        "generated_at": report.generated_at,
        "kit_version": report.kit_version,
        "target_path": _sanitize_target_path_for_payload(report.target_path, include_absolute=include_absolute_path),
        "profile": profile_block,
        "summary_by_status": _summary_to_reports_v2(report.summary_by_status),
        "controls_total": sum(report.summary_by_status.values()),
        "controls": controls,
        "results_digest": compute_results_digest(report.results),
        "operational_warnings": report.operational_warnings,
        "scorecard": {
            "path": (
                _sanitize_target_path_for_payload(report.scorecard_path, include_absolute=include_absolute_path)
                if report.scorecard_path
                else report.scorecard_path
            ),
            "supplemental": _sanitize_scorecard_supplemental(
                report.scorecard_supplemental, include_absolute=include_absolute_path
            ),
        },
        "external_waiver_path": (
            _sanitize_target_path_for_payload(report.external_waiver_path, include_absolute=include_absolute_path)
            if report.external_waiver_path
            else report.external_waiver_path
        ),
        "action_insights": compute_priority_insights(report),
        "live_collection": _live_collection_dict(report.live_collection),
        "weighted_score": weighted_score_block,
        "migration": {
            # Pointer for consumers converting STORED legacy reports; the pre-2.0
            # contracts themselves were removed from the kit in v9.0.0 (ADR-043).
            "from": "reports/1.0",
            "removed_in": "v9.0.0 (ADR-043)",
            "status_mapping": "docs/reports-contract-v2.0.md#mapping-from-reports10-to-reports20",
        },
        "extensions": {},
    }


def report_to_dict(
    report: ExecutionReport,
    *,
    schema_version_override: str | None = None,
    include_absolute_path: bool = False,
) -> dict[str, Any]:
    """Serialize execution report to a JSON-compatible ``reports/2.0`` dict.

    v9.0.0 (ADR-043, BREAKING): ``reports/2.0`` is the only report contract — the legacy
    pre-2.0 contracts (0.1/0.2/0.3/1.0) were removed. ``schema_version_override`` is accepted
    for signature compatibility but no longer selects a legacy shape (contract validation now
    happens upstream in :func:`engine.report_json_schema_url`).

    ``include_absolute_path`` controls whether ``target_path`` in the payload is sanitized to a
    basename (default, privacy-by-default) or kept as the full absolute path.
    """

    return report_to_dict_v2_0(report, include_absolute_path=include_absolute_path)


def write_json_report(
    report: ExecutionReport,
    path: Path,
    *,
    schema_version_override: str | None = None,
    include_absolute_path: bool = False,
) -> None:
    """Write evaluation-report.json."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = report_to_dict(
        report,
        schema_version_override=schema_version_override,
        include_absolute_path=include_absolute_path,
    )
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_markdown_report(  # noqa: C901
    report: ExecutionReport,
    path: Path,
    *,
    include_absolute_path: bool = False,
) -> None:
    """Write evaluation-report.md."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# OSS Policy Kit - evaluation report")
    lines.append("")
    lines.append(f"- **Generated (UTC)**: `{report.generated_at}`")
    lines.append(f"- **Kit version**: `{report.kit_version}`")
    _target_display = _sanitize_target_path_for_payload(report.target_path, include_absolute=include_absolute_path)
    lines.append(f"- **Target**: `{_target_display}`")
    lines.append(f"- **Profile**: `{report.profile_id}` - {report.profile_title}")
    if report.scorecard_path:
        _scorecard_display = _sanitize_target_path_for_payload(
            report.scorecard_path, include_absolute=include_absolute_path
        )
        lines.append(f"- **Scorecard file**: `{_scorecard_display}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("| --- | ---: |")
    for k, v in report.summary_by_status.items():
        lines.append(f"| `{k}` | {v} |")
    lines.append("")
    if report.weighted_score is not None:
        ws = report.weighted_score
        lines.append("## Weighted posture score")
        lines.append("")
        lines.append(
            f"**{ws.earned} / {ws.possible} points ({ws.percent}%)** — risk-adjusted score based on control weights "
            f"(critical=3, high=2, medium=1). Controls with status `not-applicable` or `not-evaluated` are excluded."
        )
        lines.append("")
    lines.extend(_md_prioritization_lines(report))
    lines.append("## Waivers and trust boundary")
    lines.append("")
    lines.append(
        "This evaluation only observes what is visible in a local clone (plus optional evidence under "
        "`.oss-policy-kit/evidence/`). It **does not** replace human audit or prove absence of risk."
    )
    lines.append("")
    if report.external_waiver_path:
        _waiver_display = _sanitize_target_path_for_payload(
            report.external_waiver_path, include_absolute=include_absolute_path
        )
        lines.append(
            f"- **External waiver file loaded for this run** (`--waivers`): `{_waiver_display}`. "
            "That file is **not** the same as **versioned in-repo** waiver policy."
        )
        lines.append(
            "- Control `GOV-WAIV-014` specifically checks for a waiver policy file **inside the clone** "
            "(for example `waivers/waivers.yaml`). It may therefore stay `not-evaluated` when no in-repo "
            "waiver file exists even when `--waivers` waives other controls."
        )
    else:
        lines.append(
            "- No external waiver file was passed via `--waivers` in this run. "
            "`GOV-WAIV-014` continues to evaluate **versioned in-repo** waivers only."
        )
    lines.append("")
    if report.operational_warnings:
        lines.append("## Operational warnings")
        lines.append("")
        for w in report.operational_warnings:
            lines.append(f"- {w}")
        lines.append("")
    lines.extend(_md_scorecard_supplemental_lines(report, include_absolute_path=include_absolute_path))
    lines.extend(_md_controls_table_lines(report))
    lines.extend(_md_control_detail_lines(report))
    path.write_text("\n".join(lines), encoding="utf-8")


def _md_prioritization_lines(report: ExecutionReport) -> list[str]:
    """Markdown lines for the structural-prioritization section."""

    insights = compute_priority_insights(report)
    out: list[str] = ["## Prioritization (structural causes)", "", "### Top structural buckets", ""]
    for row in insights["top_structural_causes"][:5]:
        b, n = row["bucket"], row["count"]
        out.append(f"- **{b}** — {n} control(s) failing or requiring manual review in this bucket.")
    if not insights["top_structural_causes"]:
        out.append("- (no aggregated structural findings in this run)")
    out.extend(["", "### Recommended next actions", ""])
    out.extend(f"- {item}" for item in insights["recommended_actions"][:5])
    out.extend(["", "### Failing controls by category", ""])
    if insights["failing_controls_by_category"]:
        for cat, ids in sorted(insights["failing_controls_by_category"].items()):
            out.append(f"- **{cat}**: {', '.join(f'`{i}`' for i in ids)}")
    else:
        out.append("- (no controls in `fail` or `manual-review-required`)")
    out.append("")
    return out


def _md_scorecard_supplemental_lines(report: ExecutionReport, *, include_absolute_path: bool = False) -> list[str]:
    """Markdown lines for the optional Scorecard-supplemental section (empty when absent)."""

    if not report.scorecard_supplemental:
        return []
    ss = _sanitize_scorecard_supplemental(report.scorecard_supplemental, include_absolute=include_absolute_path) or {}
    influenced = ss.get("influenced_control_ids") or []
    influenced_line = (
        f"- **Influenced controls**: {', '.join(f'`{c}`' for c in influenced)}"
        if influenced
        else "- **Influenced controls**: (none in this run)"
    )
    return [
        "## Scorecard supplemental",
        "",
        f"- **Loaded**: `{ss.get('loaded')}`",
        f"- **Check count**: {ss.get('check_count')}",
        influenced_line,
        f"- **Workflows satisfied CodeQL signal**: `{ss.get('workflows_satisfied_codeql_signal')}`",
        f"- **Explanation**: {ss.get('explanation', '')}",
        "",
    ]


def _md_controls_table_lines(report: ExecutionReport) -> list[str]:
    """Markdown lines for the controls summary table."""

    out: list[str] = [
        "## Controls",
        "",
        "| ID | Category | Lifecycle | Assurance | Status | Confidence | Reason | Remediation | Waiver |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in report.results:
        w = f"yes ({r.waiver.owner})" if r.waiver else ""
        reason = r.reason.replace("|", "\\|")
        rem = r.remediation.replace("|", "\\|")
        out.append(
            f"| `{r.control_id}` | {r.category} | {r.lifecycle} | `{r.assurance}` |"
            f" `{r.status.value}` | {r.confidence} | {reason} | {rem} | {w} |"
        )
    out.append("")
    return out


def _md_control_detail_lines(report: ExecutionReport) -> list[str]:
    """Markdown lines for the per-control detail section."""

    out: list[str] = ["## Detail", ""]
    for r in report.results:
        out.append(f"### `{r.control_id}` - {r.title}")
        out.append("")
        out.append(f"- **Status**: `{r.status.value}`")
        out.append(f"- **Lifecycle**: {r.lifecycle}")
        out.append(f"- **Assurance**: `{r.assurance}`")
        out.append(f"- **Evidence collection method**: `{r.evidence_collection_method}`")
        out.append(f"- **Confidence**: {r.confidence}")
        out.append(f"- **Reason**: {r.reason}")
        out.append(f"- **Remediation**: {r.remediation}")
        if r.evidence_sources:
            out.append("- **Evidence**:")
            out.extend(f"  - `{e}`" for e in r.evidence_sources)
        if r.waiver:
            out.append("- **Waiver**:")
            out.append(f"  - **Owner**: {r.waiver.owner}")
            out.append(f"  - **Justification**: {r.waiver.justification}")
            if r.waiver.expires_at:
                out.append(f"  - **Expires**: {r.waiver.expires_at.isoformat()}")
        out.append("")
    return out


def write_reports(
    report: ExecutionReport,
    output_dir: Path,
    *,
    schema_version_override: str | None = None,
    include_absolute_path: bool = False,
) -> tuple[Path, Path]:
    """Write JSON and Markdown reports; return paths.

    ``include_absolute_path`` is forwarded to both writers so the on-disk
    payload either sanitizes ``target_path`` (default, privacy-by-default) or
    keeps the full absolute path the operator passed in.
    """

    json_path = output_dir / "evaluation-report.json"
    md_path = output_dir / "evaluation-report.md"
    write_json_report(
        report,
        json_path,
        schema_version_override=schema_version_override,
        include_absolute_path=include_absolute_path,
    )
    write_markdown_report(report, md_path, include_absolute_path=include_absolute_path)
    return json_path, md_path


def _control_delta_dict(d: ControlDelta) -> dict[str, Any]:
    return {
        "control_id": d.control_id,
        "title": d.title,
        "before_status": d.before_status,
        "after_status": d.after_status,
        "is_regression": d.is_regression,
    }


def _drift_report_dict(report: DriftReport) -> dict[str, Any]:
    return {
        "before_path": report.before_path,
        "after_path": report.after_path,
        "before_kit_version": report.before_kit_version,
        "after_kit_version": report.after_kit_version,
        "regressions": [_control_delta_dict(x) for x in report.regressions],
        "improvements": [_control_delta_dict(x) for x in report.improvements],
        "new_controls": list(report.new_controls),
        "removed_controls": list(report.removed_controls),
        "expired_waivers": list(report.expired_waivers),
        "has_regressions": report.has_regressions,
        "profile_mismatch": report.profile_mismatch,
        "before_profile_id": report.before_profile_id,
        "after_profile_id": report.after_profile_id,
    }


def render_drift_report(report: DriftReport, fmt: str, *, color: bool = True) -> str:  # noqa: C901
    """Render a :class:`~oss_policy_kit.application.drift.DriftReport` for stdout or files.

    Args:
        report: Drift summary from :func:`~oss_policy_kit.application.drift.compute_drift`.
        fmt: ``table`` (default Rich layout), ``json``, or ``markdown`` / ``md``.
        color: Whether ANSI colors should be emitted for ``table`` format.

    Returns:
        Serialized representation as a single string (UTF-8 text).
    """

    f = fmt.strip().lower()
    if f == "json":
        return json.dumps(_drift_report_dict(report), indent=2, ensure_ascii=False) + "\n"
    if f in {"markdown", "md"}:
        return _drift_markdown(report)
    return _drift_table(report, color)


def _drift_markdown(report: DriftReport) -> str:
    """Render a drift report as Markdown."""

    lines = ["# Drift report", ""]
    if report.profile_mismatch:
        lines.extend(
            [
                "> **Note:** Before profile "
                f"(`{report.before_profile_id}`) differs from after profile (`{report.after_profile_id}`). "
                "New or removed controls may reflect profile scope change, not posture change.",
                "",
            ]
        )
    lines.extend(
        [
            f"- **Before**: `{report.before_path}`",
            f"- **After**: `{report.after_path}`",
            f"- **Kit versions**: {report.before_kit_version} → {report.after_kit_version}",
            f"- **Regressions**: {len(report.regressions)}",
            f"- **Improvements**: {len(report.improvements)}",
            "",
            "## Regressions",
            "",
            "| Control | Before | After |",
            "| --- | --- | --- |",
        ]
    )
    lines.extend(f"| `{d.control_id}` | `{d.before_status}` | `{d.after_status}` |" for d in report.regressions)
    lines.extend(["", "## Improvements", "", "| Control | Before | After |", "| --- | --- | --- |"])
    lines.extend(f"| `{d.control_id}` | `{d.before_status}` | `{d.after_status}` |" for d in report.improvements)
    if report.new_controls:
        lines.extend(["", "## New controls in after", ""])
        lines.extend(f"- `{c}`" for c in report.new_controls)
    if report.removed_controls:
        lines.extend(["", "## Removed controls (present only in before)", ""])
        lines.extend(f"- `{c}`" for c in report.removed_controls)
    if report.expired_waivers:
        lines.extend(["", "## Expired waivers", ""])
        lines.extend(f"- `{c}`" for c in report.expired_waivers)
    return "\n".join(lines) + "\n"


def _drift_table(report: DriftReport, color: bool) -> str:
    """Render a drift report as a Rich table (with trailing platform notes)."""

    buf = StringIO()
    console = Console(file=buf, width=120, force_terminal=color, color_system=("standard" if color else None))
    table = Table(title="Posture drift — regressions (red) and improvements (green)")
    table.add_column("Kind", style="bold")
    table.add_column("Control")
    table.add_column("Before")
    table.add_column("After")
    for d in report.regressions:
        table.add_row("[red]regression[/red]", d.control_id, d.before_status, d.after_status)
    for d in report.improvements:
        table.add_row("[green]improve[/green]", d.control_id, d.before_status, d.after_status)
    if not report.regressions and not report.improvements:
        table.add_row("—", "(no status changes on shared controls)", "", "")
    console.print(table)
    if report.new_controls:
        console.print(f"[cyan]New in after:[/cyan] {', '.join(report.new_controls)}")
    if report.removed_controls:
        console.print(f"[yellow]Removed:[/yellow] {', '.join(report.removed_controls)}")
    if report.expired_waivers:
        console.print(f"[magenta]Expired waivers:[/magenta] {', '.join(report.expired_waivers)}")
    return buf.getvalue()
