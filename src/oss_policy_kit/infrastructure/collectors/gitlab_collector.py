"""Collect GitLab project evidence via the REST API (v4).

Emits the same evidence JSON files the evaluators read from a clone:

* ``branch-protection.json`` (``branch-protection/v1``) — protected default branch +
  MR approval posture, consumed by **PLAT-BRPROT-015**.
* ``gitlab-mr-rules.json`` — merge-request approval threshold, consumed by **GL-PIPE-011**.
* ``org-mfa-posture.json`` (``org-mfa-posture/v1``) — top-level group 2FA requirement,
  consumed by **ORG-MFA-001** (only when the project lives under a group namespace).

SBOM / provenance artifact digests stay self-attested / pipeline-emitted (the same
"collector partial" boundary as the Azure and AWS collectors).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn, cast
from urllib.parse import quote

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors.base import CollectionResult, EvidenceCollector

logger = logging.getLogger(__name__)

GITLAB_DEFAULT_URL = "https://gitlab.com"

# GitLab protected-branch "access level" sentinel meaning "No one is allowed to push directly".
_ACCESS_LEVEL_NO_ONE = 0


def _utc_iso_timestamp() -> str:
    """Return current UTC time as ISO-8601 with ``Z`` suffix (no micros)."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso_date_prefix(ts: str) -> str:
    return ts[:10] if len(ts) >= 10 else ts


def _gitlab_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/json",
        "PRIVATE-TOKEN": token,
        "User-Agent": "oss-policy-kit-collect-evidence",
    }


def _encoded_project_id(repo_slug: str) -> str:
    """URL-encode a GitLab project identifier (numeric id or ``group/subgroup/project`` path)."""

    slug = repo_slug.strip()
    if not slug:
        msg = "Invalid GitLab project slug: empty. Expected 'group/project' or a numeric project id."
        raise ValueError(msg)
    if slug.isdigit():
        return slug
    return quote(slug, safe="")


def _enforce_rate_limit(response: Any) -> None:
    if response.status_code == 429:
        retry = response.headers.get("retry-after", "")
        hint = f" Retry-After: {retry}." if retry else ""
        raise RateLimitError("GitLab API rate limit exceeded." + hint)


def _raise_permission(url: str, status: int) -> NoReturn:
    """Translate a GitLab permission-like status into a typed collector error (always raises)."""

    raise CollectionPermissionError(
        f"GitLab API returned HTTP {status} for {url}. "
        "Check GITLAB_TOKEN scopes (read_api, plus api for protected-branch/approval/group reads) "
        "and that the project exists and is reachable."
    )


def _gitlab_collection_block(collected_at: str, source_url: str) -> dict[str, str]:
    return {
        "evidence_collection_method": "live",
        "collected_at": collected_at,
        "source_url": source_url,
        "mode": "api",
    }


def _push_access_blocks_everyone(protected: dict[str, Any]) -> bool:
    """Return True when the default-branch protection allows nobody to push directly (merge-only)."""

    levels = protected.get("push_access_levels")
    if not isinstance(levels, list) or not levels:
        return False
    for lvl in levels:
        if not isinstance(lvl, dict):
            return False
        if int(lvl.get("access_level", -1)) != _ACCESS_LEVEL_NO_ONE:
            return False
    return True


def _select_default_branch_protection(
    protected_branches: list[dict[str, Any]], default_branch: str
) -> dict[str, Any] | None:
    """Return the protected-branch entry that matches the default branch by exact name."""

    for pb in protected_branches:
        if isinstance(pb, dict) and str(pb.get("name", "")) == default_branch:
            return pb
    return None


@dataclass(slots=True)
class _GlCollectMeta:
    """Shared timestamps + base URL threaded through the GitLab collection helpers."""

    collected_at: str
    attested_date: str
    attested_by: str
    base: str


class GitLabEvidenceCollector(EvidenceCollector):
    """Collect GitLab project evidence JSON files using ``httpx`` (sync)."""

    def __init__(self, token: str, *, base_url: str = GITLAB_DEFAULT_URL) -> None:
        self._token = token
        self._base = (base_url or GITLAB_DEFAULT_URL).rstrip("/")
        self._api = f"{self._base}/api/v4"

    def collect(self, repo_slug: str) -> list[CollectionResult]:
        """Collect protected-branch, MR-approval, and group-MFA evidence for a GitLab project.

        **Environment (required):** ``GITLAB_TOKEN`` (and ``--repo group/project`` or a numeric
        project id). ``GITLAB_URL`` overrides the default ``https://gitlab.com`` for self-managed
        instances.

        **Token scopes (least privilege, read-only):** ``read_api`` covers project metadata,
        protected branches, and approval rules; reading the parent **group** 2FA posture
        (``org-mfa-posture.json``) needs group read access (``api`` or a group-scoped token).

        **Graceful degradation:** HTTP **401/403** raises
        :class:`~oss_policy_kit.domain.errors.CollectionPermissionError`; **404** on the parent
        group simply skips ``org-mfa-posture.json``; conservative ``false`` posture flags are used
        when an optional endpoint is unreachable.
        """

        try:
            import httpx
        except ImportError as exc:
            msg = "GitLab evidence collection requires httpx. Install with: pip install 'oss-policy-kit[gitlab]'"
            raise RuntimeError(msg) from exc

        project_id = _encoded_project_id(repo_slug)
        collected_at = _utc_iso_timestamp()
        meta = _GlCollectMeta(
            collected_at=collected_at,
            attested_date=_iso_date_prefix(collected_at),
            attested_by="gitlab-api-collection",
            base=self._api,
        )
        try:
            with httpx.Client(headers=_gitlab_headers(self._token), timeout=60.0) as client:
                project = _fetch_gitlab_project(client, meta, project_id)
                if project is None:
                    return []
                default_branch = str(project.get("default_branch") or "main")
                protected = _fetch_gitlab_protected_branches(client, meta, project_id)
                approvals = _fetch_gitlab_approvals(client, meta, project_id)
                rules = _fetch_gitlab_approval_rules(client, meta, project_id)
                results: list[CollectionResult] = [
                    _build_branch_protection(
                        meta, repo_slug, project_id, default_branch, project, protected, approvals
                    ),
                    _build_mr_rules(meta, repo_slug, project_id, approvals, rules, protected, default_branch),
                ]
                mfa = _build_org_mfa(client, meta, project)
                if mfa is not None:
                    results.append(mfa)
                return results
        except (CollectionPermissionError, RateLimitError, ValueError, RuntimeError):
            raise
        except httpx.RequestError as exc:
            raise CollectionNetworkError(f"GitLab network error: {exc}") from exc
        except Exception as exc:
            raise CollectionNetworkError(f"GitLab evidence collection failed: {exc}") from exc


def _gitlab_get(client: Any, meta: _GlCollectMeta, path: str, *, optional: bool, default: Any) -> Any:
    """GET ``{api}{path}``; raise on 401/403, return ``default`` on 404/422 when optional."""

    url = f"{meta.base}{path}"
    r = client.get(url)
    _enforce_rate_limit(r)
    if r.status_code in {401, 403}:
        _raise_permission(url, r.status_code)
    if r.status_code in {404, 422}:
        if optional:
            logger.warning("GitLab returned HTTP %s for %s; using conservative default.", r.status_code, path)
            return default
        _raise_permission(url, r.status_code)
    r.raise_for_status()
    return r.json()


def _fetch_gitlab_project(client: Any, meta: _GlCollectMeta, project_id: str) -> dict[str, Any] | None:
    """GET the project object; None when a 404/422 means the project is unusable."""

    raw = _gitlab_get(client, meta, f"/projects/{project_id}", optional=True, default=None)
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("GitLab project response was not an object.")
    return cast(dict[str, Any], raw)


def _fetch_gitlab_protected_branches(client: Any, meta: _GlCollectMeta, project_id: str) -> list[dict[str, Any]]:
    raw = _gitlab_get(client, meta, f"/projects/{project_id}/protected_branches", optional=True, default=[])
    return [cast(dict[str, Any], x) for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []


def _fetch_gitlab_approvals(client: Any, meta: _GlCollectMeta, project_id: str) -> dict[str, Any]:
    raw = _gitlab_get(client, meta, f"/projects/{project_id}/approvals", optional=True, default={})
    return cast(dict[str, Any], raw) if isinstance(raw, dict) else {}


def _fetch_gitlab_approval_rules(client: Any, meta: _GlCollectMeta, project_id: str) -> list[dict[str, Any]]:
    raw = _gitlab_get(client, meta, f"/projects/{project_id}/approval_rules", optional=True, default=[])
    return [cast(dict[str, Any], x) for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []


def _min_approvers(approvals: dict[str, Any], rules: list[dict[str, Any]]) -> int:
    """Highest required-approver count across the project setting and named approval rules."""

    candidates = [int(approvals.get("approvals_before_merge", 0) or 0)]
    for rule in rules:
        with_required = rule.get("approvals_required")
        if isinstance(with_required, (int, float)):
            candidates.append(int(with_required))
    return max(candidates) if candidates else 0


def _code_owner_required(protected: list[dict[str, Any]], rules: list[dict[str, Any]], default_branch: str) -> bool:
    pb = _select_default_branch_protection(protected, default_branch)
    if pb is not None and bool(pb.get("code_owner_approval_required")):
        return True
    return any(str(r.get("rule_type", "")) == "code_owner" for r in rules)


def _build_branch_protection(
    meta: _GlCollectMeta,
    repo_slug: str,
    project_id: str,
    default_branch: str,
    project: dict[str, Any],
    protected: list[dict[str, Any]],
    approvals: dict[str, Any],
) -> CollectionResult:
    pb = _select_default_branch_protection(protected, default_branch)
    min_approvers = int(approvals.get("approvals_before_merge", 0) or 0)
    restrict_force_push = pb is not None and pb.get("allow_force_push") is False
    enforce_admins = pb is not None and not pb.get("allow_force_push") and _push_access_blocks_everyone(pb)
    source = f"{meta.base}/projects/{project_id}/protected_branches"
    payload: dict[str, Any] = {
        "schema_version": "branch-protection/v1",
        "attested_at": meta.attested_date,
        "attested_by": meta.attested_by,
        "branch": default_branch,
        "protections": {
            "require_pull_request_reviews": min_approvers >= 1,
            "dismiss_stale_reviews": bool(approvals.get("reset_approvals_on_push")),
            "require_status_checks": bool(project.get("only_allow_merge_if_pipeline_succeeds")),
            "enforce_admins": bool(enforce_admins),
            "restrict_force_push": bool(restrict_force_push),
        },
        "collection": _gitlab_collection_block(meta.collected_at, source),
        "notes": (
            f"Derived from GitLab protected_branches + approvals APIs for {repo_slug}. "
            "enforce_admins reflects a merge-only default branch (no direct push); GitLab instance "
            "administrators are never fully restricted by project settings."
        ),
    }
    return CollectionResult(
        evidence_key="branch-protection", data=payload, source_url=source, collected_at=meta.collected_at
    )


def _build_mr_rules(
    meta: _GlCollectMeta,
    repo_slug: str,
    project_id: str,
    approvals: dict[str, Any],
    rules: list[dict[str, Any]],
    protected: list[dict[str, Any]],
    default_branch: str,
) -> CollectionResult:
    source = f"{meta.base}/projects/{project_id}/approval_rules"
    payload: dict[str, Any] = {
        "schema_version": "gitlab-mr-rules/v1",
        "attested_at": meta.attested_date,
        "attested_by": meta.attested_by,
        "project": repo_slug,
        "min_approvers": _min_approvers(approvals, rules),
        "code_owner_approval_required": _code_owner_required(protected, rules, default_branch),
        "reset_approvals_on_push": bool(approvals.get("reset_approvals_on_push")),
        "collection": _gitlab_collection_block(meta.collected_at, source),
        "notes": (
            "Derived from GitLab project approvals + approval_rules APIs. min_approvers is the highest "
            "required-approver count across the project setting and named rules."
        ),
    }
    return CollectionResult(
        evidence_key="gitlab-mr-rules", data=payload, source_url=source, collected_at=meta.collected_at
    )


def _build_org_mfa(client: Any, meta: _GlCollectMeta, project: dict[str, Any]) -> CollectionResult | None:
    """Build org-mfa-posture from the top-level group's 2FA requirement (None for user namespaces)."""

    namespace = project.get("namespace")
    if not isinstance(namespace, dict) or str(namespace.get("kind", "")) != "group":
        logger.info("GitLab project is not under a group namespace; skipping org-mfa-posture.json.")
        return None
    group_id = namespace.get("id")
    if group_id is None:
        return None
    group = _gitlab_get(client, meta, f"/groups/{group_id}", optional=True, default=None)
    if not isinstance(group, dict):
        logger.warning("GitLab group %s unreadable; skipping org-mfa-posture.json.", group_id)
        return None
    required = bool(group.get("require_two_factor_authentication"))
    org_name = str(group.get("full_path") or namespace.get("full_path") or "unknown")
    payload: dict[str, Any] = {
        "schema_version": "org-mfa-posture/v1",
        "attested_at": meta.attested_date,
        "attested_by": meta.attested_by,
        "org_name": org_name,
        "platform": "gitlab",
        "mfa_required_for_all_members": required,
        "mfa_required_for_admins": required,
        "notes": (
            "Derived from the GitLab top-level group require_two_factor_authentication setting. "
            "Subgroups inherit the strictest ancestor requirement."
        ),
    }
    if required:
        payload["enforcement_scope"] = "all_members"
    source = f"{meta.base}/groups/{group_id}"
    return CollectionResult(
        evidence_key="org-mfa-posture", data=payload, source_url=source, collected_at=meta.collected_at
    )
