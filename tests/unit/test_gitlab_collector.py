"""Happy-path + degradation coverage for ``GitLabEvidenceCollector.collect`` (httpx mocked)."""

from __future__ import annotations

import httpx
import pytest

from oss_policy_kit.application.evidence_loading import load_evidence_schema
from oss_policy_kit.domain.errors import CollectionPermissionError
from oss_policy_kit.infrastructure.collectors.gitlab_collector import (
    GitLabEvidenceCollector,
    _encoded_project_id,
)


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)


def _full_handler(request: httpx.Request) -> httpx.Response:
    # httpx percent-decodes %2F in request.url.path, so 'group%2Fproject' arrives as 'group/project'.
    path = request.url.path
    if path.endswith("/api/v4/projects/group/project"):
        return httpx.Response(
            200,
            json={
                "default_branch": "main",
                "only_allow_merge_if_pipeline_succeeds": True,
                "namespace": {"id": 99, "kind": "group", "full_path": "group"},
            },
        )
    if path.endswith("/protected_branches"):
        return httpx.Response(
            200,
            json=[
                {
                    "name": "main",
                    "allow_force_push": False,
                    "code_owner_approval_required": True,
                    "push_access_levels": [{"access_level": 0}],
                }
            ],
        )
    if path.endswith("/approvals"):
        return httpx.Response(200, json={"approvals_before_merge": 2, "reset_approvals_on_push": True})
    if path.endswith("/approval_rules"):
        return httpx.Response(200, json=[{"name": "default", "approvals_required": 2, "rule_type": "regular"}])
    if path.endswith("/api/v4/groups/99"):
        return httpx.Response(200, json={"require_two_factor_authentication": True, "full_path": "group"})
    return httpx.Response(404, json={"message": "unexpected"})


def test_collect_full_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, _full_handler)
    rows = GitLabEvidenceCollector("tok").collect("group/project")
    keys = {r.evidence_key for r in rows}
    assert keys == {"branch-protection", "gitlab-mr-rules", "org-mfa-posture"}

    bp = next(r for r in rows if r.evidence_key == "branch-protection").data
    assert bp["schema_version"] == "branch-protection/v1"
    assert bp["branch"] == "main"
    assert bp["protections"]["require_pull_request_reviews"] is True
    assert bp["protections"]["require_status_checks"] is True
    assert bp["protections"]["restrict_force_push"] is True
    assert bp["protections"]["enforce_admins"] is True  # push_access "no one" + no force push
    assert bp["attested_by"] == "gitlab-api-collection"

    mr = next(r for r in rows if r.evidence_key == "gitlab-mr-rules").data
    assert mr["min_approvers"] == 2
    assert mr["code_owner_approval_required"] is True

    mfa = next(r for r in rows if r.evidence_key == "org-mfa-posture").data
    assert mfa["platform"] == "gitlab"
    assert mfa["mfa_required_for_all_members"] is True
    assert mfa["enforcement_scope"] == "all_members"


def test_collected_payloads_match_bundled_schemas(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("jsonschema")
    import jsonschema

    _patch_client(monkeypatch, _full_handler)
    rows = GitLabEvidenceCollector("tok").collect("group/project")
    bp = next(r for r in rows if r.evidence_key == "branch-protection").data
    jsonschema.validate(bp, load_evidence_schema("evidence-branch-protection.schema.json"))
    mfa = next(r for r in rows if r.evidence_key == "org-mfa-posture").data
    jsonschema.validate(mfa, load_evidence_schema("evidence-org-mfa-posture.schema.json"))


def test_collect_user_namespace_skips_org_mfa(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/v4/projects/me/proj"):
            return httpx.Response(
                200,
                json={"default_branch": "main", "namespace": {"id": 1, "kind": "user", "full_path": "me"}},
            )
        if path_ends_collection(request.url.path):
            return httpx.Response(200, json=[])
        if request.url.path.endswith("/approvals"):
            return httpx.Response(200, json={})
        return httpx.Response(404, json={})

    def path_ends_collection(p: str) -> bool:
        return p.endswith("/protected_branches") or p.endswith("/approval_rules")

    _patch_client(monkeypatch, handler)
    rows = GitLabEvidenceCollector("tok").collect("me/proj")
    keys = {r.evidence_key for r in rows}
    assert "org-mfa-posture" not in keys
    assert keys == {"branch-protection", "gitlab-mr-rules"}


def test_collect_permission_error_on_project_403(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda r: httpx.Response(403, json={"message": "denied"}))
    collector = GitLabEvidenceCollector("tok")
    with pytest.raises(CollectionPermissionError):
        collector.collect("group/project")


def test_collect_project_404_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda r: httpx.Response(404, json={"message": "not found"}))
    rows = GitLabEvidenceCollector("tok").collect("group/project")
    assert rows == []  # 404 on project -> abort, no evidence


def test_self_managed_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path.endswith("/api/v4/projects/g/p"):
            return httpx.Response(200, json={"default_branch": "main", "namespace": {"kind": "user"}})
        return httpx.Response(200, json=[] if not request.url.path.endswith("/approvals") else {})

    _patch_client(monkeypatch, handler)
    GitLabEvidenceCollector("tok", base_url="https://gitlab.example.com").collect("g/p")
    assert any(u.startswith("https://gitlab.example.com/api/v4/") for u in seen)


def test_encoded_project_id() -> None:
    assert _encoded_project_id("group/project") == "group%2Fproject"
    assert _encoded_project_id("group/sub/project") == "group%2Fsub%2Fproject"
    assert _encoded_project_id("12345") == "12345"
    with pytest.raises(ValueError, match="empty"):
        _encoded_project_id("   ")
