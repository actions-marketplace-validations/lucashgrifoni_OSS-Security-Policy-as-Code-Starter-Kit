"""GitLab collector paths where the API answers with less than the code hoped for.

The collector distinguishes endpoints it can do without from endpoints it cannot. A 404 on an
optional one degrades to a conservative default and logs; a 404 on a required one is a
permission problem, because on GitLab a token without the right scope is answered with 404
rather than 403 for resources it may not even know exist. Treating that as "the resource is
absent" would report a project as having no protections when the truth is nobody looked.

The rest is shape and arithmetic: a protected-branch list carrying an entry that is not an
object, an approval rule whose count is not a number, and an MFA payload that must not claim
an enforcement scope it did not observe.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from oss_policy_kit.domain.errors import CollectionPermissionError
from oss_policy_kit.infrastructure.collectors import gitlab_collector as gl


def _meta() -> Any:
    return gl._GlCollectMeta(
        collected_at="2026-08-11T00:00:00Z",
        attested_date="2026-08-11",
        attested_by="ci",
        base="https://gitlab.example/api/v4",
    )


def _client(status: int, payload: Any = None) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(status, json=payload if payload is not None else {}))
    )


# --------------------------------------------------------------------------- #
# Optional vs required endpoints
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", [404, 422])
def test_an_optional_endpoint_degrades_to_the_conservative_default(status: int) -> None:
    sentinel = {"fallback": True}
    out = gl._gitlab_get(_client(status), _meta(), "/projects/1/approvals", optional=True, default=sentinel)
    assert out == sentinel


@pytest.mark.parametrize("status", [404, 422])
def test_a_required_endpoint_answering_404_is_a_permission_problem(status: int) -> None:
    """GitLab answers 404 for resources a token may not see; that is not absence."""

    with pytest.raises(CollectionPermissionError):
        gl._gitlab_get(_client(status), _meta(), "/projects/1", optional=False, default=None)


@pytest.mark.parametrize("status", [401, 403])
def test_an_outright_refusal_is_a_permission_problem_either_way(status: int) -> None:
    with pytest.raises(CollectionPermissionError):
        gl._gitlab_get(_client(status), _meta(), "/projects/1", optional=True, default={})


# --------------------------------------------------------------------------- #
# Shape tolerance
# --------------------------------------------------------------------------- #


def test_a_protected_branch_entry_that_is_not_an_object_is_skipped() -> None:
    """One malformed entry must not hide the real default-branch rule behind it."""

    branches = ["main", {"name": "main", "allow_force_push": False}]
    selected = gl._select_default_branch_protection(branches, "main")
    assert selected == {"name": "main", "allow_force_push": False}


def test_no_rule_for_the_default_branch_returns_nothing() -> None:
    branches = [{"name": "develop"}, {"name": "release/*"}]
    assert gl._select_default_branch_protection(branches, "main") is None


def test_an_approval_rule_without_a_numeric_count_is_ignored() -> None:
    """A non-numeric count must not be coerced into a requirement that does not exist."""

    approvals = {"approvals_before_merge": 1}
    rules = [{"approvals_required": "two"}, {"approvals_required": None}, {"approvals_required": 3}]
    assert gl._min_approvers(approvals, rules) == 3


def test_the_strictest_requirement_wins_across_project_and_rules() -> None:
    assert gl._min_approvers({"approvals_before_merge": 4}, [{"approvals_required": 2}]) == 4


# --------------------------------------------------------------------------- #
# MFA payload honesty
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("required", "expects_scope"),
    [(True, True), (False, False)],
)
def test_enforcement_scope_appears_only_when_mfa_is_actually_required(
    required: bool, expects_scope: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Claiming a scope for an unenforced setting would overstate the org's posture."""

    monkeypatch.setattr(
        gl,
        "_gitlab_get",
        lambda *_a, **_k: {"full_path": "acme", "require_two_factor_authentication": required},
    )
    project = {"namespace": {"id": 9, "kind": "group", "full_path": "acme"}}
    result = gl._build_org_mfa(_client(200), _meta(), project)

    assert result is not None
    assert result.data["mfa_required_for_all_members"] is required
    assert ("enforcement_scope" in result.data) is expects_scope


def test_a_personal_namespace_has_no_org_mfa_posture_to_report() -> None:
    """A user namespace has no group 2FA setting; inventing one would be a fabricated claim."""

    assert gl._build_org_mfa(_client(200), _meta(), {"namespace": {"id": 1, "kind": "user"}}) is None
