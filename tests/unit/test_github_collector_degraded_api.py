"""What the GitHub collector does with refused scopes and payloads of the wrong shape.

Two different degradations live here and they are deliberately not symmetric. A 403 on a
repo-level endpoint is a *failure*: the token was supposed to be able to read it, and
silently returning an empty posture would let a repository look unprotected when nobody
actually checked. A 403 on the org-level Actions policy is a *skip*: that endpoint needs
``admin:org``, which most collection tokens correctly do not carry, so it degrades to
"not collected" rather than taking the whole run down.

The rest is shape tolerance. GitHub's rulesets, environment protection rules and
selected-actions payloads are all loosely typed, and a rule that arrives as a string instead
of an object must be skipped rather than crash a collection that was otherwise fine.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError
from oss_policy_kit.infrastructure.collectors import github_collector as gh
from oss_policy_kit.infrastructure.collectors.github_collector import GitHubEvidenceCollector


def _install(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> None:
    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def _client(**kwargs: Any) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)


# --------------------------------------------------------------------------- #
# Ruleset posture: loosely typed rules
# --------------------------------------------------------------------------- #


def test_a_ruleset_rule_that_is_not_an_object_is_skipped() -> None:
    """A bare string where a rule object was expected must not abort the scan."""

    posture = dict.fromkeys(
        ["require_pull_request", "require_status_checks", "restrict_force_push", "require_code_owner_review"],
        False,
    )
    gh._apply_ruleset_rule("non_fast_forward", posture)
    assert all(v is False for v in posture.values()), posture


@pytest.mark.parametrize(
    ("rule_type", "flag"),
    [
        ("required_status_checks", "require_status_checks"),
        ("non_fast_forward", "restrict_force_push"),
        ("deletion", "restrict_force_push"),
        ("update", "restrict_force_push"),
    ],
)
def test_each_rule_type_sets_its_own_flag(rule_type: str, flag: str) -> None:
    posture = dict.fromkeys(
        ["require_pull_request", "require_status_checks", "restrict_force_push", "require_code_owner_review"],
        False,
    )
    gh._apply_ruleset_rule({"type": rule_type}, posture)
    assert posture[flag] is True


@pytest.mark.parametrize(
    "params",
    [
        {"required_reviewers": 1},
        {"require_code_owner_review": True},
    ],
)
def test_pull_request_rule_records_code_owner_review(params: dict[str, Any]) -> None:
    posture = dict.fromkeys(
        ["require_pull_request", "require_status_checks", "restrict_force_push", "require_code_owner_review"],
        False,
    )
    gh._apply_ruleset_rule({"type": "pull_request", "parameters": params}, posture)
    assert posture["require_pull_request"] is True
    assert posture["require_code_owner_review"] is True


def test_pull_request_rule_without_reviewer_parameters_does_not_claim_code_owner_review() -> None:
    """Requiring a PR is not the same as requiring a code owner on it."""

    posture = dict.fromkeys(
        ["require_pull_request", "require_status_checks", "restrict_force_push", "require_code_owner_review"],
        False,
    )
    gh._apply_ruleset_rule({"type": "pull_request", "parameters": {}}, posture)
    assert posture["require_pull_request"] is True
    assert posture["require_code_owner_review"] is False


def test_an_unrecognised_ruleset_rule_type_sets_no_flag() -> None:
    """GitHub keeps adding ruleset rule types; an unknown one must not imply protection."""

    posture = dict.fromkeys(
        ["require_pull_request", "require_status_checks", "restrict_force_push", "require_code_owner_review"],
        False,
    )
    gh._apply_ruleset_rule({"type": "commit_message_pattern"}, posture)
    assert all(v is False for v in posture.values()), posture


def test_a_disabled_ruleset_contributes_nothing() -> None:
    """`enforcement: disabled` means GitHub is not applying it, so neither do we."""

    rulesets = [
        {"enforcement": "disabled", "rules": [{"type": "pull_request"}, {"type": "non_fast_forward"}]},
    ]
    assert all(v is False for v in gh._scan_ruleset_posture(rulesets).values())


def test_an_active_ruleset_beside_a_disabled_one_still_counts() -> None:
    rulesets = [
        {"enforcement": "disabled", "rules": [{"type": "required_status_checks"}]},
        {"enforcement": "active", "rules": [{"type": "pull_request"}]},
    ]
    posture = gh._scan_ruleset_posture(rulesets)
    assert posture["require_pull_request"] is True
    assert posture["require_status_checks"] is False


# --------------------------------------------------------------------------- #
# Environment protection rules
# --------------------------------------------------------------------------- #


def test_environment_protection_rule_that_is_not_an_object_is_skipped() -> None:
    env = {"name": "prod", "protection_rules": ["required_reviewers", {"type": "required_reviewers"}]}
    mapped = gh._map_environment(env)
    assert mapped["name"] == "prod"
    assert mapped["requires_reviewers"] is True


def test_an_unrecognised_protection_rule_type_changes_nothing() -> None:
    """GitHub adds protection rule types over time; an unknown one is not a reviewer gate."""

    mapped = gh._map_environment({"name": "prod", "protection_rules": [{"type": "branch_policy"}]})
    assert mapped["requires_reviewers"] is False
    assert mapped["wait_timer_minutes"] == 0


def test_wait_timer_is_read_only_when_it_is_actually_a_number() -> None:
    """A string wait timer must leave the value at zero rather than land in the evidence."""

    numeric = gh._map_environment(
        {"name": "prod", "protection_rules": [{"type": "wait_timer", "parameters": {"wait_timer": 30}}]}
    )
    textual = gh._map_environment(
        {"name": "prod", "protection_rules": [{"type": "wait_timer", "parameters": {"wait_timer": "30"}}]}
    )
    assert numeric["wait_timer_minutes"] == 30
    assert textual["wait_timer_minutes"] == 0


def test_the_longest_wait_timer_wins() -> None:
    env = {
        "name": "prod",
        "protection_rules": [
            {"type": "wait_timer", "parameters": {"wait_timer": 5}},
            {"type": "wait_timer", "parameters": {"wait_timer": 45}},
        ],
    }
    assert gh._map_environment(env)["wait_timer_minutes"] == 45


# --------------------------------------------------------------------------- #
# Refused scopes: repo-level fails, org-level skips
# --------------------------------------------------------------------------- #


def test_a_repo_endpoint_returning_403_is_a_permission_error() -> None:
    """The token was meant to read this; an empty posture would be a false negative."""

    client = httpx.Client(
        base_url=gh.GITHUB_API, transport=httpx.MockTransport(lambda r: httpx.Response(403, json={"message": "no"}))
    )
    with pytest.raises(CollectionPermissionError):
        gh._fetch_optional_json(client, "/repos/o/r/rulesets", label="rulesets", default=None)


def test_the_org_actions_policy_returning_403_degrades_to_a_skip() -> None:
    """That endpoint needs admin:org, which most collection tokens correctly lack."""

    client = httpx.Client(
        base_url=gh.GITHUB_API, transport=httpx.MockTransport(lambda r: httpx.Response(403, json={"message": "no"}))
    )
    out = gh._fetch_optional_json(
        client, "/orgs/o/actions/permissions", label="org policy", default=None, raise_on_403=False
    )
    assert out is None


@pytest.mark.parametrize("status", [404, 422])
def test_absent_or_unprocessable_endpoints_fall_back_to_the_default(status: int) -> None:
    client = httpx.Client(
        base_url=gh.GITHUB_API, transport=httpx.MockTransport(lambda r: httpx.Response(status, json={"message": "no"}))
    )
    sentinel = {"fallback": True}
    out = gh._fetch_optional_json(client, "/repos/o/r/x", label="x", default=sentinel)
    assert out == sentinel


# --------------------------------------------------------------------------- #
# Org Actions policy
# --------------------------------------------------------------------------- #


def _actions_policy(monkeypatch: pytest.MonkeyPatch, permissions: dict[str, Any], selected: Any) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if "selected-actions" in str(request.url):
            return httpx.Response(200, json=selected)
        return httpx.Response(200, json=permissions)

    _install(monkeypatch, handler)
    client = httpx.Client(base_url=gh.GITHUB_API)
    return gh._collect_actions_policy(
        client,
        "acme",
        collected_at="2026-08-11T00:00:00Z",
        attested_date="2026-08-11",
        attested_by="ci",
    )


@pytest.mark.parametrize("allowed", ["all", "local_only"])
def test_a_policy_that_is_not_selected_does_not_query_selected_actions(
    allowed: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only `selected` has a selected-actions sub-resource; the others must not claim one."""

    result = _actions_policy(
        monkeypatch,
        {"allowed_actions": allowed, "sha_pinning_required": True},
        {"verified_allowed": True},
    )
    assert result is not None
    assert result.data["posture"]["allowed_actions"] == allowed
    assert "verified_creators_allowed" not in result.data["posture"]


def test_selected_actions_without_the_verified_flag_leaves_it_unrecorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absent means 'GitHub did not tell us', which is not the same as False."""

    result = _actions_policy(
        monkeypatch,
        {"allowed_actions": "selected", "sha_pinning_required": False},
        {"patterns_allowed": ["acme/*"]},
    )
    assert result is not None
    assert "verified_creators_allowed" not in result.data["posture"]


def test_selected_actions_records_the_verified_creator_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _actions_policy(
        monkeypatch,
        {"allowed_actions": "selected", "sha_pinning_required": False},
        {"verified_allowed": True},
    )
    assert result is not None
    assert result.data["posture"]["verified_creators_allowed"] is True


def test_an_unknown_allowed_actions_value_is_normalised_to_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unrecognised value must degrade to the least-restrictive reading, not be echoed."""

    result = _actions_policy(monkeypatch, {"allowed_actions": "something_new"}, {})
    assert result is not None
    assert result.data["posture"]["allowed_actions"] == "all"


# --------------------------------------------------------------------------- #
# collect() error translation
# --------------------------------------------------------------------------- #


def test_a_runtime_error_from_inside_collection_is_not_reclassified(monkeypatch: pytest.MonkeyPatch) -> None:
    """RuntimeError carries its own meaning; wrapping it as a network error would mislead."""

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("kit invariant violated")

    _install(monkeypatch, lambda r: httpx.Response(200, json={}))
    monkeypatch.setattr(gh, "_fetch_optional_json", _boom)
    collector = GitHubEvidenceCollector("tok")
    with pytest.raises(RuntimeError, match="kit invariant"):
        collector.collect("o/r")


def test_an_unexpected_exception_becomes_a_collection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anything else must reach the caller as a collection failure, not a raw traceback."""

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise TypeError("unexpected payload shape")

    _install(monkeypatch, lambda r: httpx.Response(200, json={}))
    monkeypatch.setattr(gh, "_fetch_optional_json", _boom)
    collector = GitHubEvidenceCollector("tok")
    with pytest.raises(CollectionNetworkError):
        collector.collect("o/r")
