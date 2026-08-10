"""How the GitLab collector fails: typed errors, not tracebacks, and never a false PASS.

`collect-evidence --platform gitlab` talks to an API that can rate-limit, refuse, disappear
mid-call, or answer with something that is not what the schema expects. Each of those has to
become a *typed* collector error the CLI can turn into an exit code, and none of them may
produce evidence that looks collected when it was not.

The branches doing that had not been executed. They matter more than most: evidence the
collector invents or silently defaults is evidence an evaluator will trust.

The pure predicates are called directly; anything involving HTTP goes through
`httpx.MockTransport`, the same harness the existing collector tests use, so the request
path and status handling are real.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from oss_policy_kit.domain.errors import (
    CollectionNetworkError,
    CollectionPermissionError,
    RateLimitError,
)
from oss_policy_kit.infrastructure.collectors import gitlab_collector as g
from oss_policy_kit.infrastructure.collectors.gitlab_collector import GitLabEvidenceCollector


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.headers = headers or {}


# --------------------------------------------------------------------------- #
# rate limiting
# --------------------------------------------------------------------------- #


def test_a_rate_limited_response_becomes_a_typed_error() -> None:
    """429 is not a collection result; it is the API asking us to stop."""

    with pytest.raises(RateLimitError):
        g._enforce_rate_limit(_FakeResponse(429))


def test_the_retry_after_hint_is_passed_through_when_the_api_sends_one() -> None:
    """The operator needs to know how long to wait; dropping it wastes their next attempt."""

    with pytest.raises(RateLimitError) as excinfo:
        g._enforce_rate_limit(_FakeResponse(429, {"retry-after": "120"}))

    assert "120" in str(excinfo.value)


def test_no_retry_after_header_still_produces_a_clean_message() -> None:
    """The hint is optional; its absence must not leave a dangling fragment."""

    with pytest.raises(RateLimitError) as excinfo:
        g._enforce_rate_limit(_FakeResponse(429))

    assert "Retry-After" not in str(excinfo.value)


@pytest.mark.parametrize("status", [200, 404, 500])
def test_any_other_status_is_not_treated_as_rate_limiting(status: int) -> None:
    """The negative case, so the checks above cannot pass by always raising."""

    g._enforce_rate_limit(_FakeResponse(status))


# --------------------------------------------------------------------------- #
# "nobody may push directly" -- the predicate behind the branch-protection evidence
# --------------------------------------------------------------------------- #


def test_every_push_level_set_to_no_one_means_merge_only() -> None:
    protected = {"push_access_levels": [{"access_level": g._ACCESS_LEVEL_NO_ONE}]}

    assert g._push_access_blocks_everyone(protected) is True


@pytest.mark.parametrize(
    ("label", "protected"),
    [
        ("no key at all", {}),
        ("not a list", {"push_access_levels": "maintainers"}),
        ("an empty list", {"push_access_levels": []}),
        ("an entry that is not an object", {"push_access_levels": ["maintainer"]}),
        ("a level that is not no-one", {"push_access_levels": [{"access_level": 40}]}),
        (
            "one no-one level beside a real one",
            {"push_access_levels": [{"access_level": 0}, {"access_level": 40}]},
        ),
    ],
)
def test_anything_that_still_allows_a_direct_push_is_not_merge_only(label: str, protected: dict[str, Any]) -> None:
    """A false True here would report a branch as protected when someone can still push to it."""

    assert g._push_access_blocks_everyone(protected) is False, label


# --------------------------------------------------------------------------- #
# HTTP failures, through a real request path
# --------------------------------------------------------------------------- #


def test_a_network_failure_becomes_a_typed_collection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A dropped connection must not reach the CLI as a raw httpx traceback."""

    def _drop(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection reset by peer")

    _patch_client(monkeypatch, _drop)
    collector = GitLabEvidenceCollector("tok")

    with pytest.raises(CollectionNetworkError) as excinfo:
        collector.collect("group/project")

    assert "network error" in str(excinfo.value)


def test_an_unexpected_exception_is_also_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    """The catch-all exists so no library-internal error escapes as an exit 3."""

    def _boom(_request: httpx.Request) -> httpx.Response:
        raise TypeError("something inside the client went wrong")

    _patch_client(monkeypatch, _boom)
    collector = GitLabEvidenceCollector("tok")

    with pytest.raises(CollectionNetworkError):
        collector.collect("group/project")


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_request_becomes_a_permission_error(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    """A token without scope must say so, not produce empty evidence."""

    _patch_client(monkeypatch, lambda _r: httpx.Response(status, json={"message": "denied"}))
    collector = GitLabEvidenceCollector("tok")

    with pytest.raises(CollectionPermissionError):
        collector.collect("group/project")


def test_a_missing_project_collects_nothing_rather_than_something_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 404 on the project yields an empty result set, not a partial or invented one.

    This is the collector's actual contract, and the distinction it turns on: no rows at
    all is a state the caller can see and act on, whereas a row built from defaults would
    reach an evaluator as evidence that was never collected. The emptiness is the signal,
    so it is asserted exactly -- one extra row here would be a fabricated one.
    """

    _patch_client(monkeypatch, lambda _r: httpx.Response(404, json={"message": "404 Project Not Found"}))
    collector = GitLabEvidenceCollector("tok")

    assert collector.collect("group/does-not-exist") == []


def test_a_project_response_that_is_not_an_object_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 200 carrying a list is not a project; treating it as one corrupts every field read."""

    def _listy(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/v4/projects/group/project"):
            return httpx.Response(200, json=["not", "an", "object"])
        return httpx.Response(200, json={})

    _patch_client(monkeypatch, _listy)
    collector = GitLabEvidenceCollector("tok")

    with pytest.raises(ValueError) as excinfo:
        collector.collect("group/project")

    assert "not an object" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# org MFA posture is skipped rather than guessed
# --------------------------------------------------------------------------- #


def _project(namespace: Any) -> dict[str, Any]:
    return {"default_branch": "main", "namespace": namespace}


@pytest.mark.parametrize(
    ("label", "namespace"),
    [
        ("a personal namespace", {"id": 7, "kind": "user", "full_path": "me"}),
        ("a namespace that is not an object", "group"),
        ("no namespace at all", None),
        ("a group with no id", {"kind": "group", "full_path": "group"}),
    ],
)
def test_org_mfa_is_skipped_when_there_is_no_group_to_read(
    monkeypatch: pytest.MonkeyPatch, label: str, namespace: Any
) -> None:
    """A user namespace has no org-wide 2FA setting; inventing one would be a false claim."""

    _patch_client(monkeypatch, lambda _r: httpx.Response(200, json={}))
    meta = g._GlCollectMeta(
        collected_at="2026-06-15T12:00:00Z",
        attested_date="2026-06-15",
        attested_by="test",
        base="https://gitlab.com/api/v4",
    )

    assert g._build_org_mfa(httpx.Client(), meta, _project(namespace)) is None, label


def test_org_mfa_is_skipped_when_the_group_cannot_be_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 404 on the group means no answer, which is not the same as "2FA not required"."""

    _patch_client(monkeypatch, lambda _r: httpx.Response(404, json={"message": "404 Group Not Found"}))
    meta = g._GlCollectMeta(
        collected_at="2026-06-15T12:00:00Z",
        attested_date="2026-06-15",
        attested_by="test",
        base="https://gitlab.com/api/v4",
    )
    project = _project({"id": 99, "kind": "group", "full_path": "group"})

    assert g._build_org_mfa(httpx.Client(), meta, project) is None
