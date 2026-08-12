"""What the Azure DevOps collector does when the API does not cooperate.

The happy path is covered in ``test_azure_collector.py``. This file is the other half: the
organisation that will not grant the PAT the scope it needs, the endpoint that answers 422
instead of data, the environments API that returns a shape nobody expected, and the response
that is valid JSON but not the object the code was written against.

The property being protected is that a *degraded* collection is never indistinguishable from
a *clean* one. Every one of these paths either raises something the caller can act on, or
records a ``posture_support`` flag saying the API could not be reached -- because a governance
posture inferred from an API that answered 403 is not evidence, and downstream evaluators are
built to notice the difference.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError
from oss_policy_kit.infrastructure.collectors import azure_collector as az
from oss_policy_kit.infrastructure.collectors.azure_collector import AzureDevOpsEvidenceCollector

_REPO_ID = "repo-guid-1"


def _ok_repos() -> httpx.Response:
    return httpx.Response(
        200,
        json={"value": [{"id": _REPO_ID, "name": "myrepo", "defaultBranch": "refs/heads/main"}]},
    )


def _install(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> None:
    """Route every httpx.Client through a MockTransport running *handler*."""

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def _client(**kwargs: Any) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)


def _collector() -> AzureDevOpsEvidenceCollector:
    return AzureDevOpsEvidenceCollector(organization="contoso", personal_access_token="pat")


def _routed(**overrides: httpx.Response | Callable[[], httpx.Response]) -> Callable[[httpx.Request], httpx.Response]:
    """Build a handler where each Azure endpoint can be overridden by keyword.

    Anything not overridden answers with a minimal healthy payload, so each test changes
    exactly one endpoint and the failure it asserts can only have come from that one.
    """

    defaults: dict[str, Any] = {
        "repositories": _ok_repos,
        "policies": lambda: httpx.Response(200, json={"value": []}),
        "pipelines": lambda: httpx.Response(200, json={"value": [{"id": 1, "name": "ci"}]}),
        "environments": lambda: httpx.Response(200, json={"value": []}),
        "checks": lambda: httpx.Response(200, json={"value": []}),
        "endpoints": lambda: httpx.Response(200, json={"value": []}),
    }
    routes = {**defaults, **overrides}

    def _resolve(key: str) -> httpx.Response:
        val = routes[key]
        resolved = val() if callable(val) else val
        assert isinstance(resolved, httpx.Response)
        return resolved

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if "git/repositories" in u:
            return _resolve("repositories")
        if "policy/configurations" in u:
            return _resolve("policies")
        if "_apis/pipelines" in u:
            return _resolve("pipelines")
        if "distributedtask/environments" in u:
            return _resolve("environments")
        if "_apis/check/configurations" in u:
            return _resolve("checks")
        if "serviceendpoint/endpoints" in u:
            return _resolve("endpoints")
        return httpx.Response(404, json={"message": "unexpected"})

    return handler


# --------------------------------------------------------------------------- #
# Pure policy-shape helpers
# --------------------------------------------------------------------------- #


def test_a_policy_scope_may_be_a_single_object_rather_than_a_list() -> None:
    """Azure returns `scope` as a bare object for some policy types; both shapes count."""

    as_list = {"settings": {"scope": [{"repositoryId": _REPO_ID}]}}
    as_object = {"settings": {"scope": {"repositoryId": _REPO_ID}}}

    assert az._policy_applies_to_repository(as_list, _REPO_ID) is True
    assert az._policy_applies_to_repository(as_object, _REPO_ID) is True


def test_a_policy_scope_of_an_unexpected_type_matches_nothing() -> None:
    assert az._policy_applies_to_repository({"settings": {"scope": "main"}}, _REPO_ID) is False
    assert az._policy_applies_to_repository({"settings": "not-a-dict"}, _REPO_ID) is False


@pytest.mark.parametrize(
    ("allow_bypass", "expected"),
    [(False, True), (True, False)],
)
def test_bypass_policy_is_recorded_the_right_way_round(allow_bypass: bool, expected: bool) -> None:
    """`bypass_policy_restricted` is the negation of Azure's `allowBypass`; getting this
    backwards would report an org that permits bypass as one that forbids it."""

    configs = [
        {
            "type": {"id": az._POLICY_BYPASS},
            "settings": {"scope": [{"repositoryId": _REPO_ID}], "allowBypass": allow_bypass},
        }
    ]
    posture = az._infer_branch_posture(configs, _REPO_ID)
    assert posture["bypass_policy_restricted"] is expected


def test_a_policy_type_we_do_not_map_leaves_the_posture_untouched() -> None:
    """Azure ships policy types this kit has no opinion about; they must not flip a flag."""

    configs = [
        {
            "type": {"id": "00000000-0000-0000-0000-000000000000"},
            "settings": {"scope": [{"repositoryId": _REPO_ID}]},
        }
    ]
    posture = az._infer_branch_posture(configs, _REPO_ID)
    assert all(v is False for v in posture.values()), posture


# --------------------------------------------------------------------------- #
# Refused scopes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", [401, 403])
def test_policy_api_refusing_the_pat_is_a_permission_error(status: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """A PAT without Code(read) must fail loudly, not yield an empty policy set."""

    _install(monkeypatch, _routed(policies=httpx.Response(status, json={"message": "nope"})))
    collector = _collector()
    with pytest.raises(CollectionPermissionError):
        collector.collect("Proj/myrepo")


@pytest.mark.parametrize("status", [401, 403])
def test_pipelines_api_refusing_the_pat_is_a_permission_error(status: int, monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _routed(pipelines=httpx.Response(status, json={"message": "nope"})))
    collector = _collector()
    with pytest.raises(CollectionPermissionError):
        collector.collect("Proj/myrepo")


# --------------------------------------------------------------------------- #
# Endpoints that answer, but not with data
# --------------------------------------------------------------------------- #


def test_policy_api_returning_422_yields_an_empty_posture_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """422 is Azure's answer for projects without policy support; treat it as 'no policies'."""

    _install(monkeypatch, _routed(policies=httpx.Response(422, json={"message": "unsupported"})))
    rows = _collector().collect("Proj/myrepo")
    bp = next(r for r in rows if r.evidence_key == "azure-branch-policies").data
    assert all(v is False for v in bp["posture"].values()), bp["posture"]


def test_pipelines_api_returning_422_still_completes_the_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _routed(pipelines=httpx.Response(422, json={"message": "unsupported"})))
    rows = _collector().collect("Proj/myrepo")
    assert {r.evidence_key for r in rows} >= {"azure-branch-policies", "azure-pipeline-governance"}


def test_policy_api_returning_404_yields_an_empty_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    """A project with no policy endpoint at all is 'no policies', not a failure."""

    _install(monkeypatch, _routed(policies=httpx.Response(404, json={"message": "gone"})))
    rows = _collector().collect("Proj/myrepo")
    bp = next(r for r in rows if r.evidence_key == "azure-branch-policies").data
    assert all(v is False for v in bp["posture"].values()), bp["posture"]


def test_pipelines_api_returning_404_does_not_raise_for_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """404 is an expected answer for a project without pipelines; only other codes raise."""

    _install(monkeypatch, _routed(pipelines=httpx.Response(404, json={"message": "gone"})))
    rows = _collector().collect("Proj/myrepo")
    gov = next(r for r in rows if r.evidence_key == "azure-pipeline-governance").data
    assert gov["posture_support"]["pipelines_api_reachable"] is False


def test_environments_api_failing_with_a_server_error_is_still_recorded_as_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 5xx is outside the known-degraded set, and must not read as 'no environments exist'."""

    _install(monkeypatch, _routed(environments=httpx.Response(503, json={"message": "down"})))
    rows = _collector().collect("Proj/myrepo")
    gov = next(r for r in rows if r.evidence_key == "azure-pipeline-governance").data
    assert gov["posture_support"]["environments_api_reachable"] is False
    assert gov["posture"]["approvals_required"] is False


@pytest.mark.parametrize("status", [401, 403, 404, 422])
def test_unreachable_environments_api_is_recorded_as_unreachable(status: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """The governance posture must admit it could not see environments, not assume the best."""

    _install(monkeypatch, _routed(environments=httpx.Response(status, json={"message": "no"})))
    rows = _collector().collect("Proj/myrepo")
    gov = next(r for r in rows if r.evidence_key == "azure-pipeline-governance").data
    assert gov["posture_support"]["environments_api_reachable"] is False


def test_environments_payload_of_the_wrong_shape_is_treated_as_no_environments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP 200 with `value` as an object rather than a list must not be read as data."""

    _install(monkeypatch, _routed(environments=httpx.Response(200, json={"value": {"id": 1}})))
    rows = _collector().collect("Proj/myrepo")
    gov = next(r for r in rows if r.evidence_key == "azure-pipeline-governance").data
    assert gov["posture"]["approvals_required"] is False


def test_no_service_connections_leaves_the_key_out_entirely(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty list would read as 'we looked and there are none'; absence is the honest shape."""

    _install(monkeypatch, _routed(endpoints=httpx.Response(200, json={"value": []})))
    rows = _collector().collect("Proj/myrepo")
    gov = next(r for r in rows if r.evidence_key == "azure-pipeline-governance").data
    assert "service_connections" not in gov


# --------------------------------------------------------------------------- #
# Responses the code was not written against
# --------------------------------------------------------------------------- #


def test_repository_without_an_id_is_rejected_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every later call keys off the repo id; continuing without one would query nothing."""

    _install(monkeypatch, _routed(repositories=httpx.Response(200, json={"value": [{"name": "myrepo"}]})))
    collector = _collector()
    with pytest.raises(ValueError, match="missing id"):
        collector.collect("Proj/myrepo")


def test_a_json_array_where_an_object_was_expected_becomes_a_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy or wrong API version can answer with valid JSON of the wrong shape.

    That must surface as a collection failure the caller can report, not as an
    ``AttributeError`` escaping from inside the collector.
    """

    _install(monkeypatch, _routed(repositories=httpx.Response(200, json=[])))
    collector = _collector()
    with pytest.raises(CollectionNetworkError):
        collector.collect("Proj/myrepo")
