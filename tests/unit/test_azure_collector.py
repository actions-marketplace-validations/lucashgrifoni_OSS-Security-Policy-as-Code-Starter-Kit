"""Unit tests for :mod:`oss_policy_kit.infrastructure.collectors.azure_collector`."""

from __future__ import annotations

import httpx
import pytest

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors.azure_collector import AzureDevOpsEvidenceCollector

_POLICY_MINIMUM_REVIEWERS = "fa4e907d-c16f-4ac8-9af7-9a14fae485e1"


def _azure_handler(request: httpx.Request) -> httpx.Response:
    u = str(request.url)
    if "git/repositories" in u:
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "repo-guid-1",
                        "name": "myrepo",
                        "defaultBranch": "refs/heads/main",
                    }
                ]
            },
        )
    if "policy/configurations" in u:
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "type": {"id": _POLICY_MINIMUM_REVIEWERS},
                        "settings": {
                            "scope": [
                                {
                                    "repositoryId": "repo-guid-1",
                                    "refName": "refs/heads/main",
                                    "matchKind": "Exact",
                                }
                            ],
                            "minimumApproverCount": 1,
                        },
                    }
                ]
            },
        )
    if "pipelines" in u and "_apis/pipelines" in u:
        return httpx.Response(200, json={"value": [{"id": 1, "name": "ci"}]})
    if "distributedtask/environments" in u:
        return httpx.Response(200, json={"value": [{"id": 1, "name": "prod"}]})
    if "_apis/check/configurations" in u:
        return httpx.Response(
            200,
            json={"value": [{"type": {"name": "Approval"}, "id": 1, "settings": {}}]},
        )
    if "serviceendpoint/endpoints" in u:
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "name": "fed-conn",
                        "authorization": {"scheme": "WorkloadIdentityFederation"},
                    }
                ]
            },
        )
    return httpx.Response(404, json={"message": "unexpected"})


@pytest.fixture
def mock_azure_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = httpx.MockTransport(_azure_handler)
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)


@pytest.mark.usefixtures("mock_azure_transport")
def test_collect_branch_policies_and_pipeline_governance() -> None:
    rows = AzureDevOpsEvidenceCollector(organization="contoso", personal_access_token="pat").collect("Proj/myrepo")
    keys = {r.evidence_key for r in rows}
    assert keys == {"azure-branch-policies", "azure-pipeline-governance"}
    bp = next(r for r in rows if r.evidence_key == "azure-branch-policies").data
    assert bp["schema_version"] == "azure-branch-policies/v1"
    assert bp["posture"]["minimum_reviewers_enabled"] is True
    gov = next(r for r in rows if r.evidence_key == "azure-pipeline-governance").data
    sup = gov["posture_support"]
    assert sup["pipelines_api_reachable"] is True
    assert sup["environments_api_reachable"] is True
    assert sup["service_endpoints_api_verified"] is True
    assert sup["environment_approval_checks_observable"] is True
    assert gov["posture"]["approvals_required"] is True
    assert gov["posture"]["federated_identity_preferred"] is True


def test_permission_error_on_403(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(403, json={"message": "nope"}))
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        return real_client(
            base_url=kwargs.get("base_url"),
            headers=kwargs.get("headers"),
            timeout=kwargs.get("timeout"),
            transport=transport,
        )

    monkeypatch.setattr(httpx, "Client", _client)
    with pytest.raises(CollectionPermissionError):
        AzureDevOpsEvidenceCollector(organization="o", personal_access_token="x").collect("P/r")


def test_rate_limit_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(429, headers={"retry-after": "10"}))
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        return real_client(
            base_url=kwargs.get("base_url"),
            headers=kwargs.get("headers"),
            timeout=kwargs.get("timeout"),
            transport=transport,
        )

    monkeypatch.setattr(httpx, "Client", _client)
    with pytest.raises(RateLimitError):
        AzureDevOpsEvidenceCollector(organization="o", personal_access_token="x").collect("P/r")


def test_collect_wraps_network_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_kwargs: object) -> httpx.Client:
        raise httpx.ConnectError("boom", request=httpx.Request("GET", "https://dev.azure.com/o/p/_apis"))

    monkeypatch.setattr(httpx, "Client", boom)
    with pytest.raises(CollectionNetworkError):
        AzureDevOpsEvidenceCollector(organization="o", personal_access_token="x").collect("P/r")


def _azure_pat_only_handler(request: httpx.Request) -> httpx.Response:
    """Happy-path repo/policy/pipeline/env responses, but every service connection is PAT-only.

    This mirrors a real Azure DevOps org that has not adopted workload identity federation yet.
    The collector must then mark ``service_connection_restricted`` and ``federated_identity_preferred``
    both false, so release-hardening evaluators can flag the remaining governance gap.
    """

    u = str(request.url)
    if "git/repositories" in u:
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "repo-guid-1",
                        "name": "myrepo",
                        "defaultBranch": "refs/heads/main",
                    }
                ]
            },
        )
    if "policy/configurations" in u:
        return httpx.Response(200, json={"value": []})
    if "_apis/pipelines" in u:
        return httpx.Response(200, json={"value": []})
    if "distributedtask/environments" in u:
        return httpx.Response(200, json={"value": []})
    if "serviceendpoint/endpoints" in u:
        return httpx.Response(
            200,
            json={
                "value": [
                    {"name": "legacy-pat", "authorization": {"scheme": "UsernamePassword"}},
                    {"name": "legacy-token", "authorization": {"scheme": "Token"}},
                ]
            },
        )
    return httpx.Response(404, json={"message": "unexpected"})


def test_service_connections_pat_only_leaves_governance_false(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = httpx.MockTransport(_azure_pat_only_handler)
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)

    rows = AzureDevOpsEvidenceCollector(organization="contoso", personal_access_token="pat").collect("Proj/myrepo")
    gov = next(r for r in rows if r.evidence_key == "azure-pipeline-governance").data
    assert gov["posture"]["service_connection_restricted"] is False
    assert gov["posture"]["federated_identity_preferred"] is False
    assert gov["posture_support"]["service_endpoints_api_verified"] is True
    # Service connections are still listed so operators can see which endpoints need uplift.
    assert gov["service_connections"], "PAT/UsernamePassword endpoints should still be listed for triage"


def test_404_on_repositories_raises_permission_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 404 on the repositories endpoint is treated as "wrong project or PAT scope", not a silent pass."""

    transport = httpx.MockTransport(lambda r: httpx.Response(404, json={"message": "no project"}))
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        return real_client(
            base_url=kwargs.get("base_url"),
            headers=kwargs.get("headers"),
            timeout=kwargs.get("timeout"),
            transport=transport,
        )

    monkeypatch.setattr(httpx, "Client", _client)
    with pytest.raises(CollectionPermissionError):
        AzureDevOpsEvidenceCollector(organization="o", personal_access_token="x").collect("P/r")
