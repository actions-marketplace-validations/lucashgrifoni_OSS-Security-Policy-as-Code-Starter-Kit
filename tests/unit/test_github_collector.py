"""Unit tests for :mod:`oss_policy_kit.infrastructure.collectors.github_collector`."""

from __future__ import annotations

import httpx
import pytest

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors.github_collector import GitHubEvidenceCollector


def _bp_json() -> dict:
    return {
        "required_pull_request_reviews": {"dismiss_stale_reviews": True},
        "required_status_checks": {"strict": True, "contexts": ["ci"]},
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
    }


def _rulesets_json() -> list:
    return [
        {
            "enforcement": "active",
            "rules": [
                {"type": "pull_request", "parameters": {"require_code_owner_review": True}},
                {"type": "required_status_checks"},
                {"type": "non_fast_forward"},
            ],
        }
    ]


def _repo_json() -> dict:
    return {
        "default_branch": "main",
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
            "secret_scanning_validity_checks": {"status": "enabled"},
        },
    }


def _env_json() -> dict:
    return {
        "environments": [
            {
                "name": "production",
                "protection_rules": [
                    {"type": "required_reviewers", "parameters": {"reviewers": [{"type": "User"}]}},
                    {"type": "wait_timer", "parameters": {"wait_timer": 5}},
                ],
            }
        ]
    }


def _github_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/repos/o/r":
        return httpx.Response(200, json=_repo_json())
    if path == "/repos/o/r/branches/main/protection":
        return httpx.Response(200, json=_bp_json())
    if path == "/repos/o/r/rulesets":
        return httpx.Response(200, json=_rulesets_json())
    if path == "/repos/o/r/environments":
        return httpx.Response(200, json=_env_json())
    return httpx.Response(404, json={"message": "unexpected"})


@pytest.fixture
def mock_github_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = httpx.MockTransport(_github_handler)
    real_client = httpx.Client

    def _client(**kwargs: object) -> httpx.Client:
        merged = dict(kwargs)
        merged["transport"] = transport
        return real_client(**merged)

    monkeypatch.setattr(httpx, "Client", _client)


@pytest.mark.usefixtures("mock_github_transport")
def test_collect_all_four_evidence_types() -> None:
    rows = GitHubEvidenceCollector("test-token").collect("o/r")
    keys = {r.evidence_key for r in rows}
    assert keys == {"branch-protection", "github-rulesets", "github-secret-scanning", "github-environment-protection"}
    bp = next(r for r in rows if r.evidence_key == "branch-protection").data
    assert bp["schema_version"] == "branch-protection/v1"
    assert bp["protections"]["require_pull_request_reviews"] is True
    assert bp["collection"]["evidence_collection_method"] == "live"
    assert bp["collection"]["mode"] == "api"
    assert bp["attested_by"] == "github-api-collection"


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
        GitHubEvidenceCollector("x").collect("o/r")


def test_rate_limit_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(429, headers={"retry-after": "42"}))
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
        GitHubEvidenceCollector("x").collect("o/r")


@pytest.mark.usefixtures("mock_github_transport")
def test_collect_does_not_write_files_by_itself(tmp_path: object) -> None:
    rows = GitHubEvidenceCollector("tok").collect("o/r")
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    assert len(rows) == 4
    assert not any(ev.glob("*.json"))


def test_collect_wraps_network_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_kwargs: object) -> httpx.Client:
        raise httpx.ConnectError("boom", request=httpx.Request("GET", "https://api.github.com/repos/o/r"))

    monkeypatch.setattr(httpx, "Client", boom)
    with pytest.raises(CollectionNetworkError):
        GitHubEvidenceCollector("tok").collect("o/r")
