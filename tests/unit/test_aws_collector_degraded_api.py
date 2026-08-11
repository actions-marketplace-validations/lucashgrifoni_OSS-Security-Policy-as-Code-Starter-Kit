"""What the AWS collector does when boto3 fails or answers with the wrong shape.

The not-found cases live in ``test_aws_collector_not_found.py``. This file is the rest of the
failure surface: an IAM principal without the read permission, a throttled account, a
transport failure that never reached AWS at all, and API payloads whose nested pieces are not
the dicts the code expects.

The classification is the point. ``AccessDenied`` has to reach the operator as a permission
problem -- something they fix by widening a policy -- while a throttle is a retry and a
transport failure is neither. Collapsing all three into one error tells the operator to go
looking in the wrong place, and this collector is often the first thing run in an unfamiliar
account.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors import aws_collector as aws
from oss_policy_kit.infrastructure.collectors.aws_collector import (
    _ENV_CODEBUILD,
    _ENV_CODEPIPELINE,
    AWSEvidenceCollector,
)


def _client_error(code: str, operation: str = "BatchGetProjects") -> Exception:
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": code, "Message": "m"}}, operation)


def _transport_error() -> Exception:
    from botocore.exceptions import BotoCoreError

    return BotoCoreError()


class _FailingClient:
    """A boto3 client whose every call raises the exception it was built with."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def __getattr__(self, _name: str) -> Any:
        def _call(*_a: Any, **_k: Any) -> Any:
            raise self._exc

        return _call


class _EmptyClient:
    """A boto3 client that succeeds but returns nothing useful."""

    def __getattr__(self, _name: str) -> Any:
        return lambda *_a, **_k: {}


def _install_session(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    import boto3

    class _Session:
        def __init__(self, **_k: Any) -> None: ...

        def client(self, _name: str) -> Any:
            return client

    monkeypatch.setattr(boto3, "Session", _Session)


def _codebuild_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv(_ENV_CODEBUILD, "proj")
    monkeypatch.delenv(_ENV_CODEPIPELINE, raising=False)


def _codepipeline_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv(_ENV_CODEBUILD, raising=False)
    monkeypatch.setenv(_ENV_CODEPIPELINE, "pipe")


# --------------------------------------------------------------------------- #
# Error-code extraction
# --------------------------------------------------------------------------- #


def test_an_exception_without_a_usable_response_yields_no_code() -> None:
    """Not every boto exception carries the dict shape; asking must not raise."""

    assert aws._client_error_code(RuntimeError("plain")) == ""
    assert aws._client_error_code(type("E", (), {"response": "not-a-dict"})()) == ""
    assert aws._client_error_code(type("E", (), {"response": {"Error": "not-a-dict"}})()) == ""


def test_a_client_error_code_is_read_from_the_response() -> None:
    assert aws._client_error_code(_client_error("AccessDeniedException")) == "AccessDeniedException"


# --------------------------------------------------------------------------- #
# Error classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "code",
    ["AccessDeniedException", "UnauthorizedOperation", "InvalidClientTokenId", "AuthFailure"],
)
def test_a_denied_call_is_a_permission_problem(code: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The operator fixes this by widening an IAM policy, so say so."""

    _codebuild_only(monkeypatch)
    _install_session(monkeypatch, _FailingClient(_client_error(code)))
    with pytest.raises(CollectionPermissionError):
        AWSEvidenceCollector().collect("")


@pytest.mark.parametrize("code", ["ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded"])
def test_a_throttled_call_is_a_rate_limit_not_a_permission_problem(code: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _codebuild_only(monkeypatch)
    _install_session(monkeypatch, _FailingClient(_client_error(code)))
    with pytest.raises(RateLimitError):
        AWSEvidenceCollector().collect("")


def test_an_unrecognised_api_error_is_reported_as_a_collection_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _codebuild_only(monkeypatch)
    _install_session(monkeypatch, _FailingClient(_client_error("SomethingNew")))
    with pytest.raises(CollectionNetworkError):
        AWSEvidenceCollector().collect("")


@pytest.mark.parametrize("setup", [_codebuild_only, _codepipeline_only])
def test_a_transport_failure_never_reached_aws_and_says_so(setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """BotoCoreError means the call did not get an answer; that is not an API error."""

    setup(monkeypatch)
    _install_session(monkeypatch, _FailingClient(_transport_error()))
    with pytest.raises(CollectionNetworkError, match="transport"):
        AWSEvidenceCollector().collect("")


def test_an_unexpected_exception_still_becomes_a_collection_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anything boto3 raises that we did not anticipate must not escape raw."""

    _codebuild_only(monkeypatch)
    _install_session(monkeypatch, _FailingClient(TypeError("unexpected")))
    with pytest.raises(CollectionNetworkError):
        AWSEvidenceCollector().collect("")


# --------------------------------------------------------------------------- #
# Responses that arrive but carry nothing
# --------------------------------------------------------------------------- #


def test_an_empty_pipeline_response_is_a_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 200 with no pipeline body must not be read as a pipeline with no protections."""

    _codepipeline_only(monkeypatch)
    _install_session(monkeypatch, _EmptyClient())
    with pytest.raises(ValueError, match="not found"):
        AWSEvidenceCollector().collect("")


def test_a_missing_codebuild_project_is_named_in_the_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """ResourceNotFound is the operator's typo, not a permission or transport problem."""

    _codebuild_only(monkeypatch)
    _install_session(monkeypatch, _FailingClient(_client_error("ResourceNotFoundException")))
    with pytest.raises(ValueError, match="proj"):
        AWSEvidenceCollector().collect("")


def test_a_transport_failure_while_opening_the_client_is_still_a_collection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """boto3 can fail before any API call -- bad region, unresolvable endpoint, no creds."""

    import boto3

    class _Session:
        def __init__(self, **_k: Any) -> None: ...

        def client(self, _name: str) -> Any:
            raise _transport_error()

    _codebuild_only(monkeypatch)
    monkeypatch.setattr(boto3, "Session", _Session)
    with pytest.raises(CollectionNetworkError, match="transport"):
        AWSEvidenceCollector().collect("")


# --------------------------------------------------------------------------- #
# Loosely typed nested payloads
# --------------------------------------------------------------------------- #


def test_a_pipeline_stage_action_that_is_not_an_object_is_skipped() -> None:
    stages = [
        {"actions": ["approval", {"actionTypeId": {"category": "Approval", "provider": "Manual"}}]},
        {"actions": []},
    ]
    assert aws._manual_approval_before_production(stages) is True


def test_an_approval_only_in_the_final_stage_does_not_count() -> None:
    """The gate has to be *before* production, or it gates nothing."""

    stages = [
        {"actions": [{"actionTypeId": {"category": "Build", "provider": "CodeBuild"}}]},
        {"actions": [{"actionTypeId": {"category": "Approval", "provider": "Manual"}}]},
    ]
    assert aws._manual_approval_before_production(stages) is False


def test_a_single_stage_pipeline_has_nothing_before_production() -> None:
    assert aws._manual_approval_before_production([{"actions": []}]) is False


def test_a_codebuild_env_var_that_is_not_an_object_is_skipped() -> None:
    """One malformed entry must not hide a real plaintext secret beside it."""

    project = {
        "environment": {
            "environmentVariables": ["PLAINTEXT", {"name": "TOKEN", "type": "PLAINTEXT"}],
        }
    }
    assert aws._codebuild_posture(project)["no_plaintext_credentials_in_project_config"] is False


def test_a_codebuild_project_using_only_parameter_store_is_clean() -> None:
    project = {
        "environment": {
            "environmentVariables": [{"name": "TOKEN", "type": "PARAMETER_STORE"}],
        }
    }
    assert aws._codebuild_posture(project)["no_plaintext_credentials_in_project_config"] is True
