"""Whether Azure approval checks were *observed* or merely *not seen*.

`_azure_environment_approvals` returns two booleans, and the whole point of the pair is the
difference between them: `approval_observable` says the API let us look at all, and
`approval_found` says what we saw. Collapsing the two -- reporting "no approvals" when the
token simply could not read the checks API -- turns a permissions gap into a compliance
statement, which is the one mistake this collector must not make.

Those branches had not been executed. Neither had the API-version fallback: Azure DevOps
answers 404 for a preview version an organisation has not enabled, and the reader has to try
the next one rather than conclude the environment has no approvals.

The client is faked rather than mocked at the HTTP layer, because what is under test is the
status-to-meaning mapping, not request construction.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.infrastructure.collectors import azure_collector as az


class _Reply:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Answers each successive GET from a queue; the last reply repeats."""

    def __init__(self, *replies: _Reply) -> None:
        self._replies = list(replies)
        self.urls: list[str] = []

    def get(self, url: str) -> _Reply:
        self.urls.append(url)
        return self._replies[min(len(self.urls) - 1, len(self._replies) - 1)]


def _approval_cfg() -> dict[str, Any]:
    return {"type": {"name": "Approval"}}


# --------------------------------------------------------------------------- #
# reading one environment's checks
# --------------------------------------------------------------------------- #


def test_an_approval_check_is_recognized() -> None:
    client = _FakeClient(_Reply(200, {"value": [_approval_cfg()]}))

    assert az._environment_has_approval_check(client, "proj", "1") is True


def test_a_non_approval_check_is_not_mistaken_for_one() -> None:
    """An environment can carry other gates; only an approval satisfies the control."""

    client = _FakeClient(_Reply(200, {"value": [{"type": {"name": "ExclusiveLock"}}]}))

    assert az._environment_has_approval_check(client, "proj", "1") is False


def test_an_environment_with_no_checks_answers_false_not_unknown() -> None:
    """An empty list is a real answer: we looked, and there is nothing there."""

    client = _FakeClient(_Reply(200, {"value": []}))

    assert az._environment_has_approval_check(client, "proj", "1") is False


@pytest.mark.parametrize("body", [{"value": "not-a-list"}, {"value": None}, {}])
def test_a_response_without_a_usable_list_answers_false(body: dict[str, Any]) -> None:
    client = _FakeClient(_Reply(200, body))

    assert az._environment_has_approval_check(client, "proj", "1") is False


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_checks_api_answers_unknown_not_false(status: int) -> None:
    """None is the "we could not look" signal, and it must not be conflated with False."""

    client = _FakeClient(_Reply(status))

    assert az._environment_has_approval_check(client, "proj", "1") is None


@pytest.mark.parametrize("status", [500, 502, 400])
def test_any_other_failure_also_answers_unknown(status: int) -> None:
    client = _FakeClient(_Reply(status))

    assert az._environment_has_approval_check(client, "proj", "1") is None


def test_a_404_falls_through_to_the_older_api_version() -> None:
    """404 means that preview version is not enabled here, not that there are no approvals."""

    client = _FakeClient(_Reply(404), _Reply(200, {"value": [_approval_cfg()]}))

    result = az._environment_has_approval_check(client, "proj", "1")

    assert result is True
    assert len(client.urls) == 2
    assert "7.2-preview.1" in client.urls[0]
    assert "7.1-preview.1" in client.urls[1]


def test_a_404_from_every_version_answers_unknown() -> None:
    """Exhausting the fallbacks means the API never answered, which is not "no approvals"."""

    client = _FakeClient(_Reply(404))

    assert az._environment_has_approval_check(client, "proj", "1") is None


# --------------------------------------------------------------------------- #
# rolling it up across environments
# --------------------------------------------------------------------------- #


def test_environments_that_could_not_be_listed_are_not_observable() -> None:
    """A non-200 on the environments call means nothing downstream was observed."""

    observable, found = az._azure_environment_approvals(_FakeClient(), "proj", [], 403)

    assert (observable, found) == (False, False)


def test_an_approval_on_any_environment_is_found() -> None:
    client = _FakeClient(_Reply(200, {"value": [_approval_cfg()]}))

    observable, found = az._azure_environment_approvals(client, "proj", [{"id": 1}], 200)

    assert (observable, found) == (True, True)


def test_environments_that_all_answer_cleanly_with_none_are_observable_and_empty() -> None:
    """This is the honest negative: we looked at every environment and saw no approval."""

    client = _FakeClient(_Reply(200, {"value": []}))

    observable, found = az._azure_environment_approvals(client, "proj", [{"id": 1}, {"id": 2}], 200)

    assert (observable, found) == (True, False)


def test_one_unreadable_environment_makes_the_whole_answer_unobservable() -> None:
    """The distinction this module exists for.

    If any environment's checks could not be read, the roll-up cannot claim the project has
    no approvals -- the unread one may well have had one. Reporting False/False here would
    turn a permissions gap into a compliance statement.
    """

    client = _FakeClient(_Reply(403))

    observable, found = az._azure_environment_approvals(client, "proj", [{"id": 1}], 200)

    assert observable is False


def test_an_approval_already_seen_survives_a_later_unreadable_environment() -> None:
    """What was observed stays observed; only the observability flag drops."""

    client = _FakeClient(_Reply(200, {"value": [_approval_cfg()]}), _Reply(403))

    observable, found = az._azure_environment_approvals(client, "proj", [{"id": 1}, {"id": 2}], 200)

    assert observable is False
    assert found is True


def test_environments_without_an_id_are_skipped_not_fatal() -> None:
    """A malformed entry must not stop the remaining environments being sampled."""

    client = _FakeClient(_Reply(200, {"value": [_approval_cfg()]}))

    observable, found = az._azure_environment_approvals(client, "proj", [{"name": "no-id"}, {"id": 2}], 200)

    assert (observable, found) == (True, True)


def test_no_environments_at_all_is_observable_and_empty() -> None:
    observable, found = az._azure_environment_approvals(_FakeClient(), "proj", [], 200)

    assert (observable, found) == (True, False)


def test_the_sample_is_capped_so_a_large_project_does_not_walk_every_environment() -> None:
    """The roll-up samples; an unbounded walk would make collection time unpredictable."""

    client = _FakeClient(_Reply(200, {"value": []}))

    az._azure_environment_approvals(client, "proj", [{"id": i} for i in range(60)], 200)

    assert len(client.urls) == 25
