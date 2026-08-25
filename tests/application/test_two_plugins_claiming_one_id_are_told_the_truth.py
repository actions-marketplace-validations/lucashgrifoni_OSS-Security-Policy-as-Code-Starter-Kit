"""A plugin that lost an ID to another plugin must not be told a built-in took it.

The loader tested `ep.name in EVALUATOR_REGISTRY` -- but an ID a plugin registered a
moment ago is in that registry too, so the second plugin claiming it was reported with
the one message the branch carries.

Measured with three entry points, two of them claiming `ACME-CUSTOM-001` and one claiming
the real built-in `GOV-SEC-001`:

    ACME-CUSTOM-001  builtin-precedence  a built-in control already owns this ID
    GOV-SEC-001      builtin-precedence  a built-in control already owns this ID

Two different problems, one row. The first line is false -- no built-in owns
`ACME-CUSTOM-001` -- and it sends the operator looking through the bundled catalog for a
control that is not there, instead of at the two plugins of theirs that collide. Nothing
said which one won, and the winner is decided by entry-point discovery order.

The behaviour is unchanged on purpose: the first registration keeps the ID. Dropping both
would silently disable a control the operator expects. What was broken is the diagnostic.
"""

from __future__ import annotations

import importlib.metadata
from collections.abc import Iterator
from typing import Any

import pytest

from oss_policy_kit.application import evaluators as ev

#: A control the bundled catalog really owns, so the built-in branch is exercised against
#: a real ID rather than a name invented for the test.
_BUILTIN = "GOV-SEC-001"
_CUSTOM = "ACME-CUSTOM-001"

_ALPHA = "acme_alpha.checks:evaluate"
_BETA = "acme_beta.checks:evaluate"


class _FakeEP:
    """The three attributes the loader reads off a real ``EntryPoint``."""

    def __init__(self, name: str, value: str, loader: Any) -> None:
        self.name = name
        self.value = value
        self._loader = loader

    def load(self) -> Any:
        return self._loader()


class _FakeEPs:
    def __init__(self, eps: list[_FakeEP]) -> None:
        self._eps = eps

    def select(self, *, group: str) -> list[_FakeEP]:
        assert group == "oss_policy_kit.evaluators"
        return self._eps


@pytest.fixture
def restored() -> Iterator[None]:
    """The registry is module state for the whole session; put it back either way."""

    before_errors = list(ev.PLUGIN_LOAD_ERRORS)
    before_keys = set(ev.EVALUATOR_REGISTRY)
    before_plugin_ids = set(ev.PLUGIN_CONTROL_IDS)
    yield
    ev.PLUGIN_LOAD_ERRORS[:] = before_errors
    ev.PLUGIN_CONTROL_IDS.clear()
    ev.PLUGIN_CONTROL_IDS.update(before_plugin_ids)
    for key in set(ev.EVALUATOR_REGISTRY) - before_keys:
        ev.EVALUATOR_REGISTRY.pop(key, None)


def _load(monkeypatch: pytest.MonkeyPatch, eps: list[_FakeEP]) -> dict[str, dict[str, str]]:
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda: _FakeEPs(eps))
    ev._load_external_evaluators()
    return {entry["name"]: entry for entry in ev.plugin_load_errors()}


def _alpha(_ctx: object) -> str:
    return "alpha"


def _beta(_ctx: object) -> str:
    return "beta"


def test_a_plugin_that_lost_to_another_plugin_is_told_so(monkeypatch: pytest.MonkeyPatch, restored: None) -> None:
    errors = _load(
        monkeypatch,
        [
            _FakeEP(_CUSTOM, _ALPHA, lambda: _alpha),
            _FakeEP(_CUSTOM, _BETA, lambda: _beta),
        ],
    )

    entry = errors[_CUSTOM]
    assert entry["kind"] == "plugin-collision", (
        f"a plugin-vs-plugin clash was reported as {entry['kind']!r}. There is no built-in "
        f"{_CUSTOM}, so the operator is sent looking through the bundled catalog for a "
        "control that does not exist."
    )
    assert "built-in" not in entry["detail"]
    assert _ALPHA in entry["detail"], (
        f"the row does not name the entry point that kept the ID: {entry['detail']!r}. "
        "Which plugin wins is decided by discovery order, so it has to be stated."
    )


def test_a_plugin_that_lost_to_a_built_in_is_still_told_that(monkeypatch: pytest.MonkeyPatch, restored: None) -> None:
    """The other half. One message for both problems is what made the first one false."""

    errors = _load(monkeypatch, [_FakeEP(_BUILTIN, _BETA, lambda: _beta)])

    assert errors[_BUILTIN]["kind"] == "builtin-precedence"
    assert errors[_BUILTIN]["detail"] == "a built-in control already owns this ID"


def test_the_two_clashes_are_distinguishable_in_one_run(monkeypatch: pytest.MonkeyPatch, restored: None) -> None:
    """Both kinds, side by side, which is how an operator actually meets them."""

    errors = _load(
        monkeypatch,
        [
            _FakeEP(_CUSTOM, _ALPHA, lambda: _alpha),
            _FakeEP(_CUSTOM, _BETA, lambda: _beta),
            _FakeEP(_BUILTIN, _BETA, lambda: _beta),
        ],
    )

    assert {name: entry["kind"] for name, entry in errors.items()} == {
        _CUSTOM: "plugin-collision",
        _BUILTIN: "builtin-precedence",
    }


def test_the_first_registration_still_keeps_the_id(monkeypatch: pytest.MonkeyPatch, restored: None) -> None:
    """Unchanged behaviour, asserted.

    Dropping both sides of a collision would silently disable a control the operator is
    counting on. Only the diagnostic was wrong.
    """

    _load(
        monkeypatch,
        [
            _FakeEP(_CUSTOM, _ALPHA, lambda: _alpha),
            _FakeEP(_CUSTOM, _BETA, lambda: _beta),
        ],
    )

    assert ev.EVALUATOR_REGISTRY[_CUSTOM] is _alpha
    assert _CUSTOM in ev.PLUGIN_CONTROL_IDS


def test_a_plugin_that_failed_to_load_does_not_reserve_the_id(monkeypatch: pytest.MonkeyPatch, restored: None) -> None:
    """It registered nothing, so the next claim on the ID is not a collision with it."""

    def _explode() -> Any:
        raise RuntimeError("import blew up")

    errors = _load(
        monkeypatch,
        [
            _FakeEP(_CUSTOM, _ALPHA, _explode),
            _FakeEP(_CUSTOM, _BETA, lambda: _beta),
        ],
    )

    assert errors[_CUSTOM]["kind"] == "load", (
        f"the working plugin was refused the ID because a broken one named it first. Recorded: {errors[_CUSTOM]!r}"
    )
    assert ev.EVALUATOR_REGISTRY[_CUSTOM] is _beta
