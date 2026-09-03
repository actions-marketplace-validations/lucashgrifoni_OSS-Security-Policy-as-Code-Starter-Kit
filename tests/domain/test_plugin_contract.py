"""The published shape of a third-party evaluator plugin.

`EvaluatorPlugin` is not used by the kit at runtime -- it is a `Protocol`, so it exists for type
checkers and for the people writing plugins against it. That is exactly why it is worth a test:
nothing else in the codebase imports it, so it can drift out of step with the loader that
actually accepts plugins and nobody would notice until an adopter's plugin stopped loading.

What the tests hold is the agreement itself: one argument in, an `EvalOutcome` out, and the same
signature the kit's own evaluators already satisfy. If a built-in evaluator would no longer
match the protocol, the protocol is describing something the kit does not do.
"""

from __future__ import annotations

import inspect
from typing import Protocol, get_type_hints

from oss_policy_kit.application.evaluators import cicd
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import EvalOutcome
from oss_policy_kit.domain.plugin_contract import EvaluatorPlugin


def test_the_contract_is_a_protocol_and_not_a_base_class() -> None:
    """Plugins conform structurally; requiring them to subclass would be a coupling."""

    assert issubclass(EvaluatorPlugin, Protocol)  # type: ignore[arg-type]


def test_the_contract_asks_for_one_argument_and_returns_an_outcome() -> None:
    """The names are supplied here because the module imports them under `TYPE_CHECKING` only.

    That is deliberate -- the contract must not drag the application layer into anything that
    imports it -- and it means the annotations are forward references that only a type checker
    resolves on its own.
    """

    hints = get_type_hints(
        EvaluatorPlugin.__call__,
        localns={"EvalContext": EvalContext, "EvalOutcome": EvalOutcome},
    )

    assert hints["ctx"] is EvalContext
    assert hints["return"] is EvalOutcome


def test_a_built_in_evaluator_already_satisfies_it() -> None:
    """If the kit's own evaluators would not load as plugins, the contract is wrong."""

    signature = inspect.signature(cicd.eval_ci_wf_005)
    (parameter,) = signature.parameters.values()

    assert parameter.annotation in (EvalContext, "EvalContext")
    assert signature.return_annotation in (EvalOutcome, "EvalOutcome")


def test_the_contract_documents_where_plugins_are_registered() -> None:
    """The entry-point group is the one detail a plugin author cannot guess."""

    assert "oss_policy_kit.evaluators" in (EvaluatorPlugin.__doc__ or "")
