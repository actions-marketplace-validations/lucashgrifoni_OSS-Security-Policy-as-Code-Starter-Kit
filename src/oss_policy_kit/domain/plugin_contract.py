"""Structural typing contract for third-party evaluator plugins."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from oss_policy_kit.application.evaluators import EvalContext
    from oss_policy_kit.domain.models import EvalOutcome


class EvaluatorPlugin(Protocol):
    """Protocol for third-party evaluator plugins.

    Register via pyproject.toml entry-point group ``oss_policy_kit.evaluators``.
    The entry-point **name** must be a valid control ID string. The loaded callable
    must accept :class:`~oss_policy_kit.application.evaluators.EvalContext` and
    return :class:`~oss_policy_kit.domain.models.EvalOutcome`.

    External plugins must not override built-in control IDs (the loader raises at
    registration time if a duplicate name is registered).
    """

    def __call__(self, ctx: EvalContext) -> EvalOutcome:  # noqa: D102
        ...
