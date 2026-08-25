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

    External plugins must not override built-in control IDs. The loader does not raise
    when one tries -- an exception during registry construction would take the whole kit
    down for one plugin. It keeps the existing evaluator, records the clash in
    ``PLUGIN_LOAD_ERRORS``, and carries on; ``evaluate --verbose`` prints what it recorded,
    with ``builtin-precedence`` and ``plugin-collision`` telling apart a clash with a
    bundled control from a clash with another plugin.

    A plugin that expects an exception here will not get one. Check ``plugin_load_errors()``
    for the entry-point's own name to find out whether it is actually active.
    """

    def __call__(self, ctx: EvalContext) -> EvalOutcome:  # noqa: D102
        ...
