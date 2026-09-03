"""Report-clock helpers.

Centralises the ``generated_at`` timestamp used by ``evaluation-report.json``
and ``evaluation-batch.json`` so reproducible builds can override the value
through the standard ``SOURCE_DATE_EPOCH`` environment variable.

Behaviour:

- When ``SOURCE_DATE_EPOCH`` is set to a non-negative integer (seconds since
  the UNIX epoch), :func:`report_generated_at` returns the corresponding UTC
  timestamp in ISO-8601 form, second-truncated. This mirrors the
  reproducible-builds convention used by Debian, NixOS, RPM, and the Python
  ``build`` backend.
- When ``SOURCE_DATE_EPOCH`` is missing, empty, or malformed, the function
  falls back to ``datetime.now(UTC)`` second-truncated, preserving the
  pre-existing behaviour.

Keeping the helper in a dedicated module avoids importing the rest of the
evaluator stack just to read a timestamp.
"""

from __future__ import annotations

from oss_policy_kit.domain.models import utc_now


def report_generated_at() -> str:
    """Return the ``generated_at`` ISO-8601 UTC timestamp for a report.

    Honours ``SOURCE_DATE_EPOCH`` for reproducible builds (the env parsing lives
    in :func:`oss_policy_kit.domain.models.utc_now`, shared with the evaluation
    freshness/expiry clock reads); otherwise uses the current time. Microseconds
    are always stripped so the value is stable across re-runs in the same second.
    """

    return utc_now().replace(microsecond=0).isoformat()
