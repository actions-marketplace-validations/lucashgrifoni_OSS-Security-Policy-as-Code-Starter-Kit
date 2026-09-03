"""Guard: no test reads the real wall clock.

``tests/conftest.py`` pins ``SOURCE_DATE_EPOCH`` so the suite is immune to calendar rot, and
the kit routes every outcome-affecting clock read through ``domain.models.utc_now``. A test that
calls ``datetime.now()`` instead compares a *real* timestamp against the product's *pinned* one,
so the gap between them grows every day until the test silently flips.

That is not hypothetical. ``test_prov_verify_061_fail_when_verification_stale`` built its "stale"
evidence as ``datetime.now(UTC) - timedelta(days=120)`` against a 90-day window; once real time
passed the pinned epoch by 30 days (2026-07-15) the evaluator saw the date as only 74 days old,
returned PASS, and the suite went red on every branch until someone looked. The same file's
``recent`` fixture had the mirror-image defect: it resolved *after* the pinned now and only counted
as "fresh" because the helper has no future-date guard — passing for the wrong reason.

Use ``utc_now()`` (or a literal date) in tests. If a test genuinely needs real elapsed time, add it
to ``_ALLOWLIST`` with a comment explaining why.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parent

# Attribute calls that read the real clock and therefore drift against the pinned epoch.
_WALL_CLOCK_ATTRS = frozenset({"now", "utcnow", "today"})

# Files permitted to read the real clock, each with a reason. Keep this empty unless a test
# measures genuine elapsed time (e.g. a timeout); never add a file just to silence the guard.
_ALLOWLIST: frozenset[str] = frozenset()


def _wall_clock_calls(source: str) -> list[tuple[str, int]]:
    """Return ``(expression, lineno)`` for every real-clock call in ``source``.

    Uses the AST rather than a text scan so prose in docstrings and comments — including this
    module's own — is never mistaken for a call.
    """

    hits: list[tuple[str, int]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in _WALL_CLOCK_ATTRS:
            continue
        owner = func.value
        # Matches `datetime.now(...)`, `date.today()`, and `datetime.datetime.utcnow()`.
        if isinstance(owner, ast.Name):
            owner_name = owner.id
        elif isinstance(owner, ast.Attribute):
            owner_name = owner.attr
        else:
            continue
        if owner_name in {"datetime", "date"}:
            hits.append((f"{owner_name}.{func.attr}()", node.lineno))
    return hits


def test_no_test_reads_the_real_wall_clock() -> None:
    offenders: list[str] = []
    for path in sorted(TESTS_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts or path == Path(__file__).resolve():
            continue
        rel = path.relative_to(TESTS_ROOT).as_posix()
        if rel in _ALLOWLIST:
            continue
        for expression, lineno in _wall_clock_calls(path.read_text(encoding="utf-8")):
            offenders.append(f"{rel}:{lineno}: {expression}")

    assert not offenders, (
        "These tests read the real wall clock and will drift against the pinned SOURCE_DATE_EPOCH. "
        "Use oss_policy_kit.domain.models.utc_now() (or a literal date) instead:\n  " + "\n  ".join(offenders)
    )


def test_guard_detects_a_wall_clock_call() -> None:
    """Mutation check: the guard must actually fire, not pass because it matches nothing."""

    assert _wall_clock_calls("from datetime import UTC, datetime\nx = datetime.now(UTC)\n") == [("datetime.now()", 2)]
    assert _wall_clock_calls("import datetime\ny = datetime.datetime.utcnow()\n") == [("datetime.utcnow()", 2)]
    # utc_now() is a bare name call, not an attribute read — it must not trip the guard.
    assert _wall_clock_calls("from oss_policy_kit.domain.models import utc_now\nz = utc_now()\n") == []
    # Prose mentioning datetime.now() must not trip it either.
    assert _wall_clock_calls('"""Historically this called datetime.now(UTC)."""\n') == []
