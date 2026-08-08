"""The `allow-ghsas` exception must not outlive the reason it was granted.

`dependency-review` carries a named allowance for three advisories against `mcp`, a
transitive dependency of semgrep. It is scoped to those three advisory IDs rather than
lowering the severity threshold, so every other vulnerable package still fails the gate.
It exists only because semgrep pins `mcp` exactly, leaving no upgrade to take: as of
2026-08-07 the newest semgrep (1.172.0) still requires `mcp==1.23.3`, and Dependabot
independently reports `security_update_not_possible`.

The removal condition was written into the workflow comment as "remove this allowance as
soon as semgrep depends on mcp >= 1.28.1". A comment is not a mechanism. Whoever
regenerates `.github/requirements/semgrep.txt` months from now has no reason to read that
line, and a security exception that outlives its justification is worse than one that was
never granted -- it silently accepts advisories nobody re-examined.

This guard binds the two files together in both directions:

- if the pinned `mcp` reaches 1.28.1, the allowance must be gone;
- if the allowance is present, the pin must still justify it;
- if semgrep stops depending on `mcp` at all, the allowance must be gone.

It fires exactly when the pins are regenerated, which is the moment the decision becomes
re-decidable, and it needs no network -- the pinned version is committed to the repo.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SEMGREP_PINS = _REPO_ROOT / ".github" / "requirements" / "semgrep.txt"
_SECURITY_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "security-ci-cd.yml"

#: The version that makes the allowance unnecessary, per the advisories' fixed range.
_MCP_FIXED_IN = (1, 28, 1)

#: The three advisories the allowance names. Kept explicit so that widening the list --
#: or swapping it for a lowered severity threshold -- shows up as a diff here too.
_ALLOWED_GHSAS = frozenset({"GHSA-hvrp-rf83-w775", "GHSA-jpw9-pfvf-9f58", "GHSA-vj7q-gjh5-988w"})


def _parse_version(raw: str) -> tuple[int, ...]:
    """`1.23.3` -> `(1, 23, 3)`. Non-numeric suffixes are dropped, not guessed at."""

    parts: list[int] = []
    for chunk in raw.split("."):
        digits = re.match(r"\d+", chunk)
        if digits is None:
            break
        parts.append(int(digits.group()))
    return tuple(parts)


def _pinned_mcp_version() -> tuple[int, ...] | None:
    """The `mcp` version resolved into semgrep's pin file, or None if it is gone."""

    text = _SEMGREP_PINS.read_text(encoding="utf-8")
    match = re.search(r"^mcp==(\S+?)(?:\s|\\|$)", text, re.MULTILINE)
    return _parse_version(match.group(1)) if match else None


def _allowed_ghsas_in_workflow() -> frozenset[str]:
    """The advisory IDs currently allowed by the dependency-review job."""

    text = _SECURITY_WORKFLOW.read_text(encoding="utf-8")
    match = re.search(r"^\s*allow-ghsas:\s*(.+)$", text, re.MULTILINE)
    if match is None:
        return frozenset()
    return frozenset(part.strip() for part in match.group(1).split(",") if part.strip())


def test_pin_file_and_workflow_are_both_readable() -> None:
    """A guard over two files is worthless if a rename quietly turns it into a no-op."""

    assert _SEMGREP_PINS.is_file(), f"missing {_SEMGREP_PINS.relative_to(_REPO_ROOT)}"
    assert _SECURITY_WORKFLOW.is_file(), f"missing {_SECURITY_WORKFLOW.relative_to(_REPO_ROOT)}"


def test_allowance_is_dropped_once_semgrep_moves_past_the_fixed_version() -> None:
    pinned = _pinned_mcp_version()
    allowed = _allowed_ghsas_in_workflow()

    if pinned is None:
        assert not allowed, (
            "semgrep no longer pins `mcp`, so the three `mcp` advisories can no longer "
            "reach this project through it, but `allow-ghsas` is still set in "
            f"{_SECURITY_WORKFLOW.name}: {sorted(allowed)}. Remove the allowance and the "
            "comment above it."
        )
        return

    if pinned >= _MCP_FIXED_IN:
        pretty = ".".join(str(n) for n in pinned)
        fixed = ".".join(str(n) for n in _MCP_FIXED_IN)
        assert not allowed, (
            f"semgrep now resolves to mcp=={pretty}, at or past the fixed {fixed}, so the "
            f"three advisories are no longer present. The removal condition written into "
            f"{_SECURITY_WORKFLOW.name} has been met: delete the `allow-ghsas` line and "
            f"the comment explaining it. Still allowed: {sorted(allowed)}."
        )


def test_allowance_while_present_is_still_justified_and_still_narrow() -> None:
    """The converse: an allowance that is present must be earning its keep."""

    allowed = _allowed_ghsas_in_workflow()
    if not allowed:
        pytest.skip("no allowance in place; the other test owns that direction")

    pinned = _pinned_mcp_version()
    assert pinned is not None and pinned < _MCP_FIXED_IN, (
        "`allow-ghsas` is set, but semgrep's pin no longer justifies it. "
        "See the other test in this module for what to remove."
    )

    assert allowed == _ALLOWED_GHSAS, (
        "the dependency-review allowance changed. It is deliberately scoped to the three "
        "`mcp` advisories so that every other vulnerable package still fails the gate.\n"
        f"  expected: {sorted(_ALLOWED_GHSAS)}\n"
        f"  found:    {sorted(allowed)}\n"
        "If an advisory was legitimately added, update _ALLOWED_GHSAS here together with "
        "the rationale comment in the workflow -- do not widen one without the other."
    )
