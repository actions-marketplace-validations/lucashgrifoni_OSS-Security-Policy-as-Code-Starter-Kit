"""Applicability precondition resolver (ADR-028).

Given a control's declared :class:`~oss_policy_kit.application.loader.ApplicabilitySpec`
and a repository root, decide whether the control is *applicable* to that repository
by inspecting the filesystem only — no code execution, no network.

This is consulted by the engine **only when the applicability engine is enabled**
(opt-in, default off). When a control has no declared precondition it is always
applicable, preserving today's behavior.
"""

from __future__ import annotations

from itertools import islice
from pathlib import Path

from oss_policy_kit.application.loader import ApplicabilitySpec

# Bound the per-pattern filesystem walk so a pathological repo cannot make
# applicability resolution expensive. We only need to know whether *any* file
# matches, so the first hit short-circuits well under this cap.
_MAX_GLOB_MATCHES = 5000


def _any_file_matches(repo_root: Path, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        try:
            for match in islice(sorted(repo_root.glob(pattern)), _MAX_GLOB_MATCHES):
                if match.is_file():
                    return True
        except (OSError, ValueError):
            # Bad pattern or unreadable tree: treat as "not matched" for this
            # pattern and continue; never raise into the evaluation loop.
            continue
    return False


def resolve_applicability(spec: ApplicabilitySpec | None, repo_root: Path) -> tuple[bool, str | None]:
    """Return ``(applicable, reason_when_not_applicable)``.

    - No spec, or a spec with no patterns: always applicable (``True, None``).
    - ``requires_any_files``: applicable iff at least one glob matches a real file.
    """

    if spec is None or not spec.requires_any_files:
        return True, None
    if _any_file_matches(repo_root, spec.requires_any_files):
        return True, None
    preview = ", ".join(spec.requires_any_files[:5])
    return False, (
        f"Precondition not met: no file matches required pattern(s) ({preview}). "
        "Control is not applicable to this repository."
    )
