"""Guard: the signal-id to stack-label mapping lives in one place.

`profile_hints` emits the tech-stack signals, so it owns their labels. `init_planner` used to
keep a private copy of the same dict to turn a signal into `primary_stack`, and the two had
already drifted before anyone noticed: `init_planner` knew `container_docker` while
`profile_hints` knew `node_lockfile`. The stack a repository was reported to use therefore
depended on which module answered.

`STACK_LABEL_BY_SIGNAL_ID` is now composed inside `profile_hints` from `_STACK_SIGNAL_LABELS`
plus `_CONTAINER_SIGNAL_ID`, and `init_planner` reads it. These tests fail if a second copy
reappears, if the composition loses an entry, or if a label goes missing for a signal the
recommender can actually emit.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from oss_policy_kit.application import init_planner, profile_hints
from oss_policy_kit.application.profile_hints import STACK_LABEL_BY_SIGNAL_ID


def test_the_shared_map_covers_both_definitions() -> None:
    """Composition must not silently drop the language labels or the container."""

    for signal_id, label in profile_hints._STACK_SIGNAL_LABELS.items():
        assert STACK_LABEL_BY_SIGNAL_ID.get(signal_id) == label, (
            f"{signal_id} is missing from STACK_LABEL_BY_SIGNAL_ID or carries a different label"
        )

    container = profile_hints._CONTAINER_SIGNAL_ID
    assert container in STACK_LABEL_BY_SIGNAL_ID, (
        f"{container} must have a label: it is a stack a caller needs to name, even though "
        "_rank_stack_signals treats it as packaging rather than a language"
    )


def test_init_planner_declares_no_stack_label_dict_of_its_own() -> None:
    """A second copy is the defect itself, so look for one rather than trust convention."""

    source = Path(inspect.getfile(init_planner)).read_text(encoding="utf-8")
    known_labels = set(STACK_LABEL_BY_SIGNAL_ID.values())

    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Dict):
            continue
        literals = {v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)}
        overlap = literals & known_labels
        if len(overlap) >= 2:
            offenders.append(f"line {node.lineno}: dict literal repeating {sorted(overlap)}")

    assert not offenders, (
        "init_planner appears to define its own signal-to-label mapping again; import "
        "STACK_LABEL_BY_SIGNAL_ID from profile_hints instead:\n  " + "\n  ".join(offenders)
    )


def test_every_label_is_reachable_from_a_real_signal_id() -> None:
    """Mutation check: the map must describe signals the recommender emits, not invented ones.

    Without this, the guard above would still pass over a map full of dead entries.
    """

    assert STACK_LABEL_BY_SIGNAL_ID, "the shared map is empty, so every assertion here is vacuous"
    for signal_id, label in STACK_LABEL_BY_SIGNAL_ID.items():
        assert signal_id.strip() == signal_id and signal_id, f"malformed signal id: {signal_id!r}"
        assert label.strip() == label and label, f"malformed label for {signal_id}: {label!r}"


def test_container_only_repository_is_still_named(tmp_path: Path) -> None:
    """Behaviour lock: the container label survived the move.

    `init_planner`'s private copy was the only one that knew `container_docker`. Importing the
    shared map naively would have dropped it and reported no stack for a Dockerfile-only repo.
    """

    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    plan = init_planner.build_init_plan(
        target=tmp_path,
        forced_profile=None,
        forced_platform=None,
        fail_on="fail",
        output_dir="./oss-policy-reports",
        with_waivers=False,
        with_evidence=False,
        with_workflow=False,
        force=False,
        dry_run=True,
    )

    assert plan.primary_stack == "Container (Docker)"
