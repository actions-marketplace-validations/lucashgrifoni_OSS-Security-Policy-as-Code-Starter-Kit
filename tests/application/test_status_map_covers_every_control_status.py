"""Guard: every ControlStatus maps to a reports/2.0 state, in both copies of the map.

`map_status_to_reports_v2` ends in a fallback that returns
``("UNKNOWN", "unmapped-source-status")`` for a status it does not recognise. That reason
appears in no document, no schema and no `--help` output, so an adopter who receives it has
nothing to act on.

It was not hypothetical. `ControlStatus` had nine members and the map had seven of them:
`NOT_EVALUATED` and `NOT_OBSERVABLE` fell through. `NOT_EVALUATED` is returned by evaluators
across five modules — `OSS-SCORECARD-001` uses it whenever no Scorecard JSON is supplied — so
evaluating the bundled hardened example against `github-level-2` was enough to put the
undocumented discriminator in a report.

The map exists twice, in `engine` and in `reporting`, and a v9.0.3 fix already had to
reconcile a drift between them. Both copies are checked here, and against each other.
"""

from __future__ import annotations

from oss_policy_kit.application.engine import REPORTS_V2_STATUS_MAP as ENGINE_MAP
from oss_policy_kit.application.engine import map_status_to_reports_v2
from oss_policy_kit.application.reporting import REPORTS_V2_STATUS_MAP as REPORTING_MAP
from oss_policy_kit.domain.models import ControlStatus

#: States the reports/2.0 contract defines. A mapping may not invent one.
_CONTRACT_STATES = frozenset({"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "ATTESTED", "SELF_ATTESTED"})


def test_every_control_status_is_mapped() -> None:
    unmapped = sorted({status.value for status in ControlStatus} - set(ENGINE_MAP))

    assert not unmapped, (
        "These ControlStatus members have no reports/2.0 mapping, so they reach adopters as "
        f"`unmapped-source-status`, a discriminator documented nowhere: {unmapped}. "
        "Add an entry to REPORTS_V2_STATUS_MAP in engine.py and reporting.py, and document "
        "the reason in docs/reports-contract-v2.0.md."
    )


def test_the_two_copies_of_the_map_agree() -> None:
    """v9.0.3 already had to fix a drift between these. Keep them identical."""

    assert ENGINE_MAP == REPORTING_MAP, (
        "engine.REPORTS_V2_STATUS_MAP and reporting.REPORTS_V2_STATUS_MAP have drifted; "
        "they are the same contract and must be edited together"
    )


def test_every_mapping_targets_a_contract_state() -> None:
    invalid = sorted({state for state, _ in ENGINE_MAP.values()} - _CONTRACT_STATES)

    assert not invalid, f"these mapped states are not in the reports/2.0 vocabulary: {invalid}"


def test_the_fallback_is_unreachable_from_a_real_status() -> None:
    """Mutation check: the guard above must be testing something the fallback can still catch."""

    for status in ControlStatus:
        _, reason = map_status_to_reports_v2(status.value)
        assert reason != "unmapped-source-status", f"{status.name} still falls through to the fallback"

    # The fallback itself must remain in place for a genuinely unknown string.
    assert map_status_to_reports_v2("something-a-future-version-invents") == (
        "UNKNOWN",
        "unmapped-source-status",
    )
