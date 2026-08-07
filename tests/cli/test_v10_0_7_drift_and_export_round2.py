"""Round-2 regressions for ``diff-reports`` and ``export-evidence --format sarif``.

Two defects found by the clean-room validation of the v10.0.7 wheel:

1. *``diff-reports`` compared two unrelated repositories as posture drift.*
   ``--before github-vulnerable-target --after github-hardened-target`` exited 0 and
   announced eleven improvements (CI-DANGER-007 FAIL->PASS, GOV-SEC-001 FAIL->PASS, ...).
   None of them happened: nothing improved, the operator pointed the command at two
   different repositories. Drift is the posture change of ONE target between two runs,
   and both reports carry the identity of the target they were produced against, so the
   command had everything it needed to say so and said nothing.

2. *the ``sarif_runs`` passthrough bypassed the entire non-finding filter.* v10.0.7
   stopped ``export-evidence --format sarif`` emitting passing controls as alerts — but
   only on the branch that synthesizes a run from ``controls``. A report carrying a
   ``sarif_runs`` key was returned verbatim, so a run listing a control at
   ``level: error`` that the same report records as ``PASS`` exported unchanged: same
   report, same format, opposite answer depending on which branch ran.

Every guard here was mutation-tested (the fix reverted on purpose, the test confirmed
to fail, the fix restored).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.drift import compute_drift, target_identity
from oss_policy_kit.cli.export_evidence import _render_sarif, _validate
from oss_policy_kit.cli.main import app

runner = CliRunner()


def _flat(text: str) -> str:
    """Collapse whitespace so a Rich soft-wrap cannot split an asserted phrase."""

    return re.sub(r"\s+", " ", text)


# --------------------------------------------------------------------------- #
# 1 — diff-reports refuses to present two repositories as one target's drift
# --------------------------------------------------------------------------- #


def _report(target: str | None, states: dict[str, str], **extra: Any) -> dict[str, Any]:
    """A minimal ``reports/2.0`` payload — the only contract ``diff-reports`` accepts."""

    payload: dict[str, Any] = {
        "contract_version": "reports/2.0",
        "kit_version": "10.0.7",
        "profile": {"id": "github-level-1"},
        "controls": [{"id": cid, "state": state, "title": cid} for cid, state in states.items()],
    }
    if target is not None:
        payload["target_path"] = target
    payload.update(extra)
    return payload


def _pair(tmp_path: Path, before: dict[str, Any], after: dict[str, Any]) -> tuple[str, str]:
    b = tmp_path / "before.json"
    a = tmp_path / "after.json"
    b.write_text(json.dumps(before), encoding="utf-8")
    a.write_text(json.dumps(after), encoding="utf-8")
    return str(b), str(a)


#: The exact clean-room invocation: a deliberately weak repository as ``--before`` and a
#: hardened one as ``--after``, which reads as a spotless improvement story.
_VULNERABLE = {"CI-DANGER-007": "FAIL", "GOV-SEC-001": "FAIL"}
_HARDENED = {"CI-DANGER-007": "PASS", "GOV-SEC-001": "PASS"}


def test_two_different_repositories_are_refused(tmp_path: Path) -> None:
    """The reported invocation, verbatim: it must no longer produce a drift verdict."""

    before, after = _pair(
        tmp_path,
        _report("github-vulnerable-target", _VULNERABLE),
        _report("github-hardened-target", _HARDENED),
    )

    res = runner.invoke(app, ["diff-reports", "--before", before, "--after", after])

    assert res.exit_code == 2, res.output
    assert "different targets" in _flat(res.output), res.output
    assert "Traceback" not in res.output, res.output
    assert "Unexpected error" not in res.output, res.output


@pytest.mark.parametrize("fmt", ["table", "json", "markdown"])
def test_no_format_publishes_the_improvements_that_never_happened(tmp_path: Path, fmt: str) -> None:
    """Refusing rather than warning is the point: the artifact is what travels.

    ``--format markdown`` exists to be pasted into a PR comment and ``--format json`` to
    be archived by CI, so a warning on stderr would not reach either. Nothing may be
    written to stdout for any format.
    """

    before, after = _pair(
        tmp_path,
        _report("github-vulnerable-target", _VULNERABLE),
        _report("github-hardened-target", _HARDENED),
    )

    res = runner.invoke(app, ["diff-reports", "--before", before, "--after", after, "-f", fmt])

    assert res.exit_code == 2, res.output
    assert res.stdout.strip() == "", res.stdout
    assert "GOV-SEC-001" not in res.stdout, res.stdout


def test_the_refusal_names_both_targets_and_the_way_out(tmp_path: Path) -> None:
    """An operator has to be able to see WHICH two repositories, and what to do next."""

    before, after = _pair(
        tmp_path,
        _report("github-vulnerable-target", _VULNERABLE),
        _report("github-hardened-target", _HARDENED),
    )

    res = runner.invoke(app, ["diff-reports", "--before", before, "--after", after])
    out = _flat(res.output)

    assert "github-vulnerable-target" in out, res.output
    assert "github-hardened-target" in out, res.output
    assert "--allow-different-targets" in out, res.output


def test_the_refusal_does_not_publish_the_directory_a_target_lived_in(tmp_path: Path) -> None:
    """M-002: a report produced with ``--include-absolute-path`` carries a full path.

    The marker is a distinctive DIRECTORY NAME rather than ``str(tmp_path)``: on Windows
    the 8.3 short name hides the account name from a naive "username not in output"
    check, and it contains no separator, so nothing here can pass for the wrong reason.
    (The literals below avoid the real home-directory spellings on purpose —
    ``scripts/check_public_hygiene.py`` refuses those anywhere in the tree — while
    keeping one POSIX-separated and one backslash-separated absolute path.)
    """

    before, after = _pair(
        tmp_path,
        _report("/srv/zzmarkerdirzz/github-vulnerable-target", _VULNERABLE),
        _report("D:\\zzmarkerdirzz\\github-hardened-target", _HARDENED),
    )

    res = runner.invoke(app, ["diff-reports", "--before", before, "--after", after])

    assert res.exit_code == 2, res.output
    assert "zzmarkerdirzz" not in res.output, res.output
    assert "github-vulnerable-target" in _flat(res.output), res.output


def test_allow_different_targets_opts_in_and_still_says_so(tmp_path: Path) -> None:
    """The legitimate reading — deliberately comparing two repositories — stays available,
    but naming it puts the intent on the record for whoever reads the CI log later."""

    before, after = _pair(
        tmp_path,
        _report("github-vulnerable-target", _VULNERABLE),
        _report("github-hardened-target", _HARDENED),
    )

    res = runner.invoke(
        app,
        ["diff-reports", "--before", before, "--after", after, "-f", "json", "--allow-different-targets"],
    )
    payload = json.loads(res.stdout)

    assert res.exit_code == 0, res.output
    assert len(payload["improvements"]) == 2, payload
    assert "different targets" in _flat(res.stderr), res.stderr


def test_one_target_evaluated_twice_is_untouched(tmp_path: Path) -> None:
    """The everyday case must not become a new false refusal."""

    before, after = _pair(
        tmp_path,
        _report("my-repo", {"GOV-SEC-001": "PASS"}),
        _report("my-repo", {"GOV-SEC-001": "PASS"}),
    )

    res = runner.invoke(app, ["diff-reports", "--before", before, "--after", after, "-f", "json"])

    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["regressions"] == []
    assert "different targets" not in _flat(res.output), res.output


def test_a_real_regression_on_one_target_still_fails_the_gate(tmp_path: Path) -> None:
    """Exit 1 is the gate firing on a genuine PASS->FAIL; the new guard must not eat it."""

    before, after = _pair(
        tmp_path,
        _report("my-repo", {"GOV-SEC-001": "PASS"}),
        _report("my-repo", {"GOV-SEC-001": "FAIL"}),
    )

    res = runner.invoke(app, ["diff-reports", "--before", before, "--after", after, "-f", "json"])

    assert res.exit_code == 1, res.output
    assert [r["control_id"] for r in json.loads(res.stdout)["regressions"]] == ["GOV-SEC-001"]


@pytest.mark.parametrize(
    ("before_target", "after_target", "why"),
    [
        (".", "my-repo", "'.' is what a report says when the target WAS the working directory"),
        ("my-repo", ".", "same, on the other side"),
        (".", ".", "two clones each evaluated from inside themselves both say '.'"),
        (None, "my-repo", "a report without target_path cannot identify anything"),
        ("my-repo", None, "same, on the other side"),
        ("My-Repo", "my-repo", "on Windows these are one directory"),
        ("/srv/ci/my-repo", "my-repo", "absolute on one side, sanitized on the other"),
    ],
)
def test_an_unprovable_mismatch_never_refuses(
    tmp_path: Path, before_target: str | None, after_target: str | None, why: str
) -> None:
    """Refuse only on proof. A missed warning costs a second look; a false refusal breaks
    a legitimate comparison, so every ambiguous pairing has to keep working."""

    before, after = _pair(
        tmp_path,
        _report(before_target, {"GOV-SEC-001": "PASS"}),
        _report(after_target, {"GOV-SEC-001": "PASS"}),
    )

    res = runner.invoke(app, ["diff-reports", "--before", before, "--after", after, "-f", "json"])

    assert res.exit_code == 0, f"{why}: {res.output}"
    assert "different targets" not in _flat(res.output), why


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("github-hardened-target", "github-hardened-target"),
        ("/srv/auditor/repo", "repo"),
        ("D:\\auditor\\repo", "repo"),
        ("/srv/auditor/repo/", "repo"),
        (".", None),
        ("", None),
        ("   ", None),
        ("unknown", None),
        ("/", None),
    ],
)
def test_target_identity_reduces_to_a_name_on_either_platform(raw: str, expected: str | None) -> None:
    """``Path`` only understands the separators of the RUNNING OS, so a Windows-written
    report read on Linux would keep the whole path — and quoting it would publish the
    auditor's home directory. Both separators have to reduce."""

    assert target_identity({"target_path": raw}) == expected


def test_the_drift_object_records_the_two_targets() -> None:
    """The CLI is not the only possible caller; the decision has to be in the data."""

    d = compute_drift(
        _report("github-vulnerable-target", _VULNERABLE),
        _report("github-hardened-target", _HARDENED),
    )

    assert d.target_mismatch is True
    assert d.before_target == "github-vulnerable-target"
    assert d.after_target == "github-hardened-target"


# --------------------------------------------------------------------------- #
# 2 — the sarif_runs passthrough obeys the same non-finding filter
# --------------------------------------------------------------------------- #


_SARIF_REPORT: dict[str, Any] = {
    "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0",
    "contract_version": "reports/2.0",
    "target_path": "examples/hardened-repo",
    "profile": {"id": "github-level-1"},
    "summary_by_status": {"PASS": 1, "FAIL": 1},
    "controls": [
        {"id": "GOV-SEC-001", "state": "PASS", "message": "ok"},
        {"id": "GH-ATT-099", "state": "ATTESTED", "message": "attested"},
        {"id": "GH-NA-050", "state": "NOT_APPLICABLE", "message": "n/a"},
        {"id": "GH-WAIVED-060", "state": "UNKNOWN", "reason": "waived", "message": "waived"},
        {"id": "CI-PIN-008", "state": "FAIL", "message": "mutable refs"},
    ],
}


def _with_runs(runs: list[Any]) -> dict[str, Any]:
    report = dict(_SARIF_REPORT)
    report["sarif_runs"] = runs
    return report


def _rule_ids(doc: dict[str, Any]) -> list[str]:
    return [r.get("ruleId") for r in doc["runs"][0]["results"]]


def test_a_carried_run_cannot_smuggle_a_passing_control_in_as_an_alert() -> None:
    """The reported defect: an injected run with a PASS control at ``level: error``."""

    doc = _render_sarif(
        _with_runs(
            [
                {
                    "tool": {"driver": {"name": "injected"}},
                    "results": [
                        {"ruleId": "GOV-SEC-001", "level": "error", "message": {"text": "passing control"}},
                        {"ruleId": "CI-PIN-008", "level": "error", "message": {"text": "real finding"}},
                    ],
                }
            ]
        )
    )

    assert "GOV-SEC-001" not in _rule_ids(doc), "a passing control reached a SARIF consumer as an alert"
    assert "CI-PIN-008" in _rule_ids(doc), "the real finding must survive"
    assert _validate(doc, "sarif") == []


@pytest.mark.parametrize("rule_id", ["GH-ATT-099", "GH-NA-050", "GH-WAIVED-060"])
def test_every_non_finding_state_is_filtered_not_just_pass(rule_id: str) -> None:
    """The whole filter, not the PASS half of it: attested, not-applicable and a waived
    UNKNOWN are all states where somebody already decided nothing needs doing."""

    doc = _render_sarif(
        _with_runs([{"tool": {"driver": {"name": "injected"}}, "results": [{"ruleId": rule_id, "level": "error"}]}])
    )

    assert _rule_ids(doc) == [], f"{rule_id} is not a finding and must not become an alert"


def test_the_rule_reference_spelling_is_filtered_too() -> None:
    """SARIF 2.1.0 spells the rule two ways (3.27.5 ``ruleId``, 3.27.7 ``rule``). Reading
    only the first leaves the second as a way to reintroduce the very result removed."""

    doc = _render_sarif(
        _with_runs(
            [{"tool": {"driver": {"name": "injected"}}, "results": [{"rule": {"id": "GOV-SEC-001"}, "level": "error"}]}]
        )
    )

    assert doc["runs"][0]["results"] == []


def test_a_result_the_report_knows_nothing_about_is_kept() -> None:
    """Foreign results may be genuine findings from another tool. Silently deleting a
    finding is the worse failure, so the filter only drops what this report calls a
    non-finding."""

    doc = _render_sarif(
        _with_runs(
            [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [{"ruleId": "python.lang.security.audit", "level": "error"}],
                }
            ]
        )
    )

    assert _rule_ids(doc) == ["python.lang.security.audit"]


def test_the_omission_is_recorded_in_the_run_it_happened_in() -> None:
    """A silent difference between two exports of the same report is how this class of
    defect survives; the artifact has to say what it left out."""

    doc = _render_sarif(
        _with_runs(
            [
                {
                    "tool": {"driver": {"name": "injected"}},
                    "results": [{"ruleId": "GOV-SEC-001"}, {"ruleId": "GH-ATT-099"}, {"ruleId": "CI-PIN-008"}],
                }
            ]
        )
    )
    props = doc["runs"][0]["properties"]

    assert props["kit_non_finding_results_omitted"] == 2
    assert "code scanning" in props["kit_results_policy"]


def test_an_untouched_carried_run_is_passed_through_unchanged() -> None:
    """Nothing was filtered, so nothing may be rewritten — including no new
    ``properties`` key appearing in an artifact that never had one."""

    run = {"tool": {"driver": {"name": "existing"}}, "results": [{"ruleId": "CI-PIN-008", "level": "error"}]}
    doc = _render_sarif(_with_runs([dict(run)]))

    assert doc["runs"][0] == run


def test_a_carried_entry_that_is_not_a_run_falls_back_to_synthesis() -> None:
    """``sarif_runs: ["nope"]`` is not SARIF. Exporting it produces a document no
    consumer can read, so the honest answer is the run synthesized from ``controls``."""

    doc = _render_sarif(_with_runs(["nope", 7, None]))

    assert _validate(doc, "sarif") == []
    assert _rule_ids(doc) == ["CI-PIN-008"], "only the failing control is a finding"


def test_export_evidence_sarif_writes_no_alert_for_a_passing_control(tmp_path: Path) -> None:
    """End to end, through the file the operator actually uploads to code scanning."""

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "evaluation-report.json").write_text(
        json.dumps(
            _with_runs(
                [
                    {
                        "tool": {"driver": {"name": "injected"}},
                        "results": [
                            {"ruleId": "GOV-SEC-001", "level": "error"},
                            {"ruleId": "CI-PIN-008", "level": "error"},
                        ],
                    }
                ]
            )
        ),
        encoding="utf-8",
    )
    written = tmp_path / "evidence.sarif.json"

    res = runner.invoke(
        app,
        ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--output", str(written), "--validate"],
    )
    doc = json.loads(written.read_text(encoding="utf-8"))

    assert res.exit_code == 0, res.output
    assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["CI-PIN-008"]
