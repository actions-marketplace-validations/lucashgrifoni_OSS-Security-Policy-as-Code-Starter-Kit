"""What `emit-vex` refuses, and why refusing beats emitting.

A VEX document is a statement to downstream consumers. Every entry asserts that the named
identifier is a vulnerability the manufacturer has looked at, and an *empty* VEX asserts the
strongest thing of all: nothing to declare. That is what makes silence the dangerous failure
mode here -- a tolerant reader that turns a malformed scan into an empty ID list produces a
perfectly valid document at exit 0 that reads as a clean bill of health.

So each refusal below is asserted on three things: a non-zero exit, no output file left behind,
and a message that names what was wrong. The message matters because the operator's next move
is to fix their input, and they can only do that if the refusal says which file and which part.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import emit_vex as ev
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()


def _sarif(*, driver: str | None = "osv-scanner", rule_ids: list[str]) -> dict[str, Any]:
    tool: dict[str, Any] = {"driver": {}} if driver is None else {"driver": {"name": driver}}
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": tool,
                "results": [{"ruleId": rid, "message": {"text": rid}} for rid in rule_ids],
            }
        ],
    }


def _write(path: Path, doc: object) -> Path:
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return path


def _run(sarif: Path, out: Path) -> Any:
    return runner.invoke(app, ["emit-vex", "--osv-sarif", str(sarif), "--output", str(out)])


# --------------------------------------------------------------------------- #
# Structurally invalid input
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "doc", "fragment"),
    [
        ("a run is not an object", {"runs": ["nope"]}, "runs[0] must be an object"),
        ("results is not an array", {"runs": [{"results": "nope"}]}, "runs[0].results must be an array"),
        ("results is explicitly null", {"runs": [{"results": None}]}, "runs[0].results must be an array"),
    ],
)
def test_a_malformed_sarif_is_refused_instead_of_read_as_finding_nothing(
    label: str, doc: dict[str, Any], fragment: str, tmp_path: Path
) -> None:
    """`"results": null` is the case worth naming: it is a broken file, not an empty scan."""

    sarif = _write(tmp_path / "osv.sarif.json", doc)
    out = tmp_path / "vex.json"
    result = _run(sarif, out)

    assert result.exit_code != 0, label
    assert not out.exists(), "a refusal that still writes a file is not a refusal"
    assert "not a structurally valid SARIF document" in result.output
    assert fragment in result.output
    assert "osv.sarif.json" in result.output


def test_the_structural_refusal_names_the_file_by_basename_only(tmp_path: Path) -> None:
    """M-002: the refusal is something operators paste into tickets and chat."""

    sarif = _write(tmp_path / "osv.sarif.json", {"runs": ["nope"]})
    with pytest.raises(InvalidInputError) as excinfo:
        ev._read_validated_sarif(sarif)

    assert "osv.sarif.json" in excinfo.value.message
    assert str(tmp_path) not in excinfo.value.message


def test_a_runs_key_that_is_not_an_array_is_caught_before_the_structural_pass(tmp_path: Path) -> None:
    """A different guard, deliberately: the reader cannot even begin without a list of runs."""

    sarif = _write(tmp_path / "osv.sarif.json", {"runs": {}})
    result = _run(sarif, tmp_path / "vex.json")

    assert result.exit_code == 2
    assert "'runs' is not an array" in result.output


# --------------------------------------------------------------------------- #
# Structurally valid, but the wrong document
# --------------------------------------------------------------------------- #


def test_the_kits_own_sarif_is_recognised_and_named_as_such(tmp_path: Path) -> None:
    """The bug this guard exists for: policy control ids emitted as if they were CVEs."""

    sarif = _write(tmp_path / "osv.sarif.json", _sarif(driver="oss-policy-kit", rule_ids=["CI-PIN-008"]))
    out = tmp_path / "vex.json"
    result = _run(sarif, out)

    assert result.exit_code != 0
    assert not out.exists()
    assert "export-evidence --format sarif" in result.output


def test_a_third_party_scanner_that_is_not_a_vulnerability_scan_is_named_in_the_refusal(tmp_path: Path) -> None:
    """Knowing which tool produced the file is how the operator finds the right one."""

    sarif = _write(tmp_path / "osv.sarif.json", _sarif(driver="semgrep", rule_ids=["python.lang.security.audit"]))
    result = _run(sarif, tmp_path / "vex.json")

    assert result.exit_code != 0
    assert "does not look like a vulnerability scan" in result.output
    assert "semgrep" in result.output


def test_a_document_that_declares_no_producer_is_still_refused(tmp_path: Path) -> None:
    """With nothing to attribute it to, the refusal has to stand on the ids alone."""

    sarif = _write(tmp_path / "osv.sarif.json", _sarif(driver=None, rule_ids=["rule-one", "rule-two"]))
    result = _run(sarif, tmp_path / "vex.json")

    assert result.exit_code != 0
    assert "does not look like a vulnerability scan" in result.output
    assert "identifies its producer" not in result.output


def test_one_recognised_vulnerability_id_is_enough_to_be_accepted(tmp_path: Path) -> None:
    """The counterpart: a scanner mixing house rule names with CVEs is a real scan."""

    sarif = _write(tmp_path / "osv.sarif.json", _sarif(rule_ids=["house-rule-1", "CVE-2024-1234"]))
    out = tmp_path / "vex.json"
    result = _run(sarif, out)

    assert result.exit_code == 0, result.output
    assert out.is_file()


# --------------------------------------------------------------------------- #
# Input the reader must not try to parse
# --------------------------------------------------------------------------- #


def test_a_deeply_nested_document_is_refused_cleanly_rather_than_exhausting_the_stack(tmp_path: Path) -> None:
    """CPython's C scanner blows the interpreter stack, and RecursionError is not a ValueError.

    Left to the parser this escaped every handler and surfaced as an exit-3 "Unexpected error".
    The depth is measured before parsing so the operator gets a validation message instead.
    """

    depth = 250
    sarif = _write(tmp_path / "osv.sarif.json", "[" * depth + "]" * depth)
    result = _run(sarif, tmp_path / "vex.json")

    assert result.exit_code == 2, result.output
    assert "nested too deeply" in result.output
    assert "200 levels" in result.output


# --------------------------------------------------------------------------- #
# Option provenance
# --------------------------------------------------------------------------- #


def test_an_option_whose_provenance_cannot_be_read_counts_as_not_passed() -> None:
    """Best-effort by design: knowing *how* a flag was set must never break the command."""

    class _NoProvenance:
        def get_parameter_source(self, name: str) -> object:
            raise RuntimeError("click internals changed under us")

    assert ev._flag_was_provided(_NoProvenance(), "product") is False  # type: ignore[arg-type]
