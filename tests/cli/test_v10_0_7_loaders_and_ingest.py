"""v10.0.7 clean-room follow-ups in the loader / ingest lane.

Four defects, all found by running the built wheel against hostile and ordinary input:

1. **The profile/catalog loader applied no depth budget.** ``diff-catalogs`` reads a
   ``profile.yaml`` through ``load_capped_document`` and refused a 250-level file with
   exit 2; ``evaluate`` read the SAME bytes through ``load_yaml_file``, parsed them
   happily and exited 0. Flow-style YAML never reaches PyYAML's ``RecursionError``, so
   leaving the budget to the exception was leaving it unenforced.

2. **``ingest-scorecard`` announced "ingested" for any JSON at all.** Unknown keys
   degrade field by field, so an arbitrary document produced the success headline with
   "Aggregate score: (not reported)", "Result date: (undated)" and every mapped check
   "(not in result)" — a green exit 0 for an ingest that read nothing.

3. **M-002: ``correlate-findings`` echoed a relative ``--output`` resolved.**
   ``--output f.json`` was answered with the fully-qualified path, spelling out the
   operator's cwd, home directory and OS account name.

4. **``correlate-findings`` ignored an unreadable ``--enrichment-file`` in silence.**
   The artifact recorded it honestly (``sources_read`` status ``unreadable``) but the
   console said only "3 ok, 8 not read" — a count of sources nobody asked for, with no
   mention of the one file the operator named on the command line.

Path assertions here use a RELATIVE argument and a separator-free directory marker on
purpose: ``json.dumps`` doubles backslashes and ``OSError.__str__`` renders the filename
through ``repr``, so a ``str(tmp_path) not in ...`` assertion is vacuous on Windows. The
load-bearing assertion in each case is the POSITIVE one — the exact line the operator
should see — which no leak can satisfy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from oss_policy_kit.cli.main import app

runner = CliRunner()

#: Nesting past ``input_limits.MAX_JSON_DEPTH`` (200). Flow style, because that is the
#: shape the bracket scanner measures and the shape PyYAML parses without complaint.
_DEEP = "[" * 250 + "]" * 250

_TOO_DEEP = "nested too deeply to parse safely (more than 200 levels)"

#: Separator-free and <= 8 characters, so neither backslash doubling nor a Windows 8.3
#: short name can make a leak invisible to the negative assertion.
_MARKER = "SECRETDR"


def _flat(text: str) -> str:
    """Collapse Rich's line wrapping so a long message can be matched as one phrase."""

    return " ".join(text.split())


# --------------------------------------------------------------------------- #
# 1. the profile/catalog loader honours the SHARED depth budget
# --------------------------------------------------------------------------- #


def _kit(root: Path, *, profile_tail: str = "", catalog_tail: str = "") -> Path:
    """A minimal but complete kit data dir, optionally with a too-deep tail appended."""

    kit = root / "kit"
    (kit / "controls").mkdir(parents=True)
    (kit / "profiles" / "p1").mkdir(parents=True)
    (kit / "controls" / "catalog.yaml").write_text(
        "controls:\n  - id: GOV-SEC-001\n    title: Security policy\n" + catalog_tail,
        encoding="utf-8",
    )
    (kit / "profiles" / "p1" / "profile.yaml").write_text(
        "id: p1\ntitle: P1\ndescription: d\naudience: a\ncontrols: [GOV-SEC-001]\n" + profile_tail,
        encoding="utf-8",
    )
    return kit


def _evaluate(kit: Path, repo: Path, out: Path) -> Result:
    return runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(repo),
            "--kit-root",
            str(kit),
            "--profile",
            "p1",
            "--output-dir",
            str(out),
            "--summary-only",
        ],
    )


def test_evaluate_refuses_a_profile_nested_past_the_shared_budget(tmp_path: Path) -> None:
    """The exact file ``diff-catalogs`` already refuses must not be evaluated instead."""

    repo = tmp_path / "repo"
    repo.mkdir()
    kit = _kit(tmp_path, profile_tail=f"notes: {_DEEP}\n")

    result = _evaluate(kit, repo, tmp_path / "out")

    assert result.exit_code == 2, result.output
    assert _TOO_DEEP in _flat(result.output)


def test_evaluate_and_diff_catalogs_answer_the_same_profile_the_same_way(tmp_path: Path) -> None:
    """The defect was disagreement, so the fix is asserted as agreement about one file."""

    repo = tmp_path / "repo"
    repo.mkdir()
    kit = _kit(tmp_path, profile_tail=f"notes: {_DEEP}\n")

    evaluated = _evaluate(kit, repo, tmp_path / "out")
    diffed = runner.invoke(app, ["diff-catalogs", "--from", str(kit)])

    assert evaluated.exit_code == diffed.exit_code == 2, (evaluated.output, diffed.output)
    needle = f"Profile 'profile.yaml' is {_TOO_DEEP}"
    assert needle in _flat(evaluated.output)
    assert needle in _flat(diffed.output)


def test_evaluate_refuses_a_catalog_nested_past_the_shared_budget(tmp_path: Path) -> None:
    """The catalog reader had the same hole; the budget applies to both kit documents."""

    repo = tmp_path / "repo"
    repo.mkdir()
    kit = _kit(tmp_path, catalog_tail=f"notes: {_DEEP}\n")

    result = _evaluate(kit, repo, tmp_path / "out")

    assert result.exit_code == 2, result.output
    assert f"Catalog 'catalog.yaml' is {_TOO_DEEP}" in _flat(result.output)


def test_an_ordinary_kit_is_not_refused_by_the_depth_budget(tmp_path: Path) -> None:
    """Guard against the guard: 200 levels is generous, honest files stay evaluable."""

    repo = tmp_path / "repo"
    repo.mkdir()
    kit = _kit(tmp_path)

    result = _evaluate(kit, repo, tmp_path / "out")

    assert result.exit_code in (0, 1), result.output
    assert _TOO_DEEP not in _flat(result.output)


# --------------------------------------------------------------------------- #
# 2. ingest-scorecard refuses a document with no Scorecard shape
# --------------------------------------------------------------------------- #


def _seed_scorecard(root: Path, payload: object) -> None:
    evidence = root / ".oss-policy-kit" / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "scorecard-result.json").write_text(json.dumps(payload), encoding="utf-8")


def test_ingest_scorecard_refuses_a_document_that_is_not_a_scorecard_result(tmp_path: Path) -> None:
    """No checks, no score, no date: nothing was ingested, so nothing may say "ingested"."""

    _seed_scorecard(tmp_path, {"hello": "world", "items": [1, 2, 3]})

    result = runner.invoke(app, ["ingest-scorecard", "--target", str(tmp_path)])

    assert result.exit_code == 1, result.output
    flat = _flat(result.output)
    assert "is not an OpenSSF Scorecard result" in flat
    assert "ingested" not in flat


def test_ingest_scorecard_json_report_marks_the_unusable_document_as_an_error(tmp_path: Path) -> None:
    """The machine surface must carry the refusal too, not an empty successful report."""

    _seed_scorecard(tmp_path, {"hello": "world"})

    result = runner.invoke(app, ["ingest-scorecard", "--target", str(tmp_path), "--format", "json"])

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["found"] is True
    assert "is not an OpenSSF Scorecard result" in payload["error"]
    assert payload["corroborated_controls"] == []


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("date only", {"date": "2026-06-01T00:00:00Z"}),
        ("score only", {"score": 7.3}),
        # A real Scorecard check that the kit's 12-row crosswalk does not map: the
        # document IS a Scorecard result, so refusing it would be a false refusal. This
        # is why the shape test reads the loaded bundle, not the mapped report.
        ("unmapped check only", {"checks": [{"name": "CII-Best-Practices", "score": 3}]}),
    ],
)
def test_ingest_scorecard_still_accepts_a_partial_scorecard_result(
    label: str, payload: dict[str, object], tmp_path: Path
) -> None:
    _seed_scorecard(tmp_path, payload)

    result = runner.invoke(app, ["ingest-scorecard", "--target", str(tmp_path)])

    assert result.exit_code == 0, f"{label}: {result.output}"
    assert "ingested" in result.stdout


def test_ingest_scorecard_still_accepts_a_full_scorecard_result(tmp_path: Path) -> None:
    _seed_scorecard(
        tmp_path,
        {
            "date": "2026-06-01T00:00:00Z",
            "score": 7.3,
            "checks": [{"name": "Token-Permissions", "score": 9, "reason": "read-only"}],
        },
    )

    result = runner.invoke(app, ["ingest-scorecard", "--target", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "CI-PERM-006" in result.stdout


# --------------------------------------------------------------------------- #
# 3. M-002: correlate-findings echoes --output as typed
# --------------------------------------------------------------------------- #


def test_correlate_findings_echoes_a_relative_output_verbatim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / _MARKER / "repo"
    repo.mkdir(parents=True)
    monkeypatch.chdir(repo)

    result = runner.invoke(app, ["correlate-findings", "--target", ".", "--output", "f.json"])

    assert result.exit_code == 0, result.output
    assert "Wrote findings/1.0 artifact: f.json" in _flat(result.stdout)
    assert _MARKER not in result.stdout
    assert (repo / "f.json").is_file()


def test_correlate_findings_default_output_is_shown_as_the_documented_relative_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default is documented as ``<target>/.oss-policy-kit/findings.json``, not an
    absolute path, so the default run leaked too."""

    repo = tmp_path / _MARKER / "repo"
    repo.mkdir(parents=True)
    monkeypatch.chdir(repo)

    result = runner.invoke(app, ["correlate-findings", "--target", "."])

    assert result.exit_code == 0, result.output
    assert "Wrote findings/1.0 artifact: .oss-policy-kit/findings.json" in _flat(result.stdout)
    assert _MARKER not in result.stdout


def test_correlate_findings_cites_an_absolute_output_relative_to_the_target(tmp_path: Path) -> None:
    """An absolute argument is the user's own string, but it still must not be printed."""

    repo = tmp_path / _MARKER / "repo"
    repo.mkdir(parents=True)
    out = repo / "sub" / "f.json"

    result = runner.invoke(app, ["correlate-findings", "--target", str(repo), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert "Wrote findings/1.0 artifact: sub/f.json" in _flat(result.stdout)
    assert _MARKER not in result.stdout


# --------------------------------------------------------------------------- #
# 4. correlate-findings says so when the supplied enrichment file was not used
# --------------------------------------------------------------------------- #


def _correlate_with_enrichment(repo: Path, monkeypatch: pytest.MonkeyPatch) -> Result:
    monkeypatch.setenv("COLUMNS", "200")  # keep Rich from wrapping the warning mid-phrase
    monkeypatch.chdir(repo)
    return runner.invoke(
        app,
        ["correlate-findings", "--target", ".", "--output", "f.json", "--enrichment-file", "enrich.json"],
    )


def test_correlate_findings_warns_when_the_supplied_enrichment_file_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "enrich.json").write_text("{ not json", encoding="utf-8")

    result = _correlate_with_enrichment(repo, monkeypatch)

    assert result.exit_code == 0, result.output
    assert "--enrichment-file enrich.json was not used" in _flat(result.output)


def test_correlate_findings_warning_does_not_change_the_artifact_or_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The data was always right; only the operator was uninformed. Keep it that way."""

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "enrich.json").write_text("{ not json", encoding="utf-8")

    result = _correlate_with_enrichment(repo, monkeypatch)

    assert result.exit_code == 0, result.output
    artifact = json.loads((repo / "f.json").read_text(encoding="utf-8"))
    record = next(s for s in artifact["sources_read"] if s["kind"] == "enrichment-snapshot")
    assert record["status"] == "unreadable"


def test_correlate_findings_stays_quiet_when_the_enrichment_file_was_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guard against a warning that fires on the happy path and trains operators to ignore it."""

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "enrich.json").write_text(json.dumps({"as_of": "2026-06-01", "vulnerabilities": {}}), encoding="utf-8")

    result = _correlate_with_enrichment(repo, monkeypatch)

    assert result.exit_code == 0, result.output
    assert "was not used" not in _flat(result.output)
