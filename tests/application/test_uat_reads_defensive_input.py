"""Ordinary bad input at a read site must never become exit 3.

Every case here was reproduced against the shipped CLI: a deeply-nested document,
an integer literal past CPython's 4300-digit conversion limit, a file the process
cannot read, and an oversized project config. Each one used to reach the CLI's
last-resort handler as "Unexpected error" (exit 3) — the code the contract
reserves for a defect in the kit — and in the batch case it also threw away every
result the run had already computed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.adapters.scorecard_json import load_scorecard_auto, load_scorecard_json
from oss_policy_kit.application import batch_evaluate
from oss_policy_kit.application.batch_evaluate import is_likely_repository, run_batch_evaluation
from oss_policy_kit.application.config_loader import CONFIG_FILENAME, load_project_config
from oss_policy_kit.application.findings_report import _load_enrichment
from oss_policy_kit.application.input_limits import MAX_CONFIG_BYTES, MAX_JSON_DEPTH
from oss_policy_kit.application.loader import load_catalog, load_profile
from oss_policy_kit.cli.main import app, prepare_cli_args
from oss_policy_kit.domain.errors import InvalidInputError, LoadError

#: Far past MAX_JSON_DEPTH, and past the 1000 default recursion limit as well, so the
#: fixture is refused whichever layer catches it first.
#:
#: Depth must NOT be left to RecursionError alone. CPython 3.12 separates the Python
#: recursion limit from the C stack guard, so the C JSON scanner raises at this depth on
#: Windows' 1 MB stack and parses the document happily on Linux' 8 MB one -- this exact
#: fixture passed locally and failed on CI with "DID NOT RAISE". PyYAML's composer is
#: pure Python and hits the limit identically on both, which is why only the JSON branch
#: diverged. The explicit guard is what makes the answer the same everywhere.
_NESTING = 3000
#: Just past the explicit budget: deep enough to be refused, shallow enough that no
#: interpreter anywhere would run out of stack. If this one ever stops raising, the
#: explicit guard is gone, whatever the 3000-level fixture happens to do.
_JUST_PAST_BUDGET = MAX_JSON_DEPTH + 20
#: Past CPython's ``sys.get_int_max_str_digits()`` default of 4300.
_HUGE_INT = "9" * 5000

_VALID_CONFIG = "\n".join(
    [
        "schema_version: oss-policy-kit/config/v1",
        "profile: github-level-1",
        "fail_on: none",
        'output_dir: "out"',
    ]
)


def _deep_json() -> str:
    return "[" * _NESTING + "]" * _NESTING


def _deep_yaml() -> str:
    return "root: " + "[" * _NESTING + "]" * _NESTING + "\n"


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- config


def test_deeply_nested_project_config_is_a_usage_error(tmp_path: Path) -> None:
    """A hostile oss-policy-kit.yaml in a cloned repo must not crash `evaluate` with exit 3."""

    cfg = _write(tmp_path / CONFIG_FILENAME, _deep_yaml())

    with pytest.raises(InvalidInputError) as excinfo:
        load_project_config(cfg)

    assert "too deeply" in str(excinfo.value)


def test_project_config_with_over_long_integer_is_a_usage_error(tmp_path: Path) -> None:
    """A 5000-digit YAML scalar must be refused, not raise ValueError out of the loader."""

    cfg = _write(tmp_path / CONFIG_FILENAME, f"{_VALID_CONFIG}\nbuild: {_HUGE_INT}\n")

    with pytest.raises(InvalidInputError):
        load_project_config(cfg)


def test_oversize_project_config_is_refused_without_parsing(tmp_path: Path) -> None:
    """A multi-megabyte config must be refused up front, not parsed for ~14 s first."""

    padding = "# " + ("x" * 78) + "\n"
    body = _VALID_CONFIG + "\n" + padding * ((MAX_CONFIG_BYTES // len(padding)) + 16)
    cfg = _write(tmp_path / CONFIG_FILENAME, body)

    with pytest.raises(InvalidInputError) as excinfo:
        load_project_config(cfg)

    assert "exceeding" in str(excinfo.value)


def test_unreadable_project_config_reports_only_the_file_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A permission-denied config is an operational condition, and must not leak the path."""

    cfg = _write(tmp_path / CONFIG_FILENAME, _VALID_CONFIG)

    def _denied(*_args: object, **_kwargs: object) -> str:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", _denied)

    with pytest.raises(InvalidInputError) as excinfo:
        load_project_config(cfg)

    message = str(excinfo.value)
    assert CONFIG_FILENAME in message
    assert str(tmp_path) not in message


def test_evaluate_cli_exits_2_on_a_deeply_nested_project_config(tmp_path: Path) -> None:
    """End to end: the shipped `evaluate` must report a usage error, never exit 3."""

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    _write(repo / CONFIG_FILENAME, _deep_yaml())

    result = CliRunner().invoke(
        app,
        prepare_cli_args(
            ["evaluate", "--target", str(repo), "--profile", "github-level-1", "--output-dir", str(tmp_path / "out")]
        ),
    )

    assert result.exit_code == 2, result.output
    assert "Unexpected error" not in result.output
    assert "Traceback" not in result.output


# ------------------------------------------------------------------------ scorecard


def test_deeply_nested_scorecard_json_is_a_load_error(tmp_path: Path) -> None:
    """A hostile --scorecard-json must degrade to exit 2, not crash the evaluator."""

    path = _write(tmp_path / "scorecard-result.json", _deep_json())

    with pytest.raises(LoadError):
        load_scorecard_json(path)


def test_scorecard_json_depth_is_refused_by_budget_not_by_stack_exhaustion(tmp_path: Path) -> None:
    """The refusal must not depend on the interpreter running out of C stack.

    This depth is trivial for every platform's stack, so nothing raises RecursionError
    here. If the explicit budget is removed, this file parses cleanly and the test fails
    -- which is what the 3000-level fixture could not detect, because it happened to blow
    the stack on the maintainer's machine and not on CI.
    """

    body = "[" * _JUST_PAST_BUDGET + "]" * _JUST_PAST_BUDGET
    path = _write(tmp_path / "scorecard-result.json", body)

    with pytest.raises(LoadError) as excinfo:
        load_scorecard_json(path)

    assert "nested" in str(excinfo.value).lower()
    assert str(MAX_JSON_DEPTH) in str(excinfo.value)


def test_ordinary_scorecard_nesting_is_not_refused(tmp_path: Path) -> None:
    """The budget must be generous enough that no honest scorecard is rejected."""

    body = json.dumps({"score": 7.4, "checks": [{"name": "Branch-Protection", "score": 8}]})
    path = _write(tmp_path / "scorecard-result.json", body)

    bundle = load_scorecard_json(path)

    assert bundle.aggregate_score == 7.4
    assert [c.name for c in bundle.checks] == ["Branch-Protection"]


def test_scorecard_json_with_over_long_integer_is_a_load_error(tmp_path: Path) -> None:
    """CPython's 4300-digit int limit is bad input, not an internal error."""

    path = _write(tmp_path / "scorecard-result.json", '{"score": ' + _HUGE_INT + "}")

    with pytest.raises(LoadError):
        load_scorecard_json(path)


def test_deeply_nested_scorecard_yaml_is_a_load_error(tmp_path: Path) -> None:
    """The YAML branch of load_scorecard_auto needs the same guard as the JSON branch."""

    path = _write(tmp_path / "scorecard.yaml", _deep_yaml())

    with pytest.raises(LoadError):
        load_scorecard_auto(path)


def test_unreadable_scorecard_path_is_a_load_error(tmp_path: Path) -> None:
    """Reading a directory as a scorecard raises OSError; the user sees exit 2 instead."""

    with pytest.raises(LoadError):
        load_scorecard_json(tmp_path)


def test_malformed_scorecard_json_still_raises_json_decode_error(tmp_path: Path) -> None:
    """Guard: ordinary malformed JSON keeps its line/column CLI message (existing contract)."""

    path = _write(tmp_path / "scorecard-result.json", "{not json}")

    with pytest.raises(json.JSONDecodeError):
        load_scorecard_json(path)


# -------------------------------------------------------------------- catalog/profile


def test_catalog_load_error_does_not_advise_changing_the_interpreter(tmp_path: Path) -> None:
    """CPython's "use sys.set_int_max_str_digits()" is advice the adopter cannot act on."""

    catalog = _write(tmp_path / "catalog.yaml", f"controls: [{_HUGE_INT}]\n")

    with pytest.raises(LoadError) as excinfo:
        load_catalog(catalog)

    message = str(excinfo.value)
    assert "Failed to load catalog" in message
    assert "set_int_max_str_digits" not in message


def test_profile_load_error_does_not_advise_changing_the_interpreter(tmp_path: Path) -> None:
    """Same wording guarantee on the ``--profile <file>`` path."""

    profile = _write(tmp_path / "profile.yaml", f"id: p\ncontrols: [{_HUGE_INT}]\n")

    with pytest.raises(LoadError) as excinfo:
        load_profile(profile)

    message = str(excinfo.value)
    assert "Failed to load profile" in message
    assert "set_int_max_str_digits" not in message


# ----------------------------------------------------------------------- enrichment


def test_enrichment_snapshot_with_over_long_integer_is_recorded_unreadable(tmp_path: Path) -> None:
    """`correlate-findings` documents unreadable evidence as never raised — including this."""

    path = _write(tmp_path / "enrichment.json", '{"vulnerabilities": {"CVE-1": {"epss": ' + _HUGE_INT + "}}}")

    table, record = _load_enrichment(path)

    assert table == {}
    assert record.status == "unreadable"


def test_correlate_findings_cli_survives_an_over_long_integer_enrichment(tmp_path: Path) -> None:
    """End to end: a hostile --enrichment-file must not turn a read-only report into exit 3."""

    repo = tmp_path / "repo"
    repo.mkdir()
    enrichment = _write(tmp_path / "enrichment.json", '{"vulnerabilities": {"CVE-1": {"epss": ' + _HUGE_INT + "}}}")

    result = CliRunner().invoke(
        app,
        prepare_cli_args(
            [
                "correlate-findings",
                "--target",
                str(repo),
                "--enrichment-file",
                str(enrichment),
                "--output",
                str(tmp_path / "findings.json"),
            ]
        ),
    )

    assert result.exit_code == 0, result.output
    assert "Unexpected error" not in result.output


# ---------------------------------------------------------------------------- batch


def test_is_likely_repository_treats_permission_denied_as_no_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A child directory the process cannot stat must not abort batch discovery."""

    real_exists = Path.exists

    def _denied(self: Path, **kwargs: Any) -> bool:
        if self.name == "pyproject.toml":
            raise PermissionError(13, "Permission denied")
        return bool(real_exists(self, **kwargs))

    monkeypatch.setattr(Path, "exists", _denied)

    likely, signal = is_likely_repository(tmp_path)

    assert likely is False
    assert signal == ""


def test_batch_records_an_unreadable_target_and_keeps_going(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """One permission-denied repository must not discard the results of every other one."""

    mono = tmp_path / "mono"
    for name in ("a-repo", "b-repo", "c-repo"):
        child = mono / name
        child.mkdir(parents=True)
        (child / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    real_evaluate = batch_evaluate.evaluate_repository

    def _evaluate(**kwargs: Any) -> Any:
        if Path(kwargs["repo_root"]).name == "b-repo":
            raise PermissionError(13, "Permission denied")
        return real_evaluate(**kwargs)

    monkeypatch.setattr(batch_evaluate, "evaluate_repository", _evaluate)

    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )

    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    assert sorted(r["target_name"] for r in payload["runs"]) == ["a-repo", "c-repo"]
    skipped = {s["name"]: s for s in payload.get("skipped_directories", [])}
    assert "b-repo" in skipped
    assert "Permission denied" in skipped["b-repo"]["reason"]
    assert str(tmp_path) not in json.dumps(payload)


def test_batch_discovery_permission_error_is_a_usage_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An unlistable --target-root is an operational condition, reported as exit 2."""

    def _denied(_self: Path) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "iterdir", _denied)

    with pytest.raises(InvalidInputError):
        run_batch_evaluation(
            target_root=tmp_path,
            profile_ids=["github-level-1"],
            output_dir=tmp_path / "out",
            kit_root=None,
            include=None,
            exclude=None,
        )


def test_batch_cli_exits_cleanly_when_one_target_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: `evaluate-many` must finish and report, not exit 3 mid-batch."""

    mono = tmp_path / "mono"
    for name in ("a-repo", "b-repo"):
        child = mono / name
        child.mkdir(parents=True)
        (child / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    real_evaluate = batch_evaluate.evaluate_repository

    def _evaluate(**kwargs: Any) -> Any:
        if Path(kwargs["repo_root"]).name == "b-repo":
            raise PermissionError(13, "Permission denied")
        return real_evaluate(**kwargs)

    monkeypatch.setattr(batch_evaluate, "evaluate_repository", _evaluate)

    result = CliRunner().invoke(
        app,
        prepare_cli_args(
            [
                "evaluate-many",
                "--target-root",
                str(mono),
                "--profiles",
                "github-level-1",
                "--output-dir",
                str(tmp_path / "out"),
            ]
        ),
    )

    assert result.exit_code == 0, result.output
    assert "Unexpected error" not in result.output


def test_batch_still_evaluates_a_healthy_monorepo(tmp_path: Path) -> None:
    """Guard: the per-target degradation must not swallow a normal, successful run."""

    mono = tmp_path / "mono"
    mono.mkdir()
    target = mono / "app"
    target.mkdir()
    (target / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (target / "README.md").write_text("# app\n", encoding="utf-8")

    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )

    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    assert [r["target_name"] for r in payload["runs"]] == ["app"]
    assert not payload.get("skipped_directories")


def test_a_normal_project_config_still_loads(tmp_path: Path) -> None:
    """Guard: the size cap and the new guards must not reject an ordinary config."""

    cfg = _write(tmp_path / CONFIG_FILENAME, _VALID_CONFIG + "\n")

    config = load_project_config(cfg)

    assert config.profile == "github-level-1"
    assert config.fail_on == "none"
