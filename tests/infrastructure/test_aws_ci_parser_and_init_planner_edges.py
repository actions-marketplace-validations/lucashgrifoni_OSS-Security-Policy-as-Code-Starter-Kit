"""Two decisions taken before any evaluation runs: what the buildspec says, and what to init.

The AWS CI parser reads buildspec and CodePipeline files out of a scanned repository, so
every shape it can be handed has to resolve to a decision rather than an exception. The
inline-secret heuristic in particular is the one that must not fire on ordinary
configuration -- a false "hardcoded credential" sends someone rotating a key that does not
exist, and enough of those teach a team to ignore the tool.

`init` runs before anything is written. Its platform and profile resolution decide what
lands on disk, and a wrong answer there is a config file `evaluate` will later reject.

Both were covered on their main paths only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import init_planner as ip
from oss_policy_kit.domain.errors import InvalidInputError
from oss_policy_kit.infrastructure import aws_ci_parser as ap
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis

# --------------------------------------------------------------------------- #
# committed CodePipeline exports
# --------------------------------------------------------------------------- #


def test_a_valid_export_yields_its_pipeline_object(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.json"
    path.write_text('{"pipeline": {"roleArn": "arn:aws:iam::1:role/x"}}', encoding="utf-8")

    assert ap.load_committed_codepipeline_document(path) == {"roleArn": "arn:aws:iam::1:role/x"}


@pytest.mark.parametrize(
    ("label", "name", "body"),
    [
        ("unparseable JSON", "pipeline.json", "{not json"),
        ("unparseable YAML", "pipeline.yaml", "pipeline:\n  - [\n"),
        ("a JSON array at the root", "pipeline.json", "[1, 2, 3]"),
        ("no pipeline key", "pipeline.json", '{"other": {}}'),
        ("pipeline is not an object", "pipeline.json", '{"pipeline": "arn"}'),
    ],
)
def test_an_export_that_is_not_a_pipeline_yields_none(tmp_path: Path, label: str, name: str, body: str) -> None:
    """None is the signal the caller checks; raising here would end the whole scan."""

    path = tmp_path / name
    path.write_text(body, encoding="utf-8")

    assert ap.load_committed_codepipeline_document(path) is None, label


def test_a_file_that_cannot_be_read_at_all_yields_none(tmp_path: Path) -> None:
    """A directory named like an export is one way this happens on a real clone."""

    path = tmp_path / "pipeline.json"
    path.mkdir()

    assert ap.load_committed_codepipeline_document(path) is None


def test_an_unparseable_export_is_recorded_as_a_parse_error(tmp_path: Path) -> None:
    """Silently skipping it would make a broken export indistinguishable from a clean scan."""

    path = tmp_path / "pipeline.json"
    path.write_text("{not json", encoding="utf-8")
    result = AwsCiAnalysis()

    ap._scan_codepipeline_export(path, result)

    assert [p for p, _reason in result.parse_errors] == [path]
    assert result.codepipeline_valid_export_paths == []


# --------------------------------------------------------------------------- #
# the inline-secret heuristic
# --------------------------------------------------------------------------- #


def test_an_aws_access_key_id_in_a_plaintext_variable_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / "buildspec.yml"
    result = AwsCiAnalysis()

    ap._plaintext_env_variables_risk({"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}, path, result)

    assert result.inline_secret_risk_paths == [path]


def test_a_long_opaque_token_in_a_plaintext_variable_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / "buildspec.yml"
    result = AwsCiAnalysis()

    ap._plaintext_env_variables_risk({"TOKEN": "A" * 64}, path, result)

    assert result.inline_secret_risk_paths == [path]


@pytest.mark.parametrize(
    ("label", "values"),
    [
        ("an empty string", {"EMPTY": ""}),
        ("only whitespace", {"BLANK": "   "}),
        ("a non-string value", {"PORT": 8080}),
        ("a boolean", {"DEBUG": True}),
        ("a nested block", {"NESTED": {"a": "b"}}),
        ("an ordinary short value", {"REGION": "us-east-1"}),
        ("a long value with characters no token uses", {"CMD": "echo " + "hello world " * 8}),
    ],
)
def test_ordinary_configuration_is_not_reported_as_a_hardcoded_secret(
    tmp_path: Path, label: str, values: dict[str, Any]
) -> None:
    """A false positive here sends someone rotating a key that does not exist.

    Enough of those and the team stops reading the tool's output, which costs more than the
    finding was ever worth.
    """

    result = AwsCiAnalysis()

    ap._plaintext_env_variables_risk(values, tmp_path / "buildspec.yml", result)

    assert result.inline_secret_risk_paths == [], label


def test_a_file_is_reported_once_even_with_several_risky_variables(tmp_path: Path) -> None:
    """The finding is about the file, and this list becomes the control's evidence_sources.

    Listing one buildspec three times reads as three independent pieces of evidence for a
    single file. Found by writing this test: the append happened per matching value.
    """

    path = tmp_path / "buildspec.yml"
    result = AwsCiAnalysis()

    ap._plaintext_env_variables_risk(
        {"A": "AKIAIOSFODNN7EXAMPLE", "B": "B" * 70, "SECRET_TOKEN": "x" * 20},
        path,
        result,
    )

    assert result.inline_secret_risk_paths == [path]


def test_the_same_file_visited_twice_is_still_reported_once(tmp_path: Path) -> None:
    """The recursive env walk can reach one file's variables more than once."""

    path = tmp_path / "buildspec.yml"
    result = AwsCiAnalysis()

    ap._plaintext_env_variables_risk({"A": "AKIAIOSFODNN7EXAMPLE"}, path, result)
    ap._plaintext_env_variables_risk({"B": "AKIAIOSFODNN7EXAMPLE"}, path, result)

    assert result.inline_secret_risk_paths == [path]


def test_two_different_files_are_both_reported(tmp_path: Path) -> None:
    """Deduplication must be per path, not a cap of one finding overall."""

    result = AwsCiAnalysis()
    first = tmp_path / "buildspec.yml"
    second = tmp_path / "buildspec-release.yml"

    ap._plaintext_env_variables_risk({"A": "AKIAIOSFODNN7EXAMPLE"}, first, result)
    ap._plaintext_env_variables_risk({"A": "AKIAIOSFODNN7EXAMPLE"}, second, result)

    assert result.inline_secret_risk_paths == [first, second]


# --------------------------------------------------------------------------- #
# the substring fallback when YAML will not parse
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("token", ["secrets-manager", "secretsmanager", "secrets_manager"])
def test_a_secrets_manager_hint_survives_a_buildspec_that_will_not_parse(tmp_path: Path, token: str) -> None:
    """All three spellings appear in real buildspecs; missing one loses the signal."""

    path = tmp_path / "buildspec.yml"
    result = AwsCiAnalysis()

    ap._raw_env_fallback(path, f"env:\n  {token}:\n    key: [", result)

    assert result.secrets_manager_signal_paths == [path]


@pytest.mark.parametrize("token", ["parameter-store", "parameter_store"])
def test_a_parameter_store_hint_survives_the_same_way(tmp_path: Path, token: str) -> None:
    path = tmp_path / "buildspec.yml"
    result = AwsCiAnalysis()

    ap._raw_env_fallback(path, f"env:\n  {token}:\n    key: [", result)

    assert result.parameter_store_signal_paths == [path]


def test_the_fallback_stays_quiet_when_neither_hint_is_present(tmp_path: Path) -> None:
    result = AwsCiAnalysis()

    ap._raw_env_fallback(tmp_path / "buildspec.yml", "version: 0.2\nphases:\n  build:\n", result)

    assert result.secrets_manager_signal_paths == []
    assert result.parameter_store_signal_paths == []


def test_the_structured_walk_stops_before_it_can_recurse_away(tmp_path: Path) -> None:
    """YAML from a scanned repository can nest arbitrarily; the walk is depth-bounded."""

    deep: Any = {"env": {"variables": {"K": "v"}}}
    for _ in range(60):
        deep = {"nested": deep}
    result = AwsCiAnalysis()

    ap._merge_structured_env_signals(deep, tmp_path / "buildspec.yml", result)

    assert result.inline_secret_risk_paths == []


# --------------------------------------------------------------------------- #
# init: platform resolution
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", [None, "", "   "])
def test_an_unset_platform_means_auto_detect(value: str | None) -> None:
    """None is the sentinel for "work it out from the clone", distinct from a bad value."""

    assert ip._validate_platform(value) is None


@pytest.mark.parametrize("value", ["GitHub", "  gitlab  ", "AZURE"])
def test_a_platform_is_normalized_before_it_is_checked(value: str) -> None:
    assert ip._validate_platform(value) == value.strip().lower()


def test_an_unsupported_platform_is_refused_with_an_actionable_message() -> None:
    """Exit 2 before anything is written, naming what is allowed."""

    with pytest.raises(InvalidInputError) as excinfo:
        ip._validate_platform("bitbucket")

    message = str(excinfo.value)
    for allowed in ("github", "gitlab", "azure", "aws"):
        assert allowed in message


# --------------------------------------------------------------------------- #
# init: platform detection from signals
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("signal_id", "expected"),
    [
        ("github_actions_workflows", "github"),
        ("gitlab_ci_yaml", "gitlab"),
        ("azure_pipelines_yaml", "azure"),
        ("aws_codebuild_buildspec", "aws"),
    ],
)
def test_each_platform_is_detected_from_its_own_signal_prefix(signal_id: str, expected: str) -> None:
    assert ip._detect_platform_from_signals([{"id": signal_id}]) == expected


def test_the_documented_priority_holds_when_several_platforms_are_present() -> None:
    """It has to match `build_profile_recommendation`, or init reports a platform the
    recommendation did not use."""

    signals = [
        {"id": "aws_codebuild_buildspec"},
        {"id": "azure_pipelines_yaml"},
        {"id": "gitlab_ci_yaml"},
        {"id": "github_actions_workflows"},
    ]

    assert ip._detect_platform_from_signals(signals) == "github"


@pytest.mark.parametrize("signals", [[], [{"id": "python_pyproject"}], [{}]])
def test_no_platform_signal_at_all_is_unknown_rather_than_a_guess(signals: list[dict[str, str]]) -> None:
    """ "unknown" is honest; picking a default would put the wrong workflow on disk."""

    assert ip._detect_platform_from_signals(signals) == "unknown"


# --------------------------------------------------------------------------- #
# init: profile resolution
# --------------------------------------------------------------------------- #


def test_a_recommendation_with_no_suggestions_falls_back_to_the_documented_default() -> None:
    """`init` still has to write something usable when the clone carries no signal."""

    profile, source = ip._pick_profile(
        forced_profile=None,
        forced_platform=None,
        recommendation=ip.ProfileRecommendation(),
    )

    assert profile == ip.DEFAULT_FALLBACK_PROFILE
    assert source == "fallback"


def test_the_top_recommendation_wins_when_there_is_one() -> None:
    """The negative case above only means something if a real suggestion is still used."""

    recommendation = ip.ProfileRecommendation(suggestions=[{"profile_id": "gitlab-level-2"}])

    profile, source = ip._pick_profile(
        forced_profile=None,
        forced_platform=None,
        recommendation=recommendation,
    )

    assert profile == "gitlab-level-2"
    assert source == "recommended"


@pytest.mark.parametrize("suggestion", [{}, {"profile_id": ""}, {"profile_id": "   "}, {"profile_id": 42}])
def test_a_suggestion_with_no_usable_id_falls_back_rather_than_writing_it(
    suggestion: dict[str, Any],
) -> None:
    """A blank or non-string id would land in `oss-policy-kit.yaml` and break `evaluate`."""

    recommendation = ip.ProfileRecommendation(suggestions=[suggestion])

    profile, source = ip._pick_profile(
        forced_profile=None,
        forced_platform=None,
        recommendation=recommendation,
    )

    assert profile == ip.DEFAULT_FALLBACK_PROFILE
    assert source == "fallback"


def test_a_bundled_profile_id_is_accepted() -> None:
    ip._validate_user_profile("github-level-1")


def test_an_unknown_profile_is_refused_before_anything_is_written() -> None:
    """Writing it would poison `oss-policy-kit.yaml` for every later `evaluate`."""

    with pytest.raises(InvalidInputError):
        ip._validate_user_profile("not-a-real-profile")


def test_a_profile_given_as_a_path_to_an_existing_file_is_accepted(tmp_path: Path) -> None:
    """The escape hatch for a custom profile the kit does not bundle."""

    custom = tmp_path / "custom.yaml"
    custom.write_text("id: custom\n", encoding="utf-8")

    ip._validate_user_profile(str(custom))
