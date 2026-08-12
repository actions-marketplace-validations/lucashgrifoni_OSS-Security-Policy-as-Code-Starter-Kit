"""Reading the two YAML files an adopter writes, and the one the kit ships.

A project config and an external profile both come from outside the kit, which means every field
is whatever someone typed. The loaders answer that in two different registers, and both are
asserted here:

- *refuse* what would change a verdict if guessed at -- a missing file, an unknown schema, a
  `report_json_contract` the build cannot honour -- because silently defaulting a contract is how
  a repository ends up gated against rules nobody chose;
- *ignore* what is merely noise -- a `detected` block of the wrong type, a catalog entry that is
  not a mapping -- because refusing a whole catalog over one malformed row would take every other
  control down with it.

The external-profile hints are worth their own tests. They are the difference between an adopter
fixing a one-word mistake in thirty seconds and filing an issue, and the two most common
mistakes -- writing `profile_id` instead of `id`, and nesting `controls` -- each get a hint
naming the fix.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.config_loader import _optional_str, load_project_config
from oss_policy_kit.application.loader import LoadError, ProfileLoadError, load_catalog, load_profile
from oss_policy_kit.domain.errors import InvalidInputError

_CONFIG_HEAD = (
    "schema_version: oss-policy-kit/config/v1\n"
    "profile: github-level-2\n"
    "fail_on: fail\n"
    "output_dir: out\n"
    "report_json_contract: '2.0'\n"
)


def _config(root: Path, body: str) -> Path:
    path = root / ".oss-policy-kit.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _profile(root: Path, body: str) -> Path:
    path = root / "profile.yaml"
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Project config
# --------------------------------------------------------------------------- #


def test_a_config_that_is_not_there_is_named_by_its_filename(tmp_path: Path) -> None:
    """The adopter passed `--config`; echoing the resolved path would leak their home dir."""

    with pytest.raises(InvalidInputError, match="Config file not found: missing.yaml"):
        load_project_config(tmp_path / "missing.yaml")


def test_a_directory_where_a_config_should_be_is_the_same_refusal(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").mkdir()

    with pytest.raises(InvalidInputError, match="not found"):
        load_project_config(tmp_path / "config.yaml")


def test_a_detected_block_of_the_wrong_shape_is_ignored_rather_than_fatal(tmp_path: Path) -> None:
    """`detected` is a cache of what a previous run inferred; a bad one is not worth refusing."""

    config = load_project_config(_config(tmp_path, _CONFIG_HEAD + "detected: not-a-mapping\n"))

    assert config.detected_platform is None
    assert config.detected_primary_stack is None
    assert config.profile == "github-level-2"


def test_a_detected_block_that_is_a_mapping_is_kept(tmp_path: Path) -> None:
    config = load_project_config(
        _config(tmp_path, _CONFIG_HEAD + "detected:\n  platform: github\n  primary_stack: python\n")
    )

    assert config.detected_platform == "github"
    assert config.detected_primary_stack == "python"


@pytest.mark.parametrize(
    ("label", "value"),
    [("absent", {}), ("null", {"k": None}), ("a number", {"k": 7}), ("a list", {"k": ["a"]}), ("blank", {"k": "  "})],
)
def test_an_optional_string_that_is_not_a_usable_string_reads_as_absent(label: str, value: dict[str, object]) -> None:
    """Returning `7` here would put a number where every caller expects text or nothing."""

    assert _optional_str(value, "k") is None, label


def test_an_optional_string_is_stripped() -> None:
    assert _optional_str({"k": "  github-level-2  "}, "k") == "github-level-2"


# --------------------------------------------------------------------------- #
# The bundled catalog
# --------------------------------------------------------------------------- #


def test_a_catalog_entry_that_is_not_a_mapping_is_skipped_without_losing_the_rest(tmp_path: Path) -> None:
    """One malformed row must not take every other control down with it."""

    catalog_yaml = tmp_path / "catalog.yaml"
    catalog_yaml.write_text(
        "controls:\n"
        "  - just-a-string\n"
        "  - - a\n"
        "    - list\n"
        "  - id: TEST-001\n"
        "    title: A real control\n"
        "    assurance: signal\n",
        encoding="utf-8",
    )

    assert list(load_catalog(catalog_yaml)) == ["TEST-001"]


def test_a_catalog_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    """Here refusing is right: there is no catalog to salvage, only a file that is not one."""

    catalog_yaml = tmp_path / "catalog.yaml"
    catalog_yaml.write_text("- a\n- b\n", encoding="utf-8")

    with pytest.raises(LoadError, match="root must be a mapping"):
        load_catalog(catalog_yaml)


def test_a_yaml_file_that_will_not_parse_is_named_by_its_basename(tmp_path: Path) -> None:
    """The message reaches an operator; the absolute path would reach them too (M-002)."""

    catalog_yaml = tmp_path / "catalog.yaml"
    catalog_yaml.write_text("controls: [\n", encoding="utf-8")

    with pytest.raises(LoadError) as excinfo:
        load_catalog(catalog_yaml)

    assert "catalog.yaml" in str(excinfo.value)
    assert str(tmp_path) not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# External profiles
# --------------------------------------------------------------------------- #


def test_the_wrong_id_field_is_answered_with_the_right_one(tmp_path: Path) -> None:
    """`profile_id` is the reports/2.0 spelling, so writing it here is an easy mistake."""

    path = _profile(tmp_path, "profile_id: mine\ntitle: Mine\ncontrols: [CI-WF-005]\n")

    with pytest.raises(ProfileLoadError) as excinfo:
        load_profile(path, validate_external_schema=True)

    assert "use field 'id' (not 'profile_id')" in str(excinfo.value)


def test_a_nested_controls_list_is_answered_with_an_example(tmp_path: Path) -> None:
    """The hint carries a literal line the adopter can paste over what they wrote."""

    path = _profile(tmp_path, "id: mine\ntitle: Mine\ncontrols:\n  - id: CI-WF-005\n")

    with pytest.raises(ProfileLoadError) as excinfo:
        load_profile(path, validate_external_schema=True)

    assert "flat list of control ID strings" in str(excinfo.value)
    assert "GOV-SEC-001" in str(excinfo.value)


def test_a_schema_failure_with_no_known_hint_still_reports_the_reason(tmp_path: Path) -> None:
    """The counterpart: an unrecognised failure must not be swallowed for lack of advice."""

    path = _profile(tmp_path, "id: mine\ntitle: 7\ncontrols: [CI-WF-005]\n")

    with pytest.raises(ProfileLoadError) as excinfo:
        load_profile(path, validate_external_schema=True)

    assert "failed schema validation" in str(excinfo.value)


def test_a_well_formed_external_profile_loads(tmp_path: Path) -> None:
    path = _profile(tmp_path, "id: mine\ntitle: Mine\ncontrols: [CI-WF-005, GOV-SEC-001]\n")

    profile = load_profile(path, validate_external_schema=True)

    assert profile.id == "mine"
    assert list(profile.control_ids) == ["CI-WF-005", "GOV-SEC-001"]
