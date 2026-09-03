"""Small readers that decide what a control is even allowed to look at.

None of these is a control. They pick which files get scanned, count what a scan reported, and
resolve the path an operator typed -- which is precisely why a mistake in one is invisible: the
control that depends on it still returns a verdict, just about a smaller world than the adopter
believes it examined.

The recurring shape is a walk that must skip what it cannot use *narrowly*. Each test below pairs
the thing that should be skipped with a sibling that must survive, because a walk that quietly
returns nothing looks exactly like a repository with nothing to find.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.application._evidence_rules import (
    files_scanned_list,
    rule_finding_count,
    sample_finding_files,
)
from oss_policy_kit.application.applicability import _any_file_matches
from oss_policy_kit.application.evaluators._shared import (
    _detect_spdx_version,
    _find_sbom_files,
    _provenance_artifact_digest_strings,
)
from oss_policy_kit.domain.errors import InvalidInputError


def _write(root: Path, rel: str, body: str = "x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Counting what a scan reported
# --------------------------------------------------------------------------- #


def test_a_rule_with_recorded_findings_is_counted() -> None:
    assert rule_finding_count({"findings_by_rule": {"IAC-TF-001": 3}}, "IAC-TF-001") == 3


@pytest.mark.parametrize(
    ("label", "data"),
    [
        ("no key at all", {}),
        ("a list instead of a map", {"findings_by_rule": ["IAC-TF-001"]}),
        ("a string", {"findings_by_rule": "IAC-TF-001=3"}),
        ("null", {"findings_by_rule": None}),
        ("the rule simply absent", {"findings_by_rule": {"IAC-TF-002": 3}}),
    ],
)
def test_a_tally_the_reader_cannot_use_counts_as_none(label: str, data: dict[str, Any]) -> None:
    """Zero here means "this rule reported nothing", which is the answer a control acts on."""

    assert rule_finding_count(data, "IAC-TF-001") == 0, label


@pytest.mark.parametrize(
    ("label", "data", "expected"),
    [
        ("a real list", {"files_scanned": ["a.tf", "b.tf"]}, ["a.tf", "b.tf"]),
        ("absent", {}, []),
        ("null", {"files_scanned": None}, []),
        ("not a list", {"files_scanned": "a.tf"}, []),
    ],
)
def test_the_scanned_file_list_is_only_ever_a_list(label: str, data: dict[str, Any], expected: list[str]) -> None:
    assert files_scanned_list(data) == expected, label


def test_sample_files_are_distinct_and_capped() -> None:
    """The sample goes in a report line; repeating one file would crowd out the others."""

    data = {
        "findings": [
            {"rule_id": "R1", "file": "a.tf"},
            {"rule_id": "R1", "file": "a.tf"},
            {"rule_id": "R1", "file": "b.tf"},
            {"rule_id": "R1", "file": "c.tf"},
            {"rule_id": "R1", "file": "d.tf"},
        ]
    }
    assert sample_finding_files(data, "R1", limit=3) == ["a.tf", "b.tf", "c.tf"]


@pytest.mark.parametrize(
    ("label", "finding"),
    [
        ("another rule", {"rule_id": "R2", "file": "x.tf"}),
        ("no file recorded", {"rule_id": "R1"}),
        ("a file that is not a string", {"rule_id": "R1", "file": 7}),
        ("an empty filename", {"rule_id": "R1", "file": ""}),
        ("an entry that is not an object", "R1"),
    ],
)
def test_findings_that_name_no_usable_file_are_skipped(label: str, finding: Any) -> None:
    data = {"findings": [finding, {"rule_id": "R1", "file": "real.tf"}]}
    assert sample_finding_files(data, "R1") == ["real.tf"], label


# --------------------------------------------------------------------------- #
# Deciding whether a control applies at all
# --------------------------------------------------------------------------- #


def test_a_matching_file_makes_a_control_applicable(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM scratch\n")
    assert _any_file_matches(tmp_path, ("**/Dockerfile",)) is True


def test_a_directory_that_matches_the_pattern_is_not_a_file(tmp_path: Path) -> None:
    """`Dockerfile/` as a directory would otherwise make a container control applicable."""

    (tmp_path / "Dockerfile").mkdir()
    assert _any_file_matches(tmp_path, ("**/Dockerfile",)) is False


def test_a_pattern_the_walker_cannot_use_does_not_stop_the_others(tmp_path: Path) -> None:
    """A bad pattern must never raise into the evaluation loop, nor mask a later good one."""

    _write(tmp_path, "Dockerfile", "FROM scratch\n")
    assert _any_file_matches(tmp_path, ("", "**/Dockerfile")) is True


def test_nothing_matching_is_not_applicable(tmp_path: Path) -> None:
    assert _any_file_matches(tmp_path, ("**/Dockerfile", "**/*.tf")) is False


# --------------------------------------------------------------------------- #
# Finding an SBOM, and reading its version
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    ["sbom.json", "bom.xml", "release.spdx", "release.spdx.json", "app.cdx.json", "nested/dir/sbom.json"],
)
def test_every_sbom_naming_convention_is_found(name: str, tmp_path: Path) -> None:
    _write(tmp_path, name, "{}")
    assert [p.name for p in _find_sbom_files(tmp_path)] == [Path(name).name]


def test_a_directory_named_like_an_sbom_is_not_one(tmp_path: Path) -> None:
    (tmp_path / "sbom.json").mkdir()
    assert _find_sbom_files(tmp_path) == []


@pytest.mark.parametrize(
    ("label", "sample", "expected"),
    [
        ("spdx 3 by spec version", '{"specVersion": "3.0.1", "@context": "https://spdx.org"}', ("spdx", "3.0.1")),
        ("spdx 3 by context url", '{"@context": "https://spdx.dev/spec/3.0/"}', ("spdx", "3.0")),
        ("spdx 2 json", '{"spdxVersion": "SPDX-2.3"}', ("spdx", "2.3")),
        ("spdx 2 tag-value", "SPDXVersion: SPDX-2.2\nDataLicense: CC0-1.0\n", ("spdx", "2.2")),
    ],
)
def test_each_spdx_flavour_is_recognised_with_its_version(label: str, sample: str, expected: tuple[str, str]) -> None:
    """The version is reported to an auditor; guessing it wrong misstates the format in use."""

    assert _detect_spdx_version(sample) == expected, label


@pytest.mark.parametrize(
    ("label", "sample"),
    [
        ("a CycloneDX document", '{"bomFormat": "CycloneDX", "specVersion": "1.6"}'),
        ("arbitrary json", '{"name": "app"}'),
        ("empty", ""),
    ],
)
def test_a_document_that_is_not_spdx_is_not_claimed_as_spdx(label: str, sample: str) -> None:
    assert _detect_spdx_version(sample) is None, label


# --------------------------------------------------------------------------- #
# Digests out of a provenance attestation
# --------------------------------------------------------------------------- #


def test_both_digests_are_collected_in_order() -> None:
    data = {"artifact": {"digest_sha256": "a" * 64}, "attestation": {"digest_sha256": "b" * 64}}
    assert _provenance_artifact_digest_strings(data) == ["a" * 64, "b" * 64]


@pytest.mark.parametrize(
    ("label", "data"),
    [
        ("artifact block missing", {"attestation": {"digest_sha256": "b" * 64}}),
        ("artifact is not an object", {"artifact": "x", "attestation": {"digest_sha256": "b" * 64}}),
        (
            "artifact digest is not a string",
            {"artifact": {"digest_sha256": 7}, "attestation": {"digest_sha256": "b" * 64}},
        ),
    ],
)
def test_an_unusable_artifact_digest_does_not_cost_the_attestation_one(label: str, data: dict[str, Any]) -> None:
    """Each block is read independently; one missing must not hide the other from the gate."""

    assert _provenance_artifact_digest_strings(data) == ["b" * 64], label


@pytest.mark.parametrize(
    ("label", "data"),
    [
        ("attestation block missing", {"artifact": {"digest_sha256": "a" * 64}}),
        ("attestation is not an object", {"artifact": {"digest_sha256": "a" * 64}, "attestation": []}),
        (
            "attestation digest is null",
            {"artifact": {"digest_sha256": "a" * 64}, "attestation": {"digest_sha256": None}},
        ),
    ],
)
def test_an_unusable_attestation_digest_does_not_cost_the_artifact_one(label: str, data: dict[str, Any]) -> None:
    assert _provenance_artifact_digest_strings(data) == ["a" * 64], label


def test_an_empty_document_yields_no_digests() -> None:
    assert _provenance_artifact_digest_strings({}) == []


# --------------------------------------------------------------------------- #
# The path the operator typed
# --------------------------------------------------------------------------- #


def test_a_real_directory_resolves(tmp_path: Path) -> None:
    assert resolve_existing_dir(str(tmp_path)) == tmp_path.resolve()


def test_a_path_that_is_not_a_directory_is_refused_in_the_words_the_operator_used(tmp_path: Path) -> None:
    """M-002: `resolve()` would make a relative target absolute and leak cwd and username."""

    _write(tmp_path, "file.txt")
    with pytest.raises(InvalidInputError, match=r"Not a directory or does not exist: .*file\.txt"):
        resolve_existing_dir(str(tmp_path / "file.txt"))


def test_a_path_the_operating_system_refuses_to_resolve_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit 2, not a traceback: an unresolvable path is something the adopter typed."""

    def _refuse(_self: Path, *_a: object, **_k: object) -> Path:
        raise OSError("The filename, directory name, or volume label syntax is incorrect")

    monkeypatch.setattr(Path, "resolve", _refuse)
    with pytest.raises(InvalidInputError, match="Invalid path"):
        resolve_existing_dir(str(tmp_path))
