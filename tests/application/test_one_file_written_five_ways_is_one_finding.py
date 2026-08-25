"""The same file written five ways must not become five findings with five ids.

The `code` correlation key is `rule + file + line`, and `location.file` was whatever the
source document said. Measured on one zizmor drop reporting one rule at one line, with
the path spelled five ways:

    5 spellings of ONE file -> 5 findings, each merged_from=1

The sharp edge is not the duplicate rows. A scanner running on Windows writes
`src\\app.py` and the same scanner on Linux CI writes `src/app.py`, so the same commit
produced different finding IDS depending on which machine scanned it. The artifact is
documented as "deterministic in content -- the finding ids, ranks, and ordering are
identical every time"; across platforms it was not.

Normalizing is done in `FindingLocation` itself rather than at each normalizer, so it is
a property of the type instead of a rule four call sites have to remember.

The limits are asserted too, because each is a place where "normalize harder" would turn
a spelling fix into a claim the kit cannot support: `..` is not resolved, a URI is not
rewritten into a path, and a UNC host is not mistaken for a doubled separator.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.finding_correlation import correlate
from oss_policy_kit.application.finding_sarif import normalize_sarif_sources
from oss_policy_kit.domain.findings import FindingLocation, normalize_path_spelling

_SARIF_DIR = Path(".oss-policy-kit") / "evidence" / "sast"

_BACKSLASH = "src" + chr(92) + "app.py"

#: Five ways to write the same path. Assembled rather than typed so the backslash form
#: survives every layer between this file and the assertion.
_SPELLINGS: tuple[str, ...] = ("src/app.py", "./src/app.py", _BACKSLASH, "src//app.py", "src/./app.py")


def _drop(repo: Path, uris: tuple[str, ...]) -> Path:
    directory = repo / _SARIF_DIR
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "zizmor", "version": "1.0"}},
                "results": [
                    {
                        "ruleId": "dangerous-exec",
                        "level": "error",
                        "message": {"text": "Detected use of exec"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                    for uri in uris
                ],
            }
        ],
    }
    (directory / "zizmor.sarif.json").write_text(json.dumps(document), encoding="utf-8")
    return repo


def _correlated(repo: Path) -> list:
    findings, _records = normalize_sarif_sources(repo)
    return list(correlate(findings).findings)


def test_five_spellings_of_one_path_are_one_finding(tmp_path: Path) -> None:
    findings = _correlated(_drop(tmp_path, _SPELLINGS))

    assert len(findings) == 1, (
        f"{len(_SPELLINGS)} spellings of one file at one line produced {len(findings)} "
        "findings. They are one issue, and an operator sees a list padded with copies."
    )
    assert findings[0].location.file == "src/app.py"
    assert findings[0].correlation is not None
    assert findings[0].correlation.merged_from == len(_SPELLINGS)


def test_the_same_issue_gets_the_same_id_on_windows_and_on_linux(tmp_path: Path) -> None:
    """The reason this matters beyond duplicate rows.

    A scanner writes the separator its platform uses. Two ids for one issue makes the
    artifact undiffable between a laptop and CI.
    """

    windows = _correlated(_drop(tmp_path / "win", (_BACKSLASH,)))
    posix = _correlated(_drop(tmp_path / "posix", ("src/app.py",)))

    assert windows[0].id == posix[0].id, (
        f"the same finding is {windows[0].id} when scanned on Windows and {posix[0].id} "
        "on Linux. Nothing downstream can tell they are the same issue."
    )


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("src/app.py", "src/app.py"),
        ("./src/app.py", "src/app.py"),
        (_BACKSLASH, "src/app.py"),
        ("src//app.py", "src/app.py"),
        ("src/./app.py", "src/app.py"),
        ("C:" + chr(92) + "proj" + chr(92) + "a.py", "C:/proj/a.py"),
        ("/etc/app.py", "/etc/app.py"),
        ("src/", "src"),
    ],
    ids=lambda v: v.replace(chr(92), "B"),
)
def test_the_spellings_that_are_normalized(raw: str, expected: str) -> None:
    assert normalize_path_spelling(raw) == expected


def test_a_parent_segment_is_never_resolved() -> None:
    """Resolving `..` is a claim about the filesystem; this layer only reads a document."""

    assert normalize_path_spelling("src/../app.py") == "src/../app.py"
    assert normalize_path_spelling("..") == ".."


def test_a_uri_is_left_exactly_as_written() -> None:
    """A `file://` reference is a different KIND of reference, not a different spelling.

    Rewriting one into a relative path would assert where the repository root is, and
    collapsing its `//` would corrupt the scheme.
    """

    assert normalize_path_spelling("file:///src/app.py") == "file:///src/app.py"
    assert normalize_path_spelling("https://example.test/a//b") == "https://example.test/a//b"


def test_a_uri_and_a_path_stay_separate_findings(tmp_path: Path) -> None:
    """The limitation, asserted end to end so it is not mistaken for full normalization."""

    findings = _correlated(_drop(tmp_path, ("src/app.py", "file:///src/app.py")))

    assert len(findings) == 2
    assert {f.location.file for f in findings} == {"src/app.py", "file:///src/app.py"}


def test_a_unc_host_is_not_a_doubled_separator() -> None:
    """On Windows a leading `//` names a host. Collapsing it changes which machine."""

    assert normalize_path_spelling("//fileserver/share/app.py") == "//fileserver/share/app.py"
    assert normalize_path_spelling(chr(92) * 2 + "fileserver" + chr(92) + "share") == "//fileserver/share"


def test_the_type_normalizes_and_not_only_the_normalizers() -> None:
    """Built directly, with no normalizer in the way."""

    assert FindingLocation(file=_BACKSLASH).file == "src/app.py"
    assert FindingLocation().file is None, "a location with no file must not gain one"


def test_a_path_that_normalizes_to_nothing_keeps_what_it_was_given() -> None:
    """`.` has no segments left after cleaning; an empty string would lose the reference."""

    assert normalize_path_spelling(".") == "."
