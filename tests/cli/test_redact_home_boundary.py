"""`redact_home`: the last line of defence against printing the operator's account name.

Per-site fixes did not converge on this class -- three rounds of patching the commands a
validation happened to name still left most swept cases printing the home directory -- so
the guarantee moved to this one boundary function. That makes its behaviour worth pinning
precisely, in both directions.

It substitutes the literal `Path.home()` string rather than trying to recognise "an absolute
path", and the difference is the whole design: pattern-matching paths would mangle URLs,
regexes and quoted user input, while this can only ever fire on the one string whose
disclosure is the actual harm.

The home directory is monkeypatched to a synthetic value throughout, so these tests assert
the substitution rule rather than anything about the machine they run on -- and so a failure
message can never itself contain the real account name.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.cli import terminal_ui as u

_FAKE_HOME = "Z:\\srv\\profiles\\acct-name"
_FAKE_HOME_POSIX = "Z:/srv/profiles/acct-name"


@pytest.fixture(autouse=True)
def synthetic_home(monkeypatch: pytest.MonkeyPatch) -> None:
    """A home directory that is nobody's, so assertions never quote the real one."""

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path(_FAKE_HOME)))
    monkeypatch.setattr(u, "_ABSOLUTE_PATHS_ALLOWED", False)


# --------------------------------------------------------------------------- #
# what it redacts
# --------------------------------------------------------------------------- #


def test_the_home_prefix_becomes_a_tilde() -> None:
    assert u.redact_home(f"{_FAKE_HOME}\\repo\\SECURITY.md") == "~\\repo\\SECURITY.md"


def test_the_posix_spelling_is_covered_too() -> None:
    """A path can arrive POSIX-shaped from a config file even on Windows."""

    assert u.redact_home(f"{_FAKE_HOME_POSIX}/repo/SECURITY.md") == "~/repo/SECURITY.md"


def test_matching_is_case_insensitive() -> None:
    """Windows paths reach here in either case; a case difference is not a different home."""

    shouted = _FAKE_HOME.upper()

    assert "acct-name" not in u.redact_home(f"{shouted}\\repo").lower().replace("~", "")


def test_every_occurrence_in_one_string_is_replaced() -> None:
    """A diff or a table row can name the home directory several times."""

    text = f"from {_FAKE_HOME}\\a to {_FAKE_HOME}\\b"

    assert u.redact_home(text) == "from ~\\a to ~\\b"


def test_an_occurrence_mid_sentence_is_replaced() -> None:
    """It is not anchored to the start; the path can appear anywhere in a message."""

    assert u.redact_home(f"Could not read {_FAKE_HOME}\\x: denied") == "Could not read ~\\x: denied"


def test_the_bare_home_directory_alone_is_replaced() -> None:
    assert u.redact_home(_FAKE_HOME) == "~"


# --------------------------------------------------------------------------- #
# what it deliberately leaves alone
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("an empty string", ""),
        ("an ordinary sentence", "Evaluation complete: 4 pass, 9 fail."),
        ("a relative path", ".github/workflows/ci.yml"),
        ("a URL", "https://example.com/repo/blob/main/SECURITY.md"),
        ("a regex", r"^[A-Za-z0-9_]+$"),
        ("an absolute path outside the home directory", "Z:\\srv\\shared\\repo\\SECURITY.md"),
    ],
)
def test_text_that_does_not_contain_the_home_directory_is_untouched(label: str, text: str) -> None:
    """The narrowness is the point.

    Recognising "an absolute path" instead would mangle URLs, regexes and quoted user
    input. Paths outside the home directory still print in full: they are less useful to
    an attacker and less embarrassing in a pasted log.
    """

    assert u.redact_home(text) == text, label


def test_a_similar_but_different_directory_is_not_redacted() -> None:
    """Substring matching is on the exact home string, not a prefix of a sibling."""

    other = "Z:\\srv\\profiles\\acct-name-2\\repo"

    assert u.redact_home(other).endswith("-2\\repo")


# --------------------------------------------------------------------------- #
# the documented opt-out
# --------------------------------------------------------------------------- #


def test_the_opt_out_restores_the_full_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """`--include-absolute-path` is the documented escape hatch and has to actually work."""

    u.allow_absolute_paths(True)
    try:
        assert u.redact_home(f"{_FAKE_HOME}\\repo") == f"{_FAKE_HOME}\\repo"
    finally:
        u.allow_absolute_paths(False)


def test_the_opt_out_is_off_again_afterwards() -> None:
    """A leaked opt-out would silently disable redaction for the rest of the process."""

    assert u.redact_home(f"{_FAKE_HOME}\\repo") == "~\\repo"


# --------------------------------------------------------------------------- #
# an unresolvable home
# --------------------------------------------------------------------------- #


def test_an_unresolvable_home_directory_leaves_text_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """No home to redact is not an error; the text simply has nothing to substitute."""

    def _no_home(cls: type[Path]) -> Path:
        raise RuntimeError("home directory cannot be determined")

    monkeypatch.setattr(Path, "home", classmethod(_no_home))

    assert u.redact_home("some text with Z:\\srv") == "some text with Z:\\srv"
