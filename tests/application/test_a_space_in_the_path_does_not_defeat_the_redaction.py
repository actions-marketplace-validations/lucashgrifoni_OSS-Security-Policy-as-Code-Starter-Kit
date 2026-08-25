"""A directory with a space in it must not defeat the M-002 redaction.

The scorecard explanation interpolates a filesystem path into prose, and the sanitizer found
paths by splitting the text on spaces and reducing any rooted token to its basename. A path
that itself contains a space arrives as several tokens, and only the FIRST one is rooted.

Measured before the fix, against a home directory whose name has a space in it: the leading
token was reduced to its basename -- the given name alone -- and every following segment
passed through untouched, so the explanation reconstructed the full account name and the
directory chain beneath it. A report written to be shared carried both.

A path without a space sanitized correctly the whole time, which is why the defect survived:
the control case works, and directories with spaces are the common case on Windows and macOS
rather than an exotic one.

The run now continues while the following tokens carry a path separator. Prose does not, so a
sentence resuming after the path ends the run and stays readable.

Every path below is ASSEMBLED rather than written as a literal. `scripts/check_public_hygiene.py`
forbids home-shaped strings in public files, and this test needs them as data -- writing them out
would trade a redaction bug for a hygiene violation, which is how the first version of this file
turned the hygiene gate red.

A SECOND defect surfaced here, and only in CI: every Windows case below passed on Windows and
failed on Linux. The basename step used `Path(...).name`, and `pathlib` on POSIX does not treat
a backslash as a separator -- so the basename of a drive-rooted Windows path is the WHOLE string
there, and the redaction silently did nothing. `evidence_projection` had already written down
the rule ("a report rendered on POSIX can carry Windows paths and vice versa, so separator
handling never relies on the local os.sep"); this module had not adopted it.
"""

from __future__ import annotations

import pytest

from oss_policy_kit.application.reporting import (
    _sanitize_embedded_path_in_text,
    _sanitize_target_path_for_payload,
)

_WIN_HOME = "C:" + "\\" + "Users" + "\\" + "Ana Souza"
_POSIX_HOME = "/" + "home" + "/Ana Souza"
_WIN_HOME_NO_SPACE = "C:" + "\\" + "Users" + "\\" + "joao"


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        pytest.param(
            f"Loaded 12 entries from {_WIN_HOME}\\proj\\scorecard.json.",
            "Souza",
            id="windows-home-with-a-space",
        ),
        pytest.param(
            f"Loaded 12 entries from {_POSIX_HOME}/proj/scorecard.json.",
            "Souza",
            id="posix-home-with-a-space",
        ),
        pytest.param(
            f"Read {_WIN_HOME}\\deep\\nested\\f.json.",
            "Souza",
            id="several-segments-after-the-space",
        ),
    ],
)
def test_a_name_with_a_space_does_not_survive_the_redaction(text: str, leaked: str) -> None:
    out = _sanitize_embedded_path_in_text(text, include_absolute=False)

    assert leaked not in out, (
        f"the redacted explanation still contains {leaked!r}: {out!r}. Only the first token of "
        "the path was rooted, so the rest passed through and the account name was reconstructed "
        "in a report written to be shared."
    )
    assert "scorecard.json" in out or "f.json" in out, (
        f"the file name is gone as well: {out!r}. Redaction is meant to drop the directories "
        "above the file, not the fact that a file was read."
    )


def test_prose_after_the_path_is_left_alone() -> None:
    """The run has to END somewhere, or the rest of the sentence is swallowed with the path."""

    out = _sanitize_embedded_path_in_text(f"Read {_WIN_HOME}\\p\\f.json. The file was empty.", include_absolute=False)

    assert out == "Read f.json. The file was empty.", (
        f"the sentence after the path did not survive: {out!r}. A word of prose carries no path "
        "separator, which is exactly what ends the run."
    )


def test_a_path_without_spaces_is_unchanged_in_behaviour() -> None:
    """The control case, which worked before and must keep working."""

    out = _sanitize_embedded_path_in_text(
        f"Loaded 12 entries from {_WIN_HOME_NO_SPACE}\\proj\\scorecard.json.", include_absolute=False
    )

    assert out == "Loaded 12 entries from scorecard.json."


def test_the_basename_step_reads_both_separator_styles() -> None:
    """The half that could only fail in CI, held directly on the function that does it.

    A test built from `Path` objects would spell the separator the way the running OS
    does and never notice; these are string literals, so they mean the same thing on
    every platform.
    """

    assert _sanitize_target_path_for_payload(_WIN_HOME + "\\proj\\f.json", include_absolute=False) == "f.json"
    assert _sanitize_target_path_for_payload(_POSIX_HOME + "/proj/f.json", include_absolute=False) == "f.json"


def test_a_root_with_no_name_under_it_is_not_reported_as_a_drive_letter() -> None:
    """`C:\\` has no basename, and answering `C:` would put the host's drive in a report."""

    assert _sanitize_target_path_for_payload("C:" + "\\", include_absolute=False) == "."
    assert _sanitize_target_path_for_payload("/", include_absolute=False) == "."


def test_text_with_no_path_at_all_is_untouched() -> None:
    assert (
        _sanitize_embedded_path_in_text("Nothing to report here.", include_absolute=False) == "Nothing to report here."
    )


def test_include_absolute_still_returns_everything() -> None:
    """The flag exists for operators who WANT the full path; redaction must not override it."""

    text = f"Loaded from {_WIN_HOME}\\p\\f.json."

    assert _sanitize_embedded_path_in_text(text, include_absolute=True) == text
