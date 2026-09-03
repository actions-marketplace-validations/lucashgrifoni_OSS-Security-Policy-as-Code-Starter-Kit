"""Rich must never eat part of a message the adopter has to act on.

Rich reads ``[word]`` as a style tag and drops it from the rendered line, silently. The
shipped consequence: ``collect-evidence`` told users to run

    pip install 'oss-policy-kit'

when the source said ``pip install 'oss-policy-kit[github]'``. The one command the message
existed to give them was the one thing it got wrong, and nothing failed — the text was
correct in the source, correct in the exception, and wrong only after rendering.

v10.0.6 fixed a single call site. The idiom
``console().print(f"[red]...[/red] {exc}")`` was duplicated at 61 fields across 22 files,
so every one of them could lose a bracketed fragment: a Windows path with ``[1]`` in it, a
package extra, a regex in an error, a SARIF rule id in brackets.

The first test proves the escaping does the job; the second is the one that matters over
time, because it fails when a NEW unescaped site appears rather than when an old one
regresses.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest
from rich.console import Console

from oss_policy_kit.cli.common import markup_safe

CLI_DIR = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "cli"

_MARKUP_PRINT = re.compile(r"console\(\)\.print\(f\"")
#: An f-string replacement field, minus format spec and conversion.
_FIELD = re.compile(r"\{([^{}:!]+)\}")

#: Interpolations that cannot carry markup and so need no escaping. Anything else is
#: assumed to be able to, because exception text and filesystem paths routinely do.
_SAFE_PREFIXES = ("'", '"', "len(")


def _render(payload: str) -> str:
    buf = io.StringIO()
    Console(file=buf, width=240, no_color=True, highlight=False).print(f"[red]Unexpected error:[/red] {payload}")
    return buf.getvalue().strip()


@pytest.mark.parametrize(
    "fragment",
    [
        # The shipped defect, and its three siblings.
        "pip install 'oss-policy-kit[github]'",
        "pip install 'oss-policy-kit[gitlab]'",
        "pip install 'oss-policy-kit[azure]'",
        "pip install 'oss-policy-kit[aws]'",
        # Fragments that collide with real Rich style names, which is the wider class:
        # any of these inside an exception message or a path is silently deleted.
        "see [dim] in the output",
        "key [default] missing",
        r"path C:\x\[bold]\y",
    ],
)
def test_markup_safe_preserves_a_bracketed_fragment(fragment: str) -> None:
    """Without the escape the bracketed run disappears; with it, it survives verbatim.

    The first assertion keeps the fixtures honest. Rich only consumes a bracketed run
    that could be a style, so ``[CI-PIN-008]`` prints literally and would have made a
    fixture that proves nothing -- two of the fixtures first written here were exactly
    that, and this line is what caught them.
    """

    assert fragment not in _render(fragment), "fixture does not actually exercise Rich markup"
    assert fragment in _render(markup_safe(fragment))


def test_no_unescaped_interpolation_remains_in_a_markup_print() -> None:
    """Every interpolation into a markup string goes through markup_safe.

    This is a whole-package invariant rather than a per-site test on purpose: the defect
    was not that one site was wrong, it was that the idiom was copied 61 times and each
    copy could lose a bracket. A per-site test would have passed on the other 60.
    """

    offenders: list[str] = []
    for path in sorted(CLI_DIR.glob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            if not _MARKUP_PRINT.search(line):
                continue
            for match in _FIELD.finditer(line):
                expr = match.group(1).strip()
                if expr.startswith("markup_safe(") or expr.startswith(_SAFE_PREFIXES):
                    continue
                offenders.append(f"{path.name}:{lineno}: {{{expr}}}")

    assert not offenders, (
        f"these interpolations can lose a bracketed fragment to Rich; wrap them in markup_safe(): {offenders}"
    )
