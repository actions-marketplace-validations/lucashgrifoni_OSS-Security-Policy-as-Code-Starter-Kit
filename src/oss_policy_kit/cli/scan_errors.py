"""The filesystem-error arm shared by the six ``scan-*`` commands.

``scan-iac``, ``scan-k8s``, ``scan-cfn``, ``scan-pulumi``, ``scan-bicep`` and
``scan-sast`` all end the same way: run a rule pack, write the result under
``.oss-policy-kit/evidence/``, and hand any ``OSError`` back as a usage error. Six
copies of that arm is six chances for one of them to drift, and all six carried the
same defect at once, so the rule is stated here instead.
"""

from __future__ import annotations

from typing import NoReturn

import typer

from oss_policy_kit.cli.common import markup_safe, stderr_console


def exit_for_unwritable_evidence(exc: OSError) -> NoReturn:
    """Report a failed evidence write by its OS reason, without the path, and exit 2.

    ``str(OSError)`` appends ``exc.filename``, and the filename ``write_evidence``
    hands it is the resolved ``<target>/.oss-policy-kit/evidence``. So ``scan-iac
    --target ./t`` answered a relative argument with the operator's home directory and
    OS account name (M-002) -- in the one line they are being asked to read, and the
    one they paste into an issue.

    ``strerror`` is the half that says what went wrong, and that is the half worth
    keeping: where the file would have gone is what they already typed. Same wording
    and same exit code as ``scaffold-evidence`` and ``emit-insights``, which settled
    this shape first.
    """

    detail = exc.strerror or "filesystem error"
    stderr_console().print(f"[red]Error:[/red] cannot write output ({markup_safe(detail)}).")
    raise typer.Exit(code=2) from exc


def warn_if_timed_out(status: str, *, seconds: int) -> None:
    """Say on stderr that the scan ran out of budget, so ``findings=0`` is not read as clean.

    The stdout summary already carries ``timeout`` -- but it carries ``findings=0`` right
    beside it, and that pair reads as a clean result to anyone skimming a CI log.
    ``scan-sast`` has printed a note like this since it was the only command that could
    produce the state; the five in-process parsers can produce it too now that they honor
    ``--timeout`` instead of discarding it.
    """

    if status != "timeout":
        return
    stderr_console().print(
        f"[yellow]The scan ran out of its {seconds}s budget[/yellow]; it reports no "
        "findings because it did not finish. Raise --timeout, or narrow --include.",
    )
