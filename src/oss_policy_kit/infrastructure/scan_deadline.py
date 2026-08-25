"""The wall-clock budget an in-process scan is allowed to spend.

All six ``scan-*`` commands advertise ``--timeout`` as "Wall-clock timeout for the parser,
in seconds". Only ``scan-sast`` honored it, because it hands the number to
``subprocess.run``. The five in-process parsers took the number and dropped it
(``_ = timeout_seconds``), so on the same tree ``--timeout 0`` answered ``timeout`` for
``scan-sast`` and returned a complete scan with findings for the other five.

The state was never missing from the contract. Every one of the five evidence schemas
already lists ``"timeout"`` in its ``status`` enum, every ``IAC-*``/``K8S-*`` evaluator
already answers ``manual-review-required`` when it reads one, and
``finding_normalization`` already counts it a known scanner status. Only the producer was
missing, which is why nothing downstream had to change.

The clock is :func:`time.monotonic`. ``SOURCE_DATE_EPOCH`` pins what the kit *reports*, so
two runs produce byte-identical artifacts; it does not pin how long a parse takes, and a
budget that honored it would never expire.
"""

from __future__ import annotations

# Bound as a module attribute rather than reached through ``time`` so a test can replace
# the clock here alone. Patching ``time.monotonic`` itself would hand a fake clock to
# pytest and hypothesis at the same time.
from time import monotonic

#: Written into ``diagnostics`` by every scanner that runs out of budget. One string with
#: five callers, so the explanation cannot drift between the scanners.
TIMEOUT_DIAGNOSTIC = (
    "the scan did not finish within the {seconds}s budget set by --timeout, so it is "
    "incomplete and reports no findings. Raise --timeout, or narrow --include."
)


class ScanDeadline:
    """A budget of ``seconds``, checked between units of work.

    A budget of zero or less is spent on arrival, which is the answer ``scan-sast``
    already gives: ``subprocess.run(timeout=0)`` raises before the scanner does any work,
    and ``--timeout -1`` behaves the same way. It falls out of the arithmetic rather than
    needing a branch -- ``monotonic()`` never runs backwards, so a deadline set at or
    before construction is already behind every later reading. The comparison is ``>=``
    and not ``>`` for that boundary: Windows resolves ``monotonic()`` to about 15ms, so
    two calls inside one tick return the same float and a strict ``>`` would hand a
    zero-second budget a whole scan.

    An earlier version cached the answer to make it sticky. A test could not tell the two
    apart -- with a monotonic clock the answer cannot flip back -- so the branch went.
    """

    __slots__ = ("_expires_at",)

    def __init__(self, seconds: float) -> None:
        self._expires_at = monotonic() + seconds

    def expired(self) -> bool:
        """True once the budget has run out."""

        return monotonic() >= self._expires_at
