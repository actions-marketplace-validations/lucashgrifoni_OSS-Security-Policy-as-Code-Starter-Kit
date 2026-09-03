"""Domain types for the normalized finding model (ADR-030, v10.0.0).

These are the frozen value objects behind the ``oss-policy-kit/findings/1.0``
artifact produced by ``correlate-findings``. The model is scoped to a single
clone-only run (anti-ASPM fence: no persistence, no cross-run state) and is a
read-only projection over scanner evidence already on disk — control
evaluators never consume it and their outcomes never depend on it.

Field semantics follow the ADR-030 Amendment (2026-07):

- ``NormalizedFinding.id`` is the ``opk-fk/v1`` fingerprint assigned by the
  correlation engine; normalizers leave it empty.
- ``severity.normalized`` uses the fixed six-value vocabulary
  ``critical|high|medium|low|info|unknown`` produced by the versioned
  x-severity-map (see :mod:`oss_policy_kit.application.finding_normalization`);
  the per-source original strings are always preserved verbatim.
- ``reachability`` is a promissory slot: no composed scanner exposes the data
  today, so normalizers always emit ``None``.
- ``priority``/``correlation`` are filled by the correlation engine;
  ``waiver`` by the waiver-linkage stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True)
class FindingSource:
    """One reporting source for a finding (a finding can have several after merge)."""

    tool: str
    source_path: str  # repo-relative evidence/SARIF path, never absolute
    rule: str
    severity_original: str  # the source tool's severity string, verbatim
    message: str
    native_id: str | None = None  # the tool's own finding/vuln id, when it has one


@dataclass(slots=True, frozen=True)
class LogicalLocation:
    """Non-file location coordinates (IaC resources, Kubernetes objects)."""

    type: str | None = None  # "resource" | "k8s-object" | "package" | None
    resource_type: str | None = None
    resource_name: str | None = None
    kind: str | None = None
    namespace: str | None = None
    name: str | None = None


def normalize_path_spelling(value: str) -> str:
    """One spelling per file, so a finding id does not depend on the machine that scanned.

    ``src/app.py``, ``./src/app.py``, ``src//app.py``, ``src/./app.py`` and ``src\\app.py``
    are the same file written five ways. The ``code`` correlation key is
    ``rule + file + line``, so each spelling produced its own finding and its own id --
    and a scanner run on Windows writes the backslash form, so the same commit scanned on
    a laptop and in Linux CI produced different ids for the same issue. The artifact is
    documented as deterministic in content; across platforms it was not.

    What is deliberately NOT done here:

    - ``..`` is kept as a segment. Resolving it is a claim about what is on the
      filesystem, and this layer is a projection over a document.
    - A value carrying a URI scheme is returned verbatim. ``file:///src/app.py`` is a
      different KIND of reference, not a different spelling, and turning one into a
      relative path would be a claim about where the repository root is.
    - A leading ``//`` survives: on Windows that is a UNC host, not a doubled separator.
    """

    if "://" in value:
        return value
    cleaned = value.replace("\\", "/")
    prefix = ""
    if cleaned.startswith("//"):
        prefix = "//"
    elif cleaned.startswith("/"):
        prefix = "/"
    segments = [segment for segment in cleaned.split("/") if segment and segment != "."]
    return (prefix + "/".join(segments)) or value


@dataclass(slots=True, frozen=True)
class FindingLocation:
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    logical: LogicalLocation = field(default_factory=LogicalLocation)

    def __post_init__(self) -> None:
        """Normalize the spelling here so no construction site can forget to.

        Four places build one of these and more will follow. Normalizing at each of them
        is a rule someone has to remember; normalizing here is a property the type has.
        """

        if self.file is not None:
            object.__setattr__(self, "file", normalize_path_spelling(self.file))


@dataclass(slots=True, frozen=True)
class SeverityView:
    """Normalized severity plus every source's original value (never rewritten)."""

    normalized: str  # critical | high | medium | low | info | unknown
    by_source: tuple[tuple[str, str], ...] = ()  # (tool, original) pairs, deterministic order


@dataclass(slots=True, frozen=True)
class WaiverLink:
    waived: bool = False
    matched_by: str | None = None  # "vulnerability_id" | "control_id" | None
    waiver_owner: str | None = None
    expires_at: str | None = None


@dataclass(slots=True, frozen=True)
class FindingPriority:
    rank: int  # 1-based deterministic total order
    rationale: str


@dataclass(slots=True, frozen=True)
class CorrelationInfo:
    key: str  # the full pre-hash opk-fk/v1 canonical string (auditable)
    merged_from: int
    confidence: str  # "exact" (enum kept open for a future corroborated tier)


@dataclass(slots=True, frozen=True)
class NormalizedFinding:
    """One normalized finding; after correlation it may represent several sources."""

    id: str  # "opk-fk/v1:<16 hex>"; empty until the correlation engine assigns it
    sources: tuple[FindingSource, ...]
    rule: str
    message: str
    severity: SeverityView
    location: FindingLocation
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    component: str | None = None  # never invented; only when a source names one
    vulnerability_ids: tuple[str, ...] = ()  # verbatim ids; no alias resolution in /1.0
    epss: float | None = None
    kev: bool | None = None  # None = the source exposed no KEV property
    cvss: float | None = None
    reachability: str | None = None  # promissory: always None today
    waiver: WaiverLink = field(default_factory=WaiverLink)
    priority: FindingPriority | None = None
    correlation: CorrelationInfo | None = None


@dataclass(slots=True, frozen=True)
class SourceRecord:
    """Honest per-source read record for the artifact's ``sources_read`` block.

    A missing or unreadable source never fails the run — it is recorded here
    (mirroring the evaluators' manual-review honesty) so the artifact states
    exactly what was and was not consumed.
    """

    path: str  # repo-relative
    kind: str  # "kit-evidence" | "external-sarif" | "enrichment-snapshot"
    tool: str
    status: str  # ok | not_available | error | timeout | missing | unreadable | oversize
    tool_version: str | None = None
    schema_version: str | None = None
