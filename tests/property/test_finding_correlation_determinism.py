"""Property-based determinism guarantees for the correlation engine (ADR-030 A-S4).

The correlated artifact is the flagship v10 output; consumers (and the SARIF
export) rely on it being reproducible bit-for-bit. These properties lock:

- idempotence (same input -> identical output),
- input-order independence (shuffling the input changes nothing),
- rank is a gapless total order 1..N,
- the conservative under-merge invariant: cross-axis findings never share an id.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from oss_policy_kit.application import finding_correlation as fc
from oss_policy_kit.domain.findings import (
    FindingLocation,
    FindingSource,
    LogicalLocation,
    NormalizedFinding,
    SeverityView,
)

_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_TOOLS = ("semgrep", "iac", "osv-scanner", "zizmor", "gitleaks", "k8s")


@st.composite
def _findings(draw: st.DrawFn) -> NormalizedFinding:
    axis = draw(st.sampled_from(["vuln", "iac", "k8s", "code", "misc"]))
    tool = draw(st.sampled_from(_TOOLS))
    rule = draw(st.sampled_from(["R1", "R2", "R3", "CVE-2026-1", "CVE-2026-2"]))
    message = draw(st.sampled_from(["m1", "m2", "m3"]))
    severity = draw(st.sampled_from(_SEVERITIES))
    file = draw(st.sampled_from(["a.py", "b.tf", "c.yaml", None]))
    line = draw(st.sampled_from([None, 1, 2, 10]))

    logical = LogicalLocation()
    vuln_ids: tuple[str, ...] = ()
    if axis == "vuln":
        vuln_ids = tuple(
            sorted(draw(st.sets(st.sampled_from(["CVE-2026-1", "CVE-2026-2", "GHSA-a"]), min_size=1, max_size=2)))
        )
    elif axis == "iac":
        logical = LogicalLocation(
            type="resource",
            resource_type=draw(st.sampled_from(["t1", "t2"])),
            resource_name=draw(st.sampled_from(["n1", "n2"])),
        )
    elif axis == "k8s":
        logical = LogicalLocation(
            type="k8s-object",
            kind=draw(st.sampled_from(["Deployment", "Pod"])),
            namespace=draw(st.sampled_from(["prod", "dev"])),
            name=draw(st.sampled_from(["api", "web"])),
        )

    return NormalizedFinding(
        id="",
        sources=(
            FindingSource(
                tool=tool,
                source_path=f".oss-policy-kit/evidence/{tool}.json",
                rule=rule,
                severity_original=severity,
                message=message,
            ),
        ),
        rule=rule,
        message=message,
        severity=SeverityView(normalized=severity, by_source=((tool, severity),)),
        location=FindingLocation(file=file, line_start=line, logical=logical),
        vulnerability_ids=vuln_ids,
        epss=draw(st.sampled_from([None, 0.1, 0.9])),
        kev=draw(st.sampled_from([None, True, False])),
        cvss=draw(st.sampled_from([None, 4.0, 9.0])),
    )


@given(findings=st.lists(_findings(), max_size=12))
@settings(max_examples=150, deadline=None)
def test_correlation_is_idempotent(findings: list[NormalizedFinding]) -> None:
    once = fc.correlate(list(findings))
    twice = fc.correlate(list(findings))
    assert once == twice


@given(data=st.data())
@settings(max_examples=150, deadline=None)
def test_correlation_is_input_order_independent(data: st.DataObject) -> None:
    findings = data.draw(st.lists(_findings(), max_size=12))
    shuffled = data.draw(st.permutations(findings))
    base = fc.correlate(list(findings))
    perm = fc.correlate(list(shuffled))
    # Same correlated set (ids, ranks, merged fields) regardless of input order.
    assert base == perm


@given(findings=st.lists(_findings(), max_size=12))
@settings(max_examples=150, deadline=None)
def test_rank_is_a_gapless_total_order(findings: list[NormalizedFinding]) -> None:
    result = fc.correlate(list(findings))
    ranks = [f.priority.rank for f in result.findings if f.priority]
    assert ranks == list(range(1, len(result.findings) + 1))
    assert all(f.priority is not None for f in result.findings)


@given(findings=st.lists(_findings(), max_size=12))
@settings(max_examples=150, deadline=None)
def test_cross_axis_findings_never_share_an_id(findings: list[NormalizedFinding]) -> None:
    result = fc.correlate(list(findings))
    # Each correlated finding's canonical key is prefixed by exactly one axis;
    # two findings with the same id must have the same axis (no cross-axis merge).
    by_id: dict[str, str] = {}
    for f in result.findings:
        assert f.correlation is not None
        axis = f.correlation.key.split("|")[1]
        if f.id in by_id:
            assert by_id[f.id] == axis
        by_id[f.id] = axis
    # ids are unique per correlated finding
    assert len({f.id for f in result.findings}) == len(result.findings)


@given(findings=st.lists(_findings(), max_size=12))
@settings(max_examples=100, deadline=None)
def test_kev_ranked_findings_come_first(findings: list[NormalizedFinding]) -> None:
    result = fc.correlate(list(findings))
    kev_flags = [bool(f.kev) for f in result.findings]
    # once a non-KEV finding appears, no KEV finding may follow (KEV sorts first)
    seen_non_kev = False
    for is_kev in kev_flags:
        if not is_kev:
            seen_non_kev = True
        elif seen_non_kev:
            raise AssertionError("a KEV finding ranked below a non-KEV finding")
