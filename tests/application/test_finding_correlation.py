"""A-S4 (ADR-030): the cross-scanner correlation engine.

Covers the per-axis merge/no-merge matrix (conservative under-merge), the
deterministic total-order ranking, and the merged-field resolution rules.
Determinism-as-a-property lives in tests/property/.
"""

from __future__ import annotations

from oss_policy_kit.application import finding_correlation as fc
from oss_policy_kit.domain.findings import (
    FindingLocation,
    FindingSource,
    LogicalLocation,
    NormalizedFinding,
    SeverityView,
)


def _nf(
    tool: str,
    rule: str,
    *,
    message: str = "msg",
    severity: str = "medium",
    original: str | None = None,
    file: str | None = None,
    line: int | None = None,
    logical: LogicalLocation | None = None,
    vuln_ids: tuple[str, ...] = (),
    cwe: tuple[str, ...] = (),
    owasp: tuple[str, ...] = (),
    epss: float | None = None,
    kev: bool | None = None,
    cvss: float | None = None,
) -> NormalizedFinding:
    orig = original if original is not None else severity
    return NormalizedFinding(
        id="",
        sources=(
            FindingSource(
                tool=tool,
                source_path=f".oss-policy-kit/evidence/{tool}.json",
                rule=rule,
                severity_original=orig,
                message=message,
            ),
        ),
        rule=rule,
        message=message,
        severity=SeverityView(normalized=severity, by_source=((tool, orig),)),
        location=FindingLocation(file=file, line_start=line, logical=logical or LogicalLocation()),
        cwe=cwe,
        owasp=owasp,
        vulnerability_ids=vuln_ids,
        epss=epss,
        kev=kev,
        cvss=cvss,
    )


# --------------------------------------------------------------------------- #
# merge / no-merge matrix
# --------------------------------------------------------------------------- #


def test_same_cve_two_tools_merges_cross_tool() -> None:
    a = _nf("osv-scanner", "CVE-2026-1", vuln_ids=("CVE-2026-1",), severity="high", message="wording A")
    b = _nf("grype", "CVE-2026-1", vuln_ids=("CVE-2026-1",), severity="critical", message="different wording")
    result = fc.correlate([a, b])
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.correlation is not None
    assert f.correlation.merged_from == 2
    assert result.merged_groups == 1
    assert result.cross_tool_merges == 1
    assert f.severity.normalized == "critical"  # strongest across the group
    assert {t for t, _ in f.severity.by_source} == {"osv-scanner", "grype"}
    assert len(f.sources) == 2


def test_iac_same_resource_same_message_merges() -> None:
    loc = LogicalLocation(type="resource", resource_type="aws_s3_bucket", resource_name="logs")
    a = _nf("iac", "IAC-TF-001", file="main.tf", logical=loc, message="public bucket")
    b = _nf("iac", "IAC-TF-001", file="main.tf", logical=loc, message="public bucket")
    result = fc.correlate([a, b])
    assert len(result.findings) == 1
    assert result.merged_groups == 1


def test_iac_same_resource_different_message_does_not_merge() -> None:
    # Conservative under-merge: same rule+resource but a different message stays split.
    loc = LogicalLocation(type="resource", resource_type="aws_s3_bucket", resource_name="logs")
    a = _nf("iac", "IAC-TF-001", file="main.tf", logical=loc, message="public acl")
    b = _nf("iac", "IAC-TF-001", file="main.tf", logical=loc, message="versioning disabled")
    result = fc.correlate([a, b])
    assert len(result.findings) == 2
    assert result.merged_groups == 0


def test_code_null_line_is_a_distinct_sentinel() -> None:
    a = _nf("semgrep", "rule-x", file="app.py", line=10, message="m")
    b = _nf("semgrep", "rule-x", file="app.py", line=None, message="m")
    result = fc.correlate([a, b])
    assert len(result.findings) == 2  # null line never merges with a concrete line


def test_cross_axis_never_merges() -> None:
    vuln = _nf("osv-scanner", "shared", vuln_ids=("CVE-2026-9",), message="m")
    code = _nf("semgrep", "shared", file="a.py", line=1, message="m")
    result = fc.correlate([vuln, code])
    assert len(result.findings) == 2
    assert {f.correlation.key.split("|")[1] for f in result.findings if f.correlation} == {"vuln", "code"}


def test_ids_are_opk_fk_v1_and_stable() -> None:
    a = _nf("semgrep", "rule-x", file="app.py", line=10, message="m")
    ids1 = [f.id for f in fc.correlate([a]).findings]
    ids2 = [f.id for f in fc.correlate([a]).findings]
    assert ids1 == ids2
    assert ids1[0].startswith("opk-fk/v1:")
    assert len(ids1[0].split(":")[1]) == 16


# --------------------------------------------------------------------------- #
# ranking
# --------------------------------------------------------------------------- #


def test_ranking_kev_then_epss_then_severity() -> None:
    kev = _nf("osv-scanner", "CVE-A", vuln_ids=("CVE-A",), severity="low", kev=True, epss=0.1)
    high_epss = _nf("osv-scanner", "CVE-B", vuln_ids=("CVE-B",), severity="low", epss=0.9)
    crit = _nf(
        "iac",
        "IAC-1",
        file="a.tf",
        logical=LogicalLocation(type="resource", resource_type="t", resource_name="n"),
        severity="critical",
    )
    low = _nf("semgrep", "rule-z", file="z.py", line=1, severity="info")
    result = fc.correlate([low, crit, high_epss, kev])
    order = [f.rule for f in result.findings]
    assert order[0] == "CVE-A"  # KEV first even at low severity
    assert order[1] == "CVE-B"  # then high EPSS
    assert order.index("IAC-1") < order.index("rule-z")  # critical before info among the rest
    assert [f.priority.rank for f in result.findings if f.priority] == [1, 2, 3, 4]
    assert "KEV-listed" in result.findings[0].priority.rationale  # type: ignore[union-attr]


# --------------------------------------------------------------------------- #
# merged-field resolution + shape
# --------------------------------------------------------------------------- #


def test_merge_takes_strongest_enrichment_and_unions_tags() -> None:
    a = _nf("osv-scanner", "CVE-M", vuln_ids=("CVE-M",), kev=None, epss=0.3, cvss=5.0, cwe=("CWE-79",), owasp=("A03",))
    b = _nf("grype", "CVE-M", vuln_ids=("CVE-M",), kev=True, epss=0.7, cvss=None, cwe=("CWE-89",))
    f = fc.correlate([a, b]).findings[0]
    assert f.kev is True  # OR across the group
    assert f.epss == 0.7
    assert f.cvss == 5.0
    assert f.cwe == ("CWE-79", "CWE-89")
    assert f.owasp == ("A03",)


def test_kev_stays_none_when_no_source_reports_it() -> None:
    a = _nf("osv-scanner", "CVE-N", vuln_ids=("CVE-N",), kev=None)
    f = fc.correlate([a]).findings[0]
    assert f.kev is None  # never fabricated as False


def test_to_dict_and_empty_input() -> None:
    empty = fc.correlate([])
    assert empty.findings == ()
    assert empty.to_dict() == {
        "strategy": "conservative-under-merge",
        "key_spec": "opk-fk/v1",
        "merged_groups": 0,
        "cross_tool_merges": 0,
    }


def test_correlation_never_carries_reachability() -> None:
    a = _nf("osv-scanner", "CVE-R", vuln_ids=("CVE-R",))
    f = fc.correlate([a]).findings[0]
    assert f.reachability is None  # promissory slot, never populated in v1
