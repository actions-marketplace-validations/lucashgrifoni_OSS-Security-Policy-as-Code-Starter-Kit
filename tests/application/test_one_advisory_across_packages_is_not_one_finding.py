"""One advisory against three dependencies is three things to fix, not one finding.

The `vuln` correlation axis keys on the advisory id plus `component`, and deliberately
leaves the file out so the same CVE from two scanners still collapses to one finding.
`NormalizedFinding.component` carries the comment "never invented; only when a source
names one" -- and no normalizer ever set it, so the key degenerated to the bare advisory
id for every finding on that axis.

Measured through `correlate-findings` on an osv-scanner drop naming three packages in
three ecosystems, each with its purl in `properties`:

    findings: 1
      component: None
      merged_from: 3
      key: opk-fk/v1|vuln|vid=CVE-2026-11111|component=-
      location: backend/go.sum

The operator is shown one Go module. Fixing it leaves `lodash` and `requests`
vulnerable, and neither appears anywhere in the artifact -- the three sources all name
the same evidence file. The engine declares `CORRELATION_STRATEGY =
"conservative-under-merge"`, and this was the opposite.

The purl was in the document the whole time; nothing read it.

Both directions are asserted. Keying on a field no two findings ever share would split
every merge and satisfy the first half, so the cross-tool merge the axis exists for is
held too.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oss_policy_kit.application import finding_sarif
from oss_policy_kit.application.finding_correlation import correlate
from oss_policy_kit.application.finding_sarif import normalize_sarif_sources
from oss_policy_kit.domain.findings import NormalizedFinding

_SARIF_DIR = Path(".oss-policy-kit") / "evidence" / "sast"

_ADVISORY = "CVE-2026-11111"

#: (package, lockfile) across three ecosystems -- three separate upgrades.
_PACKAGES: tuple[tuple[str, str], ...] = (
    ("pkg:npm/lodash@4.17.20", "frontend/package-lock.json"),
    ("pkg:golang/golang.org/x/net@0.17.0", "backend/go.sum"),
    ("pkg:pypi/requests@2.25.0", "services/api/requirements.txt"),
)


def _result(uri: str, *, rule: str = _ADVISORY, props: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
    location.update(extra)
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": f"{rule} affects a dependency of this project"},
        "locations": [location],
        "properties": props or {},
    }


def _drop(repo: Path, filename: str, driver: str, results: list[dict[str, Any]]) -> None:
    directory = repo / _SARIF_DIR
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": driver, "version": "1.0"}}, "results": results}],
    }
    (directory / filename).write_text(json.dumps(document), encoding="utf-8")


def _findings(repo: Path) -> list[NormalizedFinding]:
    normalized, _records = normalize_sarif_sources(repo)
    return list(correlate(normalized).findings)


def test_three_packages_under_one_advisory_stay_three_findings(tmp_path: Path) -> None:
    _drop(
        tmp_path,
        "osv-scanner.sarif.json",
        "osv-scanner",
        [_result(uri, props={"purl": purl}) for purl, uri in _PACKAGES],
    )

    findings = _findings(tmp_path)

    assert len(findings) == len(_PACKAGES), (
        f"{len(_PACKAGES)} vulnerable packages collapsed into {len(findings)} finding(s). "
        "The ones that vanished are still vulnerable, and nothing in the artifact names them."
    )
    assert {f.component for f in findings} == {purl for purl, _ in _PACKAGES}
    assert all(f.correlation is not None and f.correlation.merged_from == 1 for f in findings)


def test_the_same_package_from_two_tools_is_still_one_finding(tmp_path: Path) -> None:
    """The reason the axis leaves the file out. Splitting this would be the opposite defect."""

    purl = "pkg:npm/lodash@4.17.20"
    _drop(tmp_path, "osv-scanner.sarif.json", "osv-scanner", [_result("package-lock.json", props={"purl": purl})])
    _drop(
        tmp_path,
        "gitleaks.sarif.json",
        "Trivy",
        [
            _result(
                "package-lock.json",
                logicalLocations=[{"kind": "package", "fullyQualifiedName": purl}],
            )
        ],
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1, f"one package reported by two tools produced {len(findings)} findings"
    assert findings[0].component == purl
    assert findings[0].correlation is not None
    assert findings[0].correlation.merged_from == 2
    assert {s.tool for s in findings[0].sources} == {"osv-scanner", "Trivy"}


def test_a_source_that_names_no_package_keeps_the_field_null(tmp_path: Path) -> None:
    """Nothing is inferred from the lockfile path.

    A path is where the manifest is, not which dependency inside it is affected.
    Deriving one would be a claim the scanner never made, so these still merge -- there
    is genuinely nothing to tell them apart by.
    """

    _drop(
        tmp_path,
        "osv-scanner.sarif.json",
        "osv-scanner",
        [_result("frontend/package-lock.json"), _result("backend/go.sum")],
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].component is None
    assert findings[0].correlation is not None
    assert findings[0].correlation.merged_from == 2


def test_the_plain_package_spelling_is_read_when_there_is_no_purl(tmp_path: Path) -> None:
    _drop(
        tmp_path,
        "osv-scanner.sarif.json",
        "osv-scanner",
        [
            _result("go.sum", props={"package": "golang.org/x/net"}),
            _result("package-lock.json", props={"packageName": "lodash"}),
        ],
    )

    findings = _findings(tmp_path)

    assert {f.component for f in findings} == {"golang.org/x/net", "lodash"}


def test_a_logical_location_that_is_not_a_package_is_ignored(tmp_path: Path) -> None:
    """SARIF logical locations describe functions and namespaces too.

    Reading one of those as the affected dependency would put a function name in a field
    an adopter reads as "which package do I upgrade".
    """

    _drop(
        tmp_path,
        "osv-scanner.sarif.json",
        "osv-scanner",
        [_result("app.go", logicalLocations=[{"kind": "function", "fullyQualifiedName": "main.handleRequest"}])],
    )

    assert _findings(tmp_path)[0].component is None


def test_the_search_continues_past_a_package_entry_that_names_nothing(tmp_path: Path) -> None:
    """A result carries several logical locations; the first one is not the last word.

    Stopping at the first entry of kind `package` would return `None` here and lose a
    component the document does provide, two entries down.
    """

    purl = "pkg:npm/lodash@4.17.20"
    _drop(
        tmp_path,
        "osv-scanner.sarif.json",
        "osv-scanner",
        [
            _result(
                "package-lock.json",
                logicalLocations=[
                    {"kind": "package"},
                    {"kind": "package", "fullyQualifiedName": "  "},
                    {"kind": "package", "name": purl},
                ],
            )
        ],
    )

    assert _findings(tmp_path)[0].component == purl


def test_a_component_is_bounded(tmp_path: Path) -> None:
    """Target-controlled text on its way into a published artifact, bounded like the rest."""

    hostile = "pkg:npm/" + ("a" * 5_000)
    _drop(tmp_path, "osv-scanner.sarif.json", "osv-scanner", [_result("package-lock.json", props={"purl": hostile})])

    component = _findings(tmp_path)[0].component

    assert component is not None
    assert len(component) == finding_sarif._MAX_COMPONENT_CHARS, (
        f"a {len(hostile)}-character purl reached the artifact at {len(component)} characters"
    )


def test_a_control_byte_inside_a_component_does_not_survive(tmp_path: Path) -> None:
    """The escape sits in the MIDDLE, where stripping the ends does not reach it.

    `component` is printed in the ranked summary and written into the artifact, so a
    package name carrying an ANSI escape is a scanner's document steering a terminal.
    Location URIs are cleaned the same way, for the same reason.
    """

    _drop(
        tmp_path,
        "osv-scanner.sarif.json",
        "osv-scanner",
        [_result("package-lock.json", props={"purl": "pkg:npm/lo[31mdash@1.0"})],
    )

    component = _findings(tmp_path)[0].component

    assert component is not None
    assert component.isprintable(), f"an unprintable byte reached the artifact: {component!r}"
    assert component == "pkg:npm/lo[31mdash@1.0"


def test_a_blank_package_property_does_not_become_a_component(tmp_path: Path) -> None:
    """Whitespace is not a package name; falling through to the next spelling is the point."""

    _drop(
        tmp_path,
        "osv-scanner.sarif.json",
        "osv-scanner",
        [_result("package-lock.json", props={"purl": "   ", "package": "lodash"})],
    )

    assert _findings(tmp_path)[0].component == "lodash"
