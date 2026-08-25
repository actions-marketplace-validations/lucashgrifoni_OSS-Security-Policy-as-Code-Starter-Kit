"""The findings artifact must not repeat the operator's directory chain.

`target_path` was the only field in findings/1.0 going through the privacy sanitizer.
Measured with a scanner drop carrying an absolute path, the published artifact repeated the
operator's account and directories in three more places: `location.file`, `message`, and
`sources[].message`.

"That is third-party SARIF, not ours" does not hold: the kit's own `scan-sast` writes an
absolute path into its evidence, and `correlate-findings` carries whatever it reads.

The rule applied is the one `reports/2.0` already follows -- only a ROOTED path loses its
directories. A repository-relative path is left alone, because `src/app.py` is not host layout,
it is the answer to "where is this". The first version of the fix used the target-path
sanitizer, which reduces anything to its basename, and turned `src/app.py` into `app.py` for
every ordinary finding. That is asserted below so it cannot come back.

`correlation.key` is a known and deliberate exception, asserted at the bottom so nobody reads
this file and concludes the artifact is fully redacted.

Paths are assembled rather than written out: `scripts/check_public_hygiene.py` forbids
home-shaped literals in public files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.findings_report import build_findings_report

_SAST = Path(".oss-policy-kit") / "evidence" / "sast"
_ACCOUNT = "CONTA-DO-OPERADOR"
_ABSOLUTE = "C:" + "/" + "Users" + f"/{_ACCOUNT}/projeto/src/app.py"
_RELATIVE = "src/app.py"


def _drop(repo: Path, tool: str, uri: str, rule: str, message: str) -> None:
    directory = repo / _SAST
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "version": "1.0"}},
                "results": [
                    {
                        "ruleId": rule,
                        "level": "error",
                        "message": {"text": message},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 7}}}
                        ],
                    }
                ],
            }
        ],
    }
    (directory / f"{tool}.sarif.json").write_text(json.dumps(document), encoding="utf-8")


def test_an_absolute_location_loses_its_directories(tmp_path: Path) -> None:
    _drop(tmp_path, "osv-scanner", _ABSOLUTE, "CVE-2026-0001", f"Vulnerable call reached from {_ABSOLUTE}")

    report = build_findings_report(tmp_path, kit_version="test")
    finding = report["findings"][0]

    assert _ACCOUNT not in json.dumps(report), (
        f"the account name survives somewhere in the artifact: {json.dumps(report)[:400]!r}"
    )
    assert finding["location"]["file"] == "app.py"
    assert _ACCOUNT not in finding["message"]
    assert _ACCOUNT not in finding["sources"][0]["message"]


def test_a_repository_relative_location_is_left_alone(tmp_path: Path) -> None:
    """The ordinary case, and the regression the first version of this fix introduced."""

    _drop(tmp_path, "osv-scanner", _RELATIVE, "CVE-2026-0002", f"issue in {_RELATIVE}")

    finding = build_findings_report(tmp_path, kit_version="test")["findings"][0]

    assert finding["location"]["file"] == _RELATIVE, (
        f"a repository-relative path was reduced to {finding['location']['file']!r}. The "
        "directory inside the repository is not the operator's layout; it is where the finding is."
    )
    assert _RELATIVE in finding["message"]


def test_include_absolute_path_still_returns_everything(tmp_path: Path) -> None:
    """The flag exists for operators who want the full path; redaction must not override it."""

    _drop(tmp_path, "osv-scanner", _ABSOLUTE, "CVE-2026-0003", f"Vulnerable call reached from {_ABSOLUTE}")

    report = build_findings_report(tmp_path, kit_version="test", include_absolute_path=True)

    assert _ACCOUNT in json.dumps(report), "the flag was ignored and the path was redacted anyway"


@pytest.mark.xfail(
    reason="known limitation: correlation.key is a merge key, redacting it would over-merge", strict=True
)
def test_the_correlation_key_is_not_redacted_yet(tmp_path: Path) -> None:
    """Documented deliberately, so the artifact is not believed to be fully redacted.

    On the `code` axis the key contains `file=<path>`. It is the identity two findings are
    merged by, so replacing the path inside it would give two findings in different
    directories the same identity -- the over-merge ADR-030 exists to avoid. Fixing it means
    changing what the key is made of, which is a contract decision and not a redaction pass.

    `strict=True`: if the key ever stops carrying the path, this fails and the limitation gets
    removed from the docstring rather than lingering as a false warning.
    """

    _drop(tmp_path, "zizmor", _ABSOLUTE, "template-injection", "Template injection")

    finding = build_findings_report(tmp_path, kit_version="test")["findings"][0]

    assert _ACCOUNT not in finding["correlation"]["key"]
