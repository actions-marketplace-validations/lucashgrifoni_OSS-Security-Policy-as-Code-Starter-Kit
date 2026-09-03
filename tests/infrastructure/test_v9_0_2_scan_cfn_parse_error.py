"""Regression: scan-cfn must not silently drop a malformed CFN candidate (v9.0.2).

A CloudFormation template (``AWSTemplateFormatVersion`` + ``Resources`` + a real
resource type) that fails to parse must surface in ``parse_errors`` /
``files_failed`` -- not produce a dishonest clean report with
``findings_total == 0``. A genuinely non-CFN document that fails to parse stays a
legitimate silent skip.
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn

# Valid CFN structure with a YAML syntax error: the unquoted ``Properties`` map
# is followed by a bad-indent / unterminated-flow construct that PyYAML rejects.
_MALFORMED_CFN_YAML = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  PublicBucket:\n"
    "    Type: AWS::S3::Bucket\n"
    "    Properties:\n"
    "      AccessControl: PublicRead\n"
    "      Tags: [oops, {unterminated: \n"  # broken flow mapping -> yaml.YAMLError
)


def test_malformed_cfn_candidate_surfaces_as_parse_error(tmp_path: Path) -> None:
    (tmp_path / "stack.yaml").write_text(_MALFORMED_CFN_YAML, encoding="utf-8")

    outcome = cfn.run_scan(tmp_path)

    # The file must NOT be silently swallowed: it is recorded as a parse error
    # and is NOT counted as a successfully scanned file.
    assert outcome.parse_errors, "malformed CFN candidate was dropped silently"
    failed_files = {pe["file"] for pe in outcome.parse_errors}
    assert "stack.yaml" in failed_files
    assert outcome.files_scanned == []

    payload = cfn.render_evidence_payload(outcome, target=tmp_path)
    assert "stack.yaml" in payload["files_failed"]
    # A clean (status ok / findings_total 0) report over an UNREADABLE template
    # would be the dishonest outcome we are guarding against.
    assert payload["findings_total"] == 0
    assert payload["files_failed"], "evidence payload hid the parse failure"


def test_malformed_cfn_json_candidate_surfaces_as_parse_error(tmp_path: Path) -> None:
    # JSON path: valid CFN markers, but truncated -> json.JSONDecodeError.
    bad_json = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"B": {"Type": "AWS::S3::Bucket"'
    (tmp_path / "stack.json").write_text(bad_json, encoding="utf-8")

    outcome = cfn.run_scan(tmp_path)

    assert {pe["file"] for pe in outcome.parse_errors} == {"stack.json"}
    assert outcome.files_scanned == []


def test_non_cfn_malformed_yaml_stays_silent_skip(tmp_path: Path) -> None:
    # No CFN markers -> a broken non-CFN file is a legitimate silent skip,
    # not a parse error (preserves the existing skip contract).
    (tmp_path / "config.yaml").write_text("foo: [1, 2,\nbar: {oops\n", encoding="utf-8")
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")

    outcome = cfn.run_scan(tmp_path)

    assert outcome.parse_errors == []
    assert outcome.files_scanned == []
    assert outcome.findings == []
    assert outcome.status == "ok"
