"""The Terraform rules' positive verdicts, and the near-misses beside them.

The scanner had good coverage of "this input produces nothing" and much less of "this input
produces a finding". That is the wrong way round for a policy scanner: a rule that has never
been seen to fire is a rule nobody has checked, and one that quietly stopped firing looks
exactly like a clean repository.

So every case here comes in a pair -- the configuration that must be flagged and the closest
one that must not. `public_access_prevention = "inherited"` fires while `"enforced"` does not;
an AdministratorAccess attachment fires while a scoped policy does not; `encrypted = false`
fires while an absent `encrypted` takes the different "no encryption configured" path. Without
the negative half, a rule that flagged everything would pass just as well.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.infrastructure.iac import scanner as tf
from oss_policy_kit.infrastructure.iac.tf_resource_index import TfBlock, TfResourceIndex

_SRC = Path("main.tf")


def _index(resource_type: str, name: str, body: dict[str, Any]) -> TfResourceIndex:
    """An index holding exactly one resource block."""

    block = TfBlock(resource_type=resource_type, name=name, body=body, source_path=_SRC)
    return TfResourceIndex(by_type={resource_type: [block]}, raw_files={_SRC: {}})


def _block(resource_type: str, name: str, body: dict[str, Any]) -> TfBlock:
    return TfBlock(resource_type=resource_type, name=name, body=body, source_path=_SRC)


def _ids(findings: list[Any]) -> list[str]:
    return [f.rule_id for f in findings]


# --------------------------------------------------------------------------- #
# IAC-TF-001 — public storage
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("prevention", "flagged"),
    [("inherited", True), ("INHERITED", True), ("enforced", False)],
)
def test_gcs_public_access_prevention_is_flagged_only_when_inherited(
    prevention: str, flagged: bool, tmp_path: Path
) -> None:
    """`inherited` defers to the org policy, which may allow public access; `enforced` cannot."""

    idx = _index("google_storage_bucket", "data", {"public_access_prevention": prevention})
    findings = tf._rule_iac_tf_001_public_storage(tmp_path, idx)
    assert bool(findings) is flagged
    if flagged:
        assert "public_access_prevention" in findings[0].message


# --------------------------------------------------------------------------- #
# IAC-TF-002 — management ports
# --------------------------------------------------------------------------- #


def test_a_security_group_opening_ssh_to_the_world_is_flagged(tmp_path: Path) -> None:
    idx = _index(
        "aws_security_group",
        "bastion",
        {"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22}]},
    )
    findings = tf._rule_iac_tf_002_open_mgmt_ports(tmp_path, idx)
    assert _ids(findings) == ["IAC-TF-002"]
    assert "22" in findings[0].message


def test_a_security_group_scoped_to_a_private_range_is_not_flagged(tmp_path: Path) -> None:
    idx = _index(
        "aws_security_group",
        "internal",
        {"ingress": [{"cidr_blocks": ["10.0.0.0/8"], "from_port": 22, "to_port": 22}]},
    )
    assert tf._rule_iac_tf_002_open_mgmt_ports(tmp_path, idx) == []


# --------------------------------------------------------------------------- #
# IAC-TF-003 — IAM wildcards
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "policy",
    ['{"Action": "*", "Resource": "*"}', '{"Action":"*","Resource":"*"}'],
)
def test_an_inline_policy_granting_everything_on_everything_is_reported(policy: str) -> None:
    """Both spacings of the same JSON have to be recognised; only one was."""

    issues = tf._iam_policy_documents_with_wildcards(_block("aws_iam_role", "admin", {"policy": policy}))
    assert issues == ["inline policy grants Action=* on Resource=*"]


def test_a_wildcard_action_scoped_to_one_resource_is_not_reported() -> None:
    """Action=* is only the finding when Resource=* is beside it."""

    block = _block("aws_iam_role", "r", {"policy": '{"Action": "*", "Resource": "arn:aws:s3:::b/*"}'})
    assert tf._iam_policy_documents_with_wildcards(block) == []


def test_an_administrator_access_managed_policy_is_reported() -> None:
    block = _block(
        "aws_iam_role",
        "admin",
        {
            "managed_policy_arns": [
                "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "arn:aws:iam::aws:policy/AdministratorAccess",
            ]
        },
    )
    issues = tf._iam_policy_documents_with_wildcards(block)
    assert len(issues) == 1
    assert "AdministratorAccess" in issues[0]


def test_managed_policy_arns_of_the_wrong_shape_are_ignored() -> None:
    """HCL interpolation can leave a string here; asking it to iterate would crash."""

    block = _block("aws_iam_role", "r", {"managed_policy_arns": "${var.arns}"})
    assert tf._iam_policy_documents_with_wildcards(block) == []


def test_an_administrator_access_role_attachment_is_flagged(tmp_path: Path) -> None:
    idx = _index(
        "aws_iam_role_policy_attachment",
        "admin_attach",
        {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    findings = tf._rule_iac_tf_003_iam_wildcards(tmp_path, idx)
    assert _ids(findings) == ["IAC-TF-003"]


def test_a_scoped_role_attachment_is_not_flagged(tmp_path: Path) -> None:
    idx = _index(
        "aws_iam_role_policy_attachment",
        "ro",
        {"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
    )
    assert tf._rule_iac_tf_003_iam_wildcards(tmp_path, idx) == []


# --------------------------------------------------------------------------- #
# IAC-TF-004 — encryption
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("encrypted", [False, "false", "FALSE", " False "])
def test_encryption_explicitly_turned_off_says_so(encrypted: Any, tmp_path: Path) -> None:
    """Distinct from 'not configured': someone decided this, and the message must reflect it."""

    finding = tf._encryption_finding(
        "aws_ebs_volume",
        _block("aws_ebs_volume", "v", {"encrypted": encrypted}),
        _index("aws_ebs_volume", "v", {}),
        tmp_path,
    )
    assert finding is not None
    assert "explicitly disables encryption" in finding.message


def test_encryption_simply_absent_is_a_different_message(tmp_path: Path) -> None:
    finding = tf._encryption_finding(
        "aws_ebs_volume", _block("aws_ebs_volume", "v", {}), _index("aws_ebs_volume", "v", {}), tmp_path
    )
    assert finding is not None
    assert "no encryption-at-rest configured" in finding.message


def test_encryption_enabled_produces_nothing(tmp_path: Path) -> None:
    assert (
        tf._encryption_finding(
            "aws_ebs_volume",
            _block("aws_ebs_volume", "v", {"encrypted": True}),
            _index("aws_ebs_volume", "v", {}),
            tmp_path,
        )
        is None
    )


# --------------------------------------------------------------------------- #
# IAC-TF-005 — logging
# --------------------------------------------------------------------------- #


def test_a_cloudtrail_with_logging_turned_off_is_flagged(tmp_path: Path) -> None:
    idx = _index("aws_cloudtrail", "audit", {"enable_logging": False})
    assert _ids(tf._rule_iac_tf_005_logging_disabled(tmp_path, idx)) == ["IAC-TF-005"]


def test_a_cloudtrail_with_logging_on_is_not_flagged(tmp_path: Path) -> None:
    idx = _index("aws_cloudtrail", "audit", {"enable_logging": True})
    assert tf._rule_iac_tf_005_logging_disabled(tmp_path, idx) == []


def test_a_database_exporting_no_logs_is_flagged(tmp_path: Path) -> None:
    idx = _index("aws_db_instance", "main", {})
    assert _ids(tf._rule_iac_tf_005_logging_disabled(tmp_path, idx)) == ["IAC-TF-005"]


def test_a_database_exporting_logs_is_not_flagged(tmp_path: Path) -> None:
    idx = _index("aws_db_instance", "main", {"enabled_cloudwatch_logs_exports": ["audit", "error"]})
    assert tf._rule_iac_tf_005_logging_disabled(tmp_path, idx) == []


# --------------------------------------------------------------------------- #
# IAC-TF-007 — public IPs
# --------------------------------------------------------------------------- #


def test_a_launch_template_network_interface_may_arrive_as_a_single_object(tmp_path: Path) -> None:
    """HCL gives one block as a dict and several as a list; both have to be walked."""

    as_object = _block("aws_launch_template", "lt", {"network_interfaces": {"associate_public_ip_address": True}})
    as_list = _block("aws_launch_template", "lt", {"network_interfaces": [{"associate_public_ip_address": True}]})
    assert _ids(tf._launch_template_public_ip_findings(as_object, tmp_path)) == ["IAC-TF-007"]
    assert _ids(tf._launch_template_public_ip_findings(as_list, tmp_path)) == ["IAC-TF-007"]


def test_a_launch_template_without_a_public_ip_produces_nothing(tmp_path: Path) -> None:
    block = _block("aws_launch_template", "lt", {"network_interfaces": [{"associate_public_ip_address": False}]})
    assert tf._launch_template_public_ip_findings(block, tmp_path) == []


def test_a_subnet_assigning_public_ips_on_launch_is_flagged(tmp_path: Path) -> None:
    idx = _index("aws_subnet", "public", {"map_public_ip_on_launch": True})
    assert _ids(tf._rule_iac_tf_007_public_ip(tmp_path, idx)) == ["IAC-TF-007"]


def test_an_instance_asking_for_a_public_ip_is_flagged(tmp_path: Path) -> None:
    idx = _index("aws_instance", "web", {"associate_public_ip_address": True})
    assert _ids(tf._rule_iac_tf_007_public_ip(tmp_path, idx)) == ["IAC-TF-007"]


def test_a_private_subnet_and_instance_produce_nothing(tmp_path: Path) -> None:
    subnet = _index("aws_subnet", "private", {"map_public_ip_on_launch": False})
    instance = _index("aws_instance", "web", {"associate_public_ip_address": False})
    assert tf._rule_iac_tf_007_public_ip(tmp_path, subnet) == []
    assert tf._rule_iac_tf_007_public_ip(tmp_path, instance) == []


# --------------------------------------------------------------------------- #
# IAC-TF-008 — ownership tags
# --------------------------------------------------------------------------- #


def test_tags_present_but_without_an_owner_is_its_own_finding(tmp_path: Path) -> None:
    """Different from having no tags at all, and the message has to say which it is."""

    finding = tf._missing_tags_finding(
        "aws_instance", _block("aws_instance", "web", {"tags": {"env": "prod"}}), tmp_path
    )
    assert finding is not None
    assert "missing owner/cost_center" in finding.message


@pytest.mark.parametrize("key", ["owner", "Owner", "cost_center"])
def test_any_recognised_ownership_key_satisfies_the_rule(key: str, tmp_path: Path) -> None:
    block = _block("aws_instance", "web", {"tags": {key: "platform"}})
    assert tf._missing_tags_finding("aws_instance", block, tmp_path) is None


# --------------------------------------------------------------------------- #
# IAC-TF-012 — wildcard principals in policy documents
# --------------------------------------------------------------------------- #


def test_a_policy_document_entry_of_the_wrong_shape_is_skipped(tmp_path: Path) -> None:
    """`data` can hold a non-object entry; it must be stepped over, not crashed on."""

    idx = TfResourceIndex(
        raw_files={
            _SRC: {
                "data": [
                    "not-a-block",
                    {
                        "aws_iam_policy_document": {
                            "open": {"statement": [{"principals": [{"type": "AWS", "identifiers": ["*"]}]}]}
                        }
                    },
                ]
            }
        }
    )
    assert _ids(tf._rule_iac_tf_012_wildcard_principals(tmp_path, idx)) == ["IAC-TF-012"]


def test_a_policy_document_with_a_named_principal_is_not_flagged(tmp_path: Path) -> None:
    idx = TfResourceIndex(
        raw_files={
            _SRC: {
                "data": [
                    {
                        "aws_iam_policy_document": {
                            "scoped": {
                                "statement": [{"principals": [{"type": "AWS", "identifiers": ["arn:aws:iam::1:root"]}]}]
                            }
                        }
                    }
                ]
            }
        }
    )
    assert tf._rule_iac_tf_012_wildcard_principals(tmp_path, idx) == []
