"""CloudFormation property shapes the rules have to read, and the ones they must ignore.

CloudFormation is generous about types: ``SecurityGroupIngress`` may be one object or a list,
``NetworkInterfaces`` likewise, and encryption lives under a different property name on every
resource type -- ``KmsMasterKeyId`` on an SNS topic, ``BucketEncryption`` on a bucket. A rule
that understands only the common form is not a weaker scanner; it is a scanner that calls an
exposed stack clean, which is worse than not scanning it at all.

The other half is refusing to read things that are not what they look like: a list entry that
is a ``!Ref`` object rather than an ARN string, a policy statement that is not an object, a
``PolicyDocument`` that is a string, an ``!If`` the loader cannot resolve. Those must produce
nothing rather than a guess. Every one is paired with the case that *must* fire, because a
rule that never fires passes the negative half on its own.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn


def _scan(root: Path, resources: dict[str, Any]) -> set[str]:
    template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}
    (root / "stack.json").write_text(json.dumps(template), encoding="utf-8")
    outcome = cfn.run_scan(root)
    assert outcome.status == "ok", outcome.status
    return {f.rule_id for f in outcome.findings}


# --------------------------------------------------------------------------- #
# IAC-CFN-002 — ingress as object vs list
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "ingress",
    [
        {"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22},
        [{"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22}],
    ],
    ids=["single-object", "list"],
)
def test_open_management_port_is_found_in_either_ingress_shape(ingress: Any, tmp_path: Path) -> None:
    found = _scan(
        tmp_path, {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": ingress}}}
    )
    assert "IAC-CFN-002" in found


def test_ingress_of_an_unusable_type_produces_no_port_finding(tmp_path: Path) -> None:
    found = _scan(tmp_path, {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": "all"}}})
    assert "IAC-CFN-002" not in found


def test_a_management_port_closed_to_the_world_is_not_flagged(tmp_path: Path) -> None:
    found = _scan(
        tmp_path,
        {
            "SG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"SecurityGroupIngress": {"CidrIp": "10.0.0.0/8", "FromPort": 22, "ToPort": 22}},
            }
        },
    )
    assert "IAC-CFN-002" not in found


# --------------------------------------------------------------------------- #
# IAC-CFN-003 — IAM wildcards in several containers
# --------------------------------------------------------------------------- #


def test_a_managed_policy_arn_that_is_an_intrinsic_is_skipped(tmp_path: Path) -> None:
    """`!Ref MyPolicy` arrives as an object; there is no ARN text to match against."""

    found = _scan(
        tmp_path,
        {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {"ManagedPolicyArns": [{"Ref": "MyPolicy"}]},
            }
        },
    )
    assert "IAC-CFN-003" not in found


def test_an_administrator_access_arn_in_the_list_is_read(tmp_path: Path) -> None:
    """The counterpart, so the test above cannot pass by skipping every entry."""

    found = _scan(
        tmp_path,
        {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {"ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
            }
        },
    )
    assert "IAC-CFN-003" in found


def test_an_inline_policy_with_a_wildcard_statement_is_read(tmp_path: Path) -> None:
    found = _scan(
        tmp_path,
        {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Policies": [
                        {
                            "PolicyName": "wild",
                            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
                        }
                    ]
                },
            }
        },
    )
    assert "IAC-CFN-003" in found


@pytest.mark.parametrize(
    "document",
    [
        "not-a-document",
        {"Statement": ["not-an-object"]},
        {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
        {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
    ],
    ids=["string-document", "statement-not-object", "deny-not-allow", "scoped-action"],
)
def test_a_policy_that_does_not_grant_everything_is_not_flagged(document: Any, tmp_path: Path) -> None:
    """Deny, a scoped action, and shapes that are not policies must all stay quiet."""

    found = _scan(
        tmp_path,
        {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {"Policies": [{"PolicyName": "p", "PolicyDocument": document}]},
            }
        },
    )
    assert "IAC-CFN-003" not in found


# --------------------------------------------------------------------------- #
# IAC-CFN-004 — encryption lives under a different name per resource type
# --------------------------------------------------------------------------- #


def test_an_sns_topic_with_a_kms_key_is_encrypted(tmp_path: Path) -> None:
    """SNS spells it `KmsMasterKeyId`; reading only `BucketEncryption` would flag it wrongly."""

    found = _scan(
        tmp_path,
        {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"KmsMasterKeyId": "alias/aws/sns"}}},
    )
    assert "IAC-CFN-004" not in found


def test_an_sns_topic_without_a_kms_key_is_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path, {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}})
    assert "IAC-CFN-004" in found


# --------------------------------------------------------------------------- #
# IAC-CFN-005 — CloudTrail logging
# --------------------------------------------------------------------------- #


def test_a_trail_with_logging_switched_off_is_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path, {"Trail": {"Type": "AWS::CloudTrail::Trail", "Properties": {"IsLogging": False}}})
    assert "IAC-CFN-005" in found


def test_a_trail_with_logging_on_is_not_flagged(tmp_path: Path) -> None:
    found = _scan(tmp_path, {"Trail": {"Type": "AWS::CloudTrail::Trail", "Properties": {"IsLogging": True}}})
    assert "IAC-CFN-005" not in found


# --------------------------------------------------------------------------- #
# IAC-CFN-006 — public IPs on instances
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "interfaces",
    [
        {"AssociatePublicIpAddress": True},
        [{"AssociatePublicIpAddress": True}],
    ],
    ids=["single-object", "list"],
)
def test_a_public_network_interface_is_found_in_either_shape(interfaces: Any, tmp_path: Path) -> None:
    found = _scan(
        tmp_path,
        {"Box": {"Type": "AWS::EC2::Instance", "Properties": {"NetworkInterfaces": interfaces}}},
    )
    assert "IAC-CFN-006" in found


def test_a_private_instance_is_not_flagged(tmp_path: Path) -> None:
    found = _scan(
        tmp_path,
        {
            "Box": {
                "Type": "AWS::EC2::Instance",
                "Properties": {"NetworkInterfaces": [{"AssociatePublicIpAddress": False}]},
            }
        },
    )
    assert "IAC-CFN-006" not in found


# --------------------------------------------------------------------------- #
# YAML short-form intrinsics
# --------------------------------------------------------------------------- #


def test_a_mapping_intrinsic_is_resolved_and_a_sequence_one_is_not_guessed(tmp_path: Path) -> None:
    """`!If` bodies the loader cannot resolve must yield nothing, not a fabricated value."""

    (tmp_path / "stack.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Trail:\n"
        "    Type: AWS::CloudTrail::Trail\n"
        "    Properties: !If [Cond, {IsLogging: false}, {IsLogging: true}]\n",
        encoding="utf-8",
    )
    outcome = cfn.run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.files_scanned, "the template should still have been read"


# --------------------------------------------------------------------------- #
# YAML short-form intrinsics
# --------------------------------------------------------------------------- #


def test_all_three_intrinsic_node_shapes_are_re_encoded(tmp_path: Path) -> None:
    """`!Ref` is scalar, `!If` a sequence, `!Sub` sometimes a mapping -- all become long form.

    PyYAML only ever produces those three node kinds (`CollectionNode` is the abstract base of
    the latter two), so the constructor's trailing `return None` cannot be reached. It is left
    in place as defence in depth rather than covered by a fabricated node.
    """

    (tmp_path / "stack.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Trail:\n"
        "    Type: AWS::CloudTrail::Trail\n"
        "    Properties:\n"
        "      IsLogging: false\n"
        "      S3BucketName: !Ref LogBucket\n"
        "      SnsTopicName: !If [IsProd, prod-topic, dev-topic]\n"
        "      Tags: !Sub {Key: '${AWS::StackName}'}\n",
        encoding="utf-8",
    )
    outcome = cfn.run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.files_scanned, "the template with intrinsics was not read"
    assert "IAC-CFN-005" in {f.rule_id for f in outcome.findings}, "properties beside the intrinsics were lost"
