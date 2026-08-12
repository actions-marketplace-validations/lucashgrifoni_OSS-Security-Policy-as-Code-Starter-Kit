"""Pulumi rules, asserted in both directions against real Python programs.

Pulumi infrastructure is a program, not a document, so this scanner reads an AST and only
recognises what a constructor call literally spells out. That makes the quiet direction the one
to distrust: a rule can be perfectly correct and still never see the resource, because the call
was built dynamically, aliased, or spelled in camelCase when the rule looked for snake_case.

Every rule below therefore gets a program that must trip it and one that must not, and the
encryption rule additionally gets both spellings -- Pulumi accepts `storage_encrypted` and
`storageEncrypted`, and a rule that honoured only one would silently pass half its users.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.iac.pulumi.scanner import run_scan

_IMPORT = "import pulumi\nimport pulumi_aws as aws\n"


def _scan(root: Path, body: str) -> set[str]:
    (root / "__main__.py").write_text(_IMPORT + body, encoding="utf-8")
    return {f.rule_id for f in run_scan(root).findings}


# --------------------------------------------------------------------------- #
# What the AST walk recognises at all
# --------------------------------------------------------------------------- #


def test_calls_that_are_not_attribute_chains_are_skipped(tmp_path: Path) -> None:
    """A bare or computed call has no resource type to reason about; it must not crash the walk."""

    body = "print('hello')\nhandlers = [lambda: None]\nhandlers[0]()\n"
    assert _scan(tmp_path, body) == set()


def test_a_non_pulumi_attribute_call_is_not_treated_as_a_resource(tmp_path: Path) -> None:
    """`json.dumps(...)` is an attribute chain too; anchoring on the package root is the filter."""

    body = "import json\njson.dumps({'encrypted': False})\n"
    assert _scan(tmp_path, body) == set()


# --------------------------------------------------------------------------- #
# IAC-PUL-002 -- management ports open to the internet
# --------------------------------------------------------------------------- #


def _security_group(from_port: int, to_port: int, cidr: str = "0.0.0.0/0") -> str:
    return (
        "aws.ec2.SecurityGroup('web',\n"
        "    ingress=[{\n"
        f"        'from_port': {from_port},\n"
        f"        'to_port': {to_port},\n"
        "        'protocol': 'tcp',\n"
        f"        'cidr_blocks': ['{cidr}'],\n"
        "    }],\n"
        ")\n"
    )


@pytest.mark.parametrize(
    ("label", "from_port", "to_port"),
    [("ssh exactly", 22, 22), ("rdp exactly", 3389, 3389), ("a range covering mysql", 3000, 4000)],
)
def test_a_management_port_open_to_the_world_is_reported(
    label: str, from_port: int, to_port: int, tmp_path: Path
) -> None:
    assert "IAC-PUL-002" in _scan(tmp_path, _security_group(from_port, to_port)), label


def test_a_range_that_covers_no_management_port_is_not_reported(tmp_path: Path) -> None:
    assert "IAC-PUL-002" not in _scan(tmp_path, _security_group(8080, 8090))


def test_a_management_port_open_only_to_a_private_range_is_not_reported(tmp_path: Path) -> None:
    """The counterpart that matters: SSH from inside the VPC is how bastions work."""

    assert "IAC-PUL-002" not in _scan(tmp_path, _security_group(22, 22, cidr="10.0.0.0/8"))


# --------------------------------------------------------------------------- #
# IAC-PUL-004 -- encryption at rest
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "program"),
    [
        ("rds with nothing said", "aws.rds.Instance('db')\n"),
        ("rds explicitly unencrypted", "aws.rds.Instance('db', storage_encrypted=False)\n"),
        ("ebs with nothing said", "aws.ebs.Volume('vol')\n"),
        ("ebs explicitly unencrypted", "aws.ebs.Volume('vol', encrypted=False)\n"),
        ("dynamodb with nothing said", "aws.dynamodb.Table('tbl')\n"),
    ],
)
def test_storage_without_encryption_at_rest_is_reported(label: str, program: str, tmp_path: Path) -> None:
    """Absent and explicitly false are the same posture, and both are reported."""

    assert "IAC-PUL-004" in _scan(tmp_path, program), label


@pytest.mark.parametrize(
    ("label", "program"),
    [
        ("rds snake_case", "aws.rds.Instance('db', storage_encrypted=True)\n"),
        ("rds camelCase", "aws.rds.Instance('db', storageEncrypted=True)\n"),
        ("ebs", "aws.ebs.Volume('vol', encrypted=True)\n"),
        ("dynamodb snake_case", "aws.dynamodb.Table('tbl', server_side_encryption={'enabled': True})\n"),
        ("dynamodb camelCase", "aws.dynamodb.Table('tbl', serverSideEncryption={'enabled': True})\n"),
    ],
)
def test_encrypted_storage_is_not_reported_in_either_spelling(label: str, program: str, tmp_path: Path) -> None:
    """Pulumi accepts both; honouring one would silently fail half the users of this rule."""

    assert "IAC-PUL-004" not in _scan(tmp_path, program), label


# --------------------------------------------------------------------------- #
# IAC-PUL-006 -- resources that hand out a public IP
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "program"),
    [
        ("subnet", "aws.ec2.Subnet('public', map_public_ip_on_launch=True)\n"),
        ("subnet camelCase", "aws.ec2.Subnet('public', mapPublicIpOnLaunch=True)\n"),
        ("instance", "aws.ec2.Instance('web', associate_public_ip_address=True)\n"),
        ("instance camelCase", "aws.ec2.Instance('web', associatePublicIpAddress=True)\n"),
    ],
)
def test_a_resource_that_takes_a_public_ip_is_reported(label: str, program: str, tmp_path: Path) -> None:
    assert "IAC-PUL-006" in _scan(tmp_path, program), label


@pytest.mark.parametrize(
    ("label", "program"),
    [
        ("subnet says no", "aws.ec2.Subnet('private', map_public_ip_on_launch=False)\n"),
        ("subnet says nothing", "aws.ec2.Subnet('private')\n"),
        ("instance says no", "aws.ec2.Instance('web', associate_public_ip_address=False)\n"),
    ],
)
def test_a_resource_that_does_not_take_a_public_ip_is_not_reported(label: str, program: str, tmp_path: Path) -> None:
    """`is True` on purpose: silence here has to mean silence, not "probably fine"."""

    assert "IAC-PUL-006" not in _scan(tmp_path, program), label
