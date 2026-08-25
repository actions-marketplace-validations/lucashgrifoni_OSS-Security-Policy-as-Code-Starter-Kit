"""``timeout`` beside ``findings=0`` reads as a clean scan unless something says otherwise.

The one-line summary the five in-process ``scan-*`` commands print carries the status --
but it carries ``findings=0`` in the same breath, and in a CI log that pair looks like a
pass. ``scan-sast`` has printed a note beside it since it was the only command that could
produce the state; the other five could not produce it at all, because they discarded
``--timeout``. Now that they honor it, they owe the operator the same sentence.

Asserted through the real command rather than the emitter, because the wiring is the part
that was missing: five separate call sites, and a note nobody calls is a note nobody sees.

Whitespace is collapsed before matching. Rich wraps stderr at the console width, so the
sentence arrives split across lines at a point that depends on the terminal.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()

#: (command, filename, source). One file each, so the run has something to skip.
COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("scan-iac", "main.tf", 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'),
    (
        "scan-k8s",
        "deploy.yaml",
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\n"
        "spec:\n  containers:\n    - name: app\n      image: nginx:latest\n",
    ),
    (
        "scan-cfn",
        "stack.template",
        'AWSTemplateFormatVersion: "2010-09-09"\n'
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"
        "    Properties:\n      AccessControl: PublicRead\n",
    ),
    (
        "scan-pulumi",
        "__main__.py",
        "import pulumi\nimport pulumi_aws as aws\n\naws.s3.Bucket('d', acl='public-read')\n",
    ),
    (
        "scan-bicep",
        "infra.bicep",
        "resource sa 'Microsoft.Storage/storageAccounts@2021-04-01' = {\n"
        "  name: 'demo'\n  location: 'eastus'\n"
        "  properties: {\n    supportsHttpsTrafficOnly: false\n  }\n}\n",
    ),
)

_IDS = [command for command, _, _ in COMMANDS]


@pytest.mark.parametrize("command,filename,source", COMMANDS, ids=_IDS)
def test_the_operator_is_told_the_scan_did_not_finish(command: str, filename: str, source: str, tmp_path: Path) -> None:
    (tmp_path / filename).write_text(source, encoding="utf-8")

    result = runner.invoke(app, [command, "--target", str(tmp_path), "--timeout", "0"])
    output = " ".join(result.output.split())

    assert result.exit_code == 0, (
        f"{command} exited {result.exit_code} on a timeout. Running out of budget is a "
        "recorded evidence state, not a usage error -- `scan-sast` exits 0 for it."
    )
    assert f"{command}: timeout" in output, f"the summary line does not carry the status: {output!r}"
    assert "ran out of its 0s budget" in output, (
        f"{command} printed `findings=0` beside `timeout` and said nothing else. Output: {output!r}"
    )
    assert "did not finish" in output


def test_a_scan_with_time_to_spare_says_nothing_about_a_budget(tmp_path: Path) -> None:
    """Otherwise the note above would be printed on every run and mean nothing."""

    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n', encoding="utf-8")

    result = runner.invoke(app, ["scan-iac", "--target", str(tmp_path)])
    output = " ".join(result.output.split())

    assert "scan-iac: ok" in output
    assert "budget" not in output, f"a complete scan warned about its budget: {output!r}"
