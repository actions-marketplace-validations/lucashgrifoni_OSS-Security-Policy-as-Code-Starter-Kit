"""Four Bicep rules, asserted in both directions against real templates.

A rule that never fires and a rule that always fires look identical from a passing test suite,
and they fail an adopter in opposite, equally expensive ways: one lets an open management port
into production, the other buries the real finding under noise nobody reads. Each rule below
gets a template that must trip it and a template that must not.

The templates are written as Bicep and put through `run_scan`, not handed to the rule functions
directly. The scanner is a line-and-brace reader rather than a compiler, so what it actually
sees in a file is the thing worth testing -- a rule can be perfectly correct about a resource the
parser never handed it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.iac.bicep.scanner import run_scan


def _scan(root: Path, body: str) -> set[str]:
    (root / "main.bicep").write_text(body, encoding="utf-8")
    return {f.rule_id for f in run_scan(root).findings}


def _nsg(port_range: str) -> str:
    return (
        "resource nsg 'Microsoft.Network/networkSecurityGroups/securityRules@2023-05-01' = {\n"
        "  name: 'allow-inbound'\n"
        "  properties: {\n"
        "    access: 'Allow'\n"
        "    direction: 'Inbound'\n"
        "    sourceAddressPrefix: '*'\n"
        f"    destinationPortRange: '{port_range}'\n"
        "  }\n"
        "}\n"
    )


# --------------------------------------------------------------------------- #
# IAC-BICEP-002 -- management ports open to the internet
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "port_range"),
    [("ssh exactly", "22-22"), ("rdp exactly", "3389-3389"), ("a range covering postgres", "5000-6000")],
)
def test_a_management_port_open_to_the_world_is_reported(label: str, port_range: str, tmp_path: Path) -> None:
    assert "IAC-BICEP-002" in _scan(tmp_path, _nsg(port_range)), label


def test_a_range_that_covers_no_management_port_is_not_reported(tmp_path: Path) -> None:
    """The counterpart: flagging every open inbound range would flag every load balancer."""

    assert "IAC-BICEP-002" not in _scan(tmp_path, _nsg("8080-8090"))


def test_an_inbound_rule_that_is_not_open_to_the_world_is_not_reported(tmp_path: Path) -> None:
    body = _nsg("22-22").replace("sourceAddressPrefix: '*'", "sourceAddressPrefix: '10.0.0.0/8'")
    assert "IAC-BICEP-002" not in _scan(tmp_path, body)


# --------------------------------------------------------------------------- #
# IAC-BICEP-003 -- high-privilege built-in roles
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "role_id"),
    [
        ("Owner", "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"),
        ("Contributor", "b24988ac-6180-42a0-ab88-20f7382dd24c"),
        ("User Access Administrator", "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"),
    ],
)
def test_a_broad_built_in_role_binding_is_reported(label: str, role_id: str, tmp_path: Path) -> None:
    body = (
        "resource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n"
        "  name: guid('ra')\n"
        "  properties: {\n"
        f"    roleDefinitionId: '/providers/Microsoft.Authorization/roleDefinitions/{role_id}'\n"
        "  }\n"
        "}\n"
    )
    assert "IAC-BICEP-003" in _scan(tmp_path, body), label


def test_a_narrow_role_binding_is_not_reported(tmp_path: Path) -> None:
    """Reader (`acdd72a7-...`) is the shape a least-privilege assignment takes."""

    body = (
        "resource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n"
        "  name: guid('ra')\n"
        "  properties: {\n"
        "    roleDefinitionId: '/providers/Microsoft.Authorization/roleDefinitions/"
        "acdd72a7-3385-48ef-bd42-f606fba81ae7'\n"
        "  }\n"
        "}\n"
    )
    assert "IAC-BICEP-003" not in _scan(tmp_path, body)


# --------------------------------------------------------------------------- #
# IAC-BICEP-004 -- database encryption at rest
# --------------------------------------------------------------------------- #


def test_a_sql_database_without_transparent_data_encryption_is_reported(tmp_path: Path) -> None:
    body = "resource db 'Microsoft.Sql/servers/databases@2023-05-01' = {\n  name: 'appdb'\n}\n"
    assert "IAC-BICEP-004" in _scan(tmp_path, body)


def test_a_sql_database_that_declares_encryption_enabled_is_not_reported(tmp_path: Path) -> None:
    body = (
        "resource db 'Microsoft.Sql/servers/databases@2023-05-01' = {\n"
        "  name: 'appdb'\n"
        "  properties: {\n"
        "    transparentDataEncryption: {\n"
        "      state: 'Enabled'\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert "IAC-BICEP-004" not in _scan(tmp_path, body)


# --------------------------------------------------------------------------- #
# IAC-BICEP-005 -- diagnostic settings
# --------------------------------------------------------------------------- #


def test_a_storage_account_with_no_paired_diagnostic_settings_is_reported(tmp_path: Path) -> None:
    body = "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'appstorage'\n}\n"
    assert "IAC-BICEP-005" in _scan(tmp_path, body)


def test_a_storage_account_with_diagnostic_settings_scoped_to_it_is_not_reported(tmp_path: Path) -> None:
    """The pairing is matched on the `scope:` symbol, which is how Bicep expresses it."""

    body = (
        "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'appstorage'\n"
        "}\n"
        "resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
        "  name: 'stg-diag'\n"
        "  scope: stg\n"
        "}\n"
    )
    assert "IAC-BICEP-005" not in _scan(tmp_path, body)


def test_diagnostic_settings_scoped_to_something_else_do_not_cover_the_storage_account(tmp_path: Path) -> None:
    """A pairing matched loosely would silence the rule for every resource in the file."""

    body = (
        "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'appstorage'\n"
        "}\n"
        "resource vault 'Microsoft.KeyVault/vaults@2023-02-01' = {\n"
        "  name: 'appvault'\n"
        "}\n"
        "resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
        "  name: 'vault-diag'\n"
        "  scope: vault\n"
        "}\n"
    )
    (tmp_path / "main.bicep").write_text(body, encoding="utf-8")
    uncovered = [f.resource_name for f in run_scan(tmp_path).findings if f.rule_id == "IAC-BICEP-005"]

    assert uncovered == ["stg"]
