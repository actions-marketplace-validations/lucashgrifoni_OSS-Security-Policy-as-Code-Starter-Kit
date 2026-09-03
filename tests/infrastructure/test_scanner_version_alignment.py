"""Every scanner stamps its evidence with the version of the code that ran.

A scanner writes ``tool_version`` into the evidence file an evaluator later reads. When the
working tree and the installed wheel disagree -- the normal state during development, and
measured on this checkout as source 10.0.17 against installed metadata 10.0.4 -- stamping
the wheel's version would label evidence with code that did not produce it.

This file used to assert that three times over, once per branch of a lookup that read the
installed version and then discarded it whenever it differed:

    installed == source        -> returns the installed string
    installed != source        -> source wins
    package not installed      -> source wins

Three tests, one answer. The lookup was equivalent to returning the source constant, which
is what the bicep, CloudFormation and Pulumi scanners already say in so many words; the
Terraform and Kubernetes ones kept the branches, and ``init`` never got the rule at all --
it stamped the metadata version, or ``unknown`` when there was none.

So the property is asserted once, and across all five scanners rather than the two that
happened to have the dead branches.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

import pytest

import oss_policy_kit
from oss_policy_kit.infrastructure.iac import scanner as iac_scanner
from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep_scanner
from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn_scanner
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi_scanner
from oss_policy_kit.infrastructure.k8s import scanner as k8s_scanner

_SCANNERS = [iac_scanner, k8s_scanner, cfn_scanner, pulumi_scanner, bicep_scanner]
_IDS = ["iac", "k8s", "cfn", "pulumi", "bicep"]


@pytest.mark.parametrize("scanner_module", _SCANNERS, ids=_IDS)
def test_the_stamped_version_is_the_source_constant(scanner_module: Any) -> None:
    assert scanner_module._kit_version() == oss_policy_kit.__version__


@pytest.mark.parametrize("scanner_module", _SCANNERS, ids=_IDS)
def test_the_stamped_version_does_not_depend_on_installed_metadata(
    scanner_module: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Running from a checkout with no install, or with a stale one, changes nothing.

    Not redundant with the test above. That one only distinguishes a metadata lookup from
    the source constant on a machine where the two happen to DIFFER -- true on a dev
    checkout, false in CI, which installs the wheel it just built. Breaking the lookup
    outright asserts the same property everywhere: the installed distribution has no say.
    """

    def _raise(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("oss-policy-kit")

    monkeypatch.setattr(importlib.metadata, "version", _raise)

    assert scanner_module._kit_version() == oss_policy_kit.__version__


@pytest.mark.parametrize("scanner_module", _SCANNERS, ids=_IDS)
def test_the_stamped_version_reaches_the_evidence_file(scanner_module: Any, tmp_path: Path) -> None:
    """The field this exists for. A helper nothing writes out would be free to be wrong."""

    payload = scanner_module.render_evidence_payload(scanner_module.run_scan(tmp_path), target=tmp_path)

    assert payload["tool_version"] == oss_policy_kit.__version__
