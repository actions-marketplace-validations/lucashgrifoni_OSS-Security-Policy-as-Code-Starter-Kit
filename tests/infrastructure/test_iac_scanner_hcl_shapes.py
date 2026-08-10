"""Both shapes HCL2 hands the Terraform scanner for the same construct.

`python-hcl2` returns a block sometimes as a dict and sometimes as a list of one dict,
depending on how the source was written. Every helper below normalizes for that, and every
one of those normalizations had only ever been exercised on one side.

That is a bad thing to leave half-tested in a scanner. A normalization that drops the shape
it never saw does not raise and does not warn -- it returns no findings, and a repository
with a wide-open security group is reported clean. The failure is invisible in exactly the
direction that matters.

So each pair of tests feeds the same logical configuration in both shapes and asserts they
produce the same answer, rather than asserting each shape's answer separately: equality
between the two is the property the normalization exists to provide.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.infrastructure.iac import scanner as s
from oss_policy_kit.infrastructure.iac.tf_resource_index import TfBlock, TfResourceIndex


def _index(**raw: Any) -> TfResourceIndex:
    """A resource index whose single file parsed to *raw*."""

    return TfResourceIndex(raw_files={Path("main.tf"): dict(raw)})


def _block(**body: Any) -> TfBlock:
    """A real TfBlock rather than a bare dict, so the helpers get the type they declare."""

    return TfBlock(
        resource_type="aws_security_group",
        name="example",
        body=dict(body),
        source_path=Path("main.tf"),
    )


# --------------------------------------------------------------------------- #
# security group ingress
# --------------------------------------------------------------------------- #


_INGRESS = {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}


def test_a_single_ingress_is_read_whether_hcl_wrapped_it_in_a_list_or_not() -> None:
    """The dict shape was the untested one; missing it hides an open SSH port."""

    as_dict = s._sg_ingress_entries(_block(ingress=_INGRESS))
    as_list = s._sg_ingress_entries(_block(ingress=[_INGRESS]))

    assert as_dict == as_list == [_INGRESS]


def test_ingress_entries_that_are_not_objects_are_dropped() -> None:
    assert s._sg_ingress_entries(_block(ingress=["not-a-dict", _INGRESS, None])) == [_INGRESS]


@pytest.mark.parametrize("block", [{}, {"ingress": None}, {"ingress": []}])
def test_a_group_with_no_ingress_yields_nothing(block: dict[str, Any]) -> None:
    assert s._sg_ingress_entries(_block(**block)) == []


# --------------------------------------------------------------------------- #
# terraform { } blocks
# --------------------------------------------------------------------------- #


def test_a_terraform_block_is_found_in_either_shape() -> None:
    body = {"required_version": ">= 1.5"}

    as_dict = list(s._iter_terraform_blocks(_index(terraform=body)))
    as_list = list(s._iter_terraform_blocks(_index(terraform=[body])))

    assert as_dict == as_list == [(Path("main.tf"), body)]


def test_a_non_object_terraform_entry_is_skipped() -> None:
    assert list(s._iter_terraform_blocks(_index(terraform=["not-a-dict"]))) == []


# --------------------------------------------------------------------------- #
# required_providers
# --------------------------------------------------------------------------- #


def test_an_unpinned_provider_is_reported_in_either_shape() -> None:
    """An unpinned provider is the supply-chain finding this rule exists for."""

    required = {"aws": {}}

    assert s._unpinned_providers(required) == s._unpinned_providers([required]) == ["aws"]


def test_a_pinned_provider_is_not_reported() -> None:
    """The negative case, so the test above cannot pass by always reporting."""

    assert s._unpinned_providers([{"aws": {"version": "~> 5.0"}}]) == []


def test_a_provider_whose_spec_is_not_an_object_counts_as_unpinned() -> None:
    """No parseable version constraint means nothing is pinning it."""

    assert s._unpinned_providers([{"aws": "5.0"}]) == ["aws"]


def test_a_non_object_entry_in_required_providers_is_skipped() -> None:
    assert s._unpinned_providers(["not-a-dict", {"aws": {}}]) == ["aws"]


# --------------------------------------------------------------------------- #
# lifecycle.prevent_destroy
# --------------------------------------------------------------------------- #


def test_prevent_destroy_is_read_in_either_shape() -> None:
    lifecycle = {"prevent_destroy": True}

    assert s._prevent_destroy_enabled(_block(lifecycle=lifecycle)) is True
    assert s._prevent_destroy_enabled(_block(lifecycle=[lifecycle])) is True


@pytest.mark.parametrize(
    "block",
    [
        {},
        {"lifecycle": []},
        {"lifecycle": "not-an-object"},
        {"lifecycle": {"prevent_destroy": False}},
        # Only a real boolean counts: the string "true" is what an unresolved
        # interpolation looks like, and treating it as enabled would claim a
        # protection the plan does not actually have.
        {"lifecycle": {"prevent_destroy": "true"}},
    ],
)
def test_anything_short_of_an_explicit_true_is_not_prevent_destroy(block: dict[str, Any]) -> None:
    assert s._prevent_destroy_enabled(_block(**block)) is False


# --------------------------------------------------------------------------- #
# data blocks and IAM policy documents
# --------------------------------------------------------------------------- #


def test_a_data_block_is_iterated_in_either_shape() -> None:
    entry = {"aws_ami": {"ubuntu": {"most_recent": True}}}

    as_dict = list(s._iter_data_entries(_index(data=entry)))
    as_list = list(s._iter_data_entries(_index(data=[entry])))

    assert as_dict == as_list == [(Path("main.tf"), entry)]


@pytest.mark.parametrize("data", ["not-a-list-or-dict", 42])
def test_a_data_section_of_an_unusable_type_is_skipped(data: Any) -> None:
    assert list(s._iter_data_entries(_index(data=data))) == []


def test_an_iam_policy_document_is_yielded_with_its_name() -> None:
    body = {"statement": [{"actions": ["s3:*"], "resources": ["*"]}]}
    index = _index(data=[{"aws_iam_policy_document": {"wide_open": body}}])

    assert list(s._iter_iam_policy_docs(index)) == [(Path("main.tf"), "wide_open", body)]


def test_a_policy_document_section_that_is_not_an_object_is_skipped() -> None:
    index = _index(data=[{"aws_iam_policy_document": "not-an-object"}])

    assert list(s._iter_iam_policy_docs(index)) == []


def test_a_policy_document_body_that_is_not_an_object_is_skipped() -> None:
    index = _index(data=[{"aws_iam_policy_document": {"broken": "not-an-object"}}])

    assert list(s._iter_iam_policy_docs(index)) == []


# --------------------------------------------------------------------------- #
# file discovery
# --------------------------------------------------------------------------- #


def test_a_directory_matching_the_glob_is_not_scanned_as_a_file(tmp_path: Path) -> None:
    """`*.tf` matches directories too; handing one to the parser is an error, not a scan."""

    (tmp_path / "modules.tf").mkdir()
    real = tmp_path / "main.tf"
    real.write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")

    found = s._walk_tf_files(tmp_path, ["*.tf"], None)

    assert found == [real.resolve()]


def test_an_operator_exclude_removes_a_file_that_the_include_matched(tmp_path: Path) -> None:
    """`--exclude` is how an adopter silences a vendored or generated tree."""

    (tmp_path / "main.tf").write_text("", encoding="utf-8")
    generated = tmp_path / "generated.tf"
    generated.write_text("", encoding="utf-8")

    found = s._walk_tf_files(tmp_path, ["*.tf"], ["generated.tf"])

    assert generated.resolve() not in found
    assert (tmp_path / "main.tf").resolve() in found


@pytest.mark.parametrize("skipped", sorted(s._SKIP_DIRS))
def test_vendored_and_build_directories_are_never_scanned(tmp_path: Path, skipped: str) -> None:
    """A provider's own bundled Terraform is not this repository's posture."""

    nested = tmp_path / skipped / "vendor.tf"
    nested.parent.mkdir(parents=True)
    nested.write_text("", encoding="utf-8")

    assert s._walk_tf_files(tmp_path, ["**/*.tf"], None) == []


def test_the_same_file_reached_by_two_globs_is_returned_once(tmp_path: Path) -> None:
    """Duplicate paths would double-count every finding in that file."""

    (tmp_path / "main.tf").write_text("", encoding="utf-8")

    found = s._walk_tf_files(tmp_path, ["*.tf", "**/*.tf"], None)

    assert len(found) == 1
