"""The Terraform index skips what it cannot understand instead of refusing the whole file.

`hcl2` hands back whatever the document contained, and a `.tf` file in a real repository is not
always the shape the parser's happy path assumes -- generated modules, partial templates and
files mid-edit all reach this code. The index therefore drops the entries it cannot read and
keeps the rest, because a single odd block must not cost the evaluators every other resource in
the same file.

That tolerance is only safe while it is *narrow*: what gets skipped must be the malformed entry
and nothing else. Each test below pairs an unreadable entry with a well-formed one and asserts
the good one survived.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.infrastructure.iac.tf_resource_index import (
    TfResourceIndex,
    _blocks_from_resource_entry,
    _iter_resource_blocks,
    build_index,
)

_SOURCE = Path("main.tf")


def _types(parsed: dict[str, Any]) -> list[tuple[str, str]]:
    return [(b.resource_type, b.name) for b in _iter_resource_blocks(parsed, _SOURCE)]


# --------------------------------------------------------------------------- #
# Shapes the walk refuses
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "raw_resources"),
    [
        ("a resource key holding a mapping", {"aws_s3_bucket": {}}),
        ("a resource key holding a string", "aws_s3_bucket"),
        ("a resource key holding a number", 7),
    ],
)
def test_a_resource_section_that_is_not_a_list_yields_nothing(label: str, raw_resources: Any) -> None:
    """hcl2 emits a list of entries; anything else is a document this walk cannot navigate."""

    assert _types({"resource": raw_resources}) == [], label


def test_a_file_with_no_resource_section_yields_nothing() -> None:
    assert _types({"variable": [{"region": {"default": "us-east-1"}}]}) == []


@pytest.mark.parametrize(
    ("label", "entry"),
    [
        ("an entry that is a bare string", "aws_s3_bucket"),
        ("an entry that is a list", ["aws_s3_bucket"]),
        ("an entry that is null", None),
    ],
)
def test_an_entry_that_is_not_a_type_to_name_mapping_is_skipped(label: str, entry: Any) -> None:
    assert list(_blocks_from_resource_entry(entry, _SOURCE)) == [], label


def test_a_resource_type_whose_names_are_not_a_mapping_is_skipped_without_losing_the_rest() -> None:
    """The narrowness that makes the tolerance safe: one bad type, every other type kept."""

    parsed = {
        "resource": [
            {
                "aws_s3_bucket": ["not-a-name-mapping"],
                "aws_kms_key": {"main": {"enable_key_rotation": True}},
            }
        ]
    }
    assert _types(parsed) == [("aws_kms_key", "main")]


def test_a_named_resource_whose_body_is_not_a_mapping_is_skipped_without_losing_its_siblings() -> None:
    parsed = {
        "resource": [
            {
                "aws_s3_bucket": {
                    "broken": "just-a-string",
                    "good": {"bucket": "logs"},
                }
            }
        ]
    }
    assert _types(parsed) == [("aws_s3_bucket", "good")]


# --------------------------------------------------------------------------- #
# Reading the index back
# --------------------------------------------------------------------------- #


def test_every_block_is_reachable_without_knowing_its_type(tmp_path: Path) -> None:
    """`all_blocks` is how whole-file rules run; missing a type would silently narrow them."""

    tf = tmp_path / "main.tf"
    tf.write_text(
        'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n'
        'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n'
        'resource "aws_kms_key" "main" {\n  enable_key_rotation = true\n}\n',
        encoding="utf-8",
    )
    index = build_index([tf])

    assert sorted(b.name for b in index.all_blocks()) == ["data", "logs", "main"]
    assert sorted(index.types_matching("aws_")) == ["aws_kms_key", "aws_s3_bucket"]
    assert [b.name for b in index.resources("aws_s3_bucket")] == ["logs", "data"]


def test_an_empty_index_iterates_to_nothing() -> None:
    assert list(TfResourceIndex().all_blocks()) == []
    assert TfResourceIndex().resources("aws_s3_bucket") == []


def test_a_file_that_cannot_be_parsed_is_recorded_rather_than_raised(tmp_path: Path) -> None:
    """Best-effort like a real CSPM tool: one broken file must not end the scan."""

    broken = tmp_path / "broken.tf"
    broken.write_text('resource "aws_s3_bucket" "logs" {\n', encoding="utf-8")
    good = tmp_path / "good.tf"
    good.write_text('resource "aws_kms_key" "main" {\n  enable_key_rotation = true\n}\n', encoding="utf-8")

    index = build_index([broken, good])

    assert [p for p, _ in index.parse_errors] == [broken]
    assert index.files_parsed == [good]
    assert [b.name for b in index.all_blocks()] == ["main"]
