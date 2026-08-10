"""Branch coverage for application/evaluators_common.py shared helpers."""

from __future__ import annotations

import importlib.resources as ir
from pathlib import Path

import pytest

from oss_policy_kit.application import evaluators_common as ec
from oss_policy_kit.domain.models import ControlStatus

# --------------------------------------------------------------------------- #
# evidence_is_api_backed
# --------------------------------------------------------------------------- #


def test_evidence_is_api_backed_variants() -> None:
    assert ec.evidence_is_api_backed({"attested_by": "github-api-collection"}) is True
    assert ec.evidence_is_api_backed({"collection": {"evidence_collection_method": "live"}}) is True
    assert ec.evidence_is_api_backed({"collection": {"mode": "api"}}) is True
    assert ec.evidence_is_api_backed({"collection": {"mode": "manual"}}) is False
    assert ec.evidence_is_api_backed({}) is False


# --------------------------------------------------------------------------- #
# validate_json_evidence
# --------------------------------------------------------------------------- #


def _schema() -> dict:
    return {"type": "object", "required": ["x"], "properties": {"x": {"type": "integer"}}}


def test_validate_json_evidence_unreadable(tmp_path: Path) -> None:
    p = tmp_path / "ev.json"
    p.write_text("{not valid json", encoding="utf-8")
    data, err, ph = ec.validate_json_evidence(p, schema_loader=_schema, evidence_name="test")
    assert data is None
    assert err is not None
    assert "unreadable or invalid JSON" in err
    assert ph == []


def test_validate_json_evidence_non_dict_root(tmp_path: Path) -> None:
    p = tmp_path / "ev.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    data, err, _ph = ec.validate_json_evidence(p, schema_loader=_schema, evidence_name="test")
    assert data is None
    assert err is not None
    assert "root must be a JSON object" in err


def test_validate_json_evidence_schema_violation(tmp_path: Path) -> None:
    p = tmp_path / "ev.json"
    p.write_text('{"y": 1}', encoding="utf-8")  # missing required "x"
    data, err, _ph = ec.validate_json_evidence(p, schema_loader=_schema, evidence_name="test")
    assert data is None
    assert err is not None
    assert "does not match schema" in err


def test_validate_json_evidence_ok(tmp_path: Path) -> None:
    p = tmp_path / "ev.json"
    p.write_text('{"x": 1}', encoding="utf-8")
    data, err, ph = ec.validate_json_evidence(p, schema_loader=_schema, evidence_name="test")
    assert data == {"x": 1}
    assert err is None
    assert ph == []


# --------------------------------------------------------------------------- #
# is_valid_sha256_digest
# --------------------------------------------------------------------------- #


def test_is_valid_sha256_digest() -> None:
    assert ec.is_valid_sha256_digest(12345) is False  # not a string
    assert ec.is_valid_sha256_digest("deadbeef") is False  # too short / not 64 hex
    assert ec.is_valid_sha256_digest("0" * 64) is False  # weak all-zero
    assert ec.is_valid_sha256_digest("a" * 64) is False  # weak single-char
    assert ec.is_valid_sha256_digest("ab" * 32) is False  # weak repeating pair
    real = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert ec.is_valid_sha256_digest(real) is True


# --------------------------------------------------------------------------- #
# load_packaged_schema
# --------------------------------------------------------------------------- #


def test_load_packaged_schema_reads_a_bundled_schema() -> None:
    names = [p.name for p in ir.files("oss_policy_kit.data.schema").iterdir() if p.name.endswith(".json")]
    assert names, "expected at least one packaged JSON schema"
    schema = ec.load_packaged_schema(names[0])
    assert isinstance(schema, dict)


# --------------------------------------------------------------------------- #
# _looks_like_dockerfile
# --------------------------------------------------------------------------- #


def test_looks_like_dockerfile() -> None:
    assert ec._looks_like_dockerfile("Dockerfile") is True
    assert ec._looks_like_dockerfile("app.Dockerfile") is True
    assert ec._looks_like_dockerfile("Dockerfile.dev") is True
    assert ec._looks_like_dockerfile("README.md") is False  # no regex match
    assert ec._looks_like_dockerfile("Dockerfile.md") is False  # matches name but doc extension


# --------------------------------------------------------------------------- #
# find_dockerfiles / _iter_accepted_dockerfiles / _accept_dockerfile_candidate
# --------------------------------------------------------------------------- #


def test_find_dockerfiles_respects_limit(tmp_path: Path) -> None:
    for i in range(3):
        (tmp_path / f"Dockerfile.{i}").write_text("FROM scratch\n", encoding="utf-8")
    assert len(ec.find_dockerfiles(tmp_path, limit=2)) == 2


def test_find_dockerfiles_finds_real_files(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# not a dockerfile\n", encoding="utf-8")
    found = ec.find_dockerfiles(tmp_path)
    assert [p.name for p in found] == ["Dockerfile"]


def test_iter_accepted_dockerfiles_swallows_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(self: Path, *a: object, **k: object):
        raise OSError("rglob failed")

    monkeypatch.setattr(Path, "rglob", _boom)
    assert ec.find_dockerfiles(tmp_path) == []


def test_accept_dockerfile_candidate_resolve_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    def _boom(self: Path, *a: object, **k: object):
        raise OSError("resolve failed")

    monkeypatch.setattr(Path, "resolve", _boom)
    assert ec.find_dockerfiles(tmp_path) == []


def test_evidence_placeholder_outcome() -> None:
    assert ec.evidence_placeholder_outcome(Path("ev.json"), []) is None
    outcome = ec.evidence_placeholder_outcome(Path("ev.json"), ["REPLACE_ME"])
    assert outcome is not None
    assert outcome.status == ControlStatus.NOT_EVALUATED
