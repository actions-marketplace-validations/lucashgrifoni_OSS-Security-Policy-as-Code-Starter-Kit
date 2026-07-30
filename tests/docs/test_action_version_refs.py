"""Guard: documented Action tag references match the shipped version.

The composite Action is advertised in several places. Each `@vX.Y.Z` reference is a copy-paste
target, so a stale one hands the reader an Action release older than the kit they just installed.
Four had drifted before this guard existed: README.md pinned `@v7.2.0`, docs/quickstart-15-min.md
`@v7.2.0`, and docs/github-action.md carried `@v10.0.1` *and* `@v6.4.0` — up to four majors behind.

Each is now annotated with `# x-release-please-version` and its file is listed under `extra-files`
in `.github/release-please-config.json`, so release-please rewrites them on every release. This test
is the backstop: it fails if a reference drifts from the packaged version, if a new reference is
added without the annotation, or if a file carrying one drops out of `extra-files`.

Commit-SHA pins are deliberately exempt: the SHA of a release commit cannot be known before that
release exists, so it necessarily trails by one version and release-please cannot rewrite it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from oss_policy_kit import __version__

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_PLEASE_CONFIG = REPO_ROOT / ".github" / "release-please-config.json"

_ACTION = "lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit"
# `@v1.2.3` tag references only; a 40-hex commit pin is matched separately and skipped.
_TAG_REF = re.compile(rf"{re.escape(_ACTION)}@v(\d+\.\d+\.\d+)")
_SHA_REF = re.compile(rf"{re.escape(_ACTION)}@[0-9a-f]{{40}}")
_ANNOTATION = "x-release-please-version"

_SKIP_DIRS = {".git", ".venv", "node_modules", "melhorias", "sonar", "out", "artifacts", "dist"}


def _searchable_files() -> list[Path]:
    files: list[Path] = []
    for pattern in ("*.md", "*.yml", "*.yaml"):
        for path in REPO_ROOT.rglob(pattern):
            if _SKIP_DIRS & set(path.parts):
                continue
            if path.name.startswith(".venv") or ".tmp" in path.parts[0:2]:
                continue
            files.append(path)
    return files


def _tag_reference_lines() -> list[tuple[Path, int, str]]:
    hits: list[tuple[Path, int, str]] = []
    for path in _searchable_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _ACTION not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _SHA_REF.search(line):
                continue
            if _TAG_REF.search(line):
                hits.append((path, lineno, line.strip()))
    return hits


def test_documented_action_tag_matches_packaged_version() -> None:
    stale = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line}"
        for path, lineno, line in _tag_reference_lines()
        if _TAG_REF.search(line).group(1) != __version__  # type: ignore[union-attr]
    ]
    assert not stale, (
        f"These Action references do not match the packaged version {__version__}. "
        "A reader copying them gets an older Action than the kit they installed:\n  " + "\n  ".join(stale)
    )


def test_every_action_tag_reference_is_release_please_annotated() -> None:
    unannotated = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line}"
        for path, lineno, line in _tag_reference_lines()
        if _ANNOTATION not in line
    ]
    assert not unannotated, (
        f"These Action references lack the `{_ANNOTATION}` annotation, so release-please will not "
        "bump them and they will silently go stale:\n  " + "\n  ".join(unannotated)
    )


def test_files_with_annotated_references_are_release_please_extra_files() -> None:
    config = json.loads(RELEASE_PLEASE_CONFIG.read_text(encoding="utf-8"))
    extra_files = set(config["packages"]["."]["extra-files"])
    missing = sorted(
        {path.relative_to(REPO_ROOT).as_posix() for path, _, line in _tag_reference_lines() if _ANNOTATION in line}
        - extra_files
    )
    assert not missing, (
        "These files carry an annotated Action reference but are not in the release-please "
        "`extra-files` list, so the annotation is inert:\n  " + "\n  ".join(missing)
    )


def test_guard_actually_finds_the_known_references() -> None:
    """Mutation check: the guard must be scanning something, not passing on an empty set."""

    assert len(_tag_reference_lines()) >= 3
