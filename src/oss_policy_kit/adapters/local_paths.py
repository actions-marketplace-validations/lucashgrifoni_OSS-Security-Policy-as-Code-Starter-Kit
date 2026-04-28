"""Safe path resolution for repository targets."""

from pathlib import Path

from oss_policy_kit.domain.errors import InvalidInputError


def resolve_existing_dir(path_str: str) -> Path:
    """Resolve user-supplied path to an absolute directory."""

    candidate = Path(path_str).expanduser()
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise InvalidInputError(f"Invalid path: {path_str} ({exc})") from exc
    if not resolved.is_dir():
        raise InvalidInputError(f"Not a directory or does not exist: {resolved}")
    return resolved
