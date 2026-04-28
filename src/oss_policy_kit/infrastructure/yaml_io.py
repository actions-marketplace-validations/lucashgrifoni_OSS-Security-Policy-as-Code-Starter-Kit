"""Safe YAML loading."""

from pathlib import Path
from typing import Any, cast

import yaml


def load_yaml_file(path: Path) -> Any:
    """Load YAML using safe_load only."""

    text = path.read_text(encoding="utf-8")
    return cast(Any, yaml.safe_load(text))
