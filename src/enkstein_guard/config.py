"""Small strict JSON configuration. No network, secret loading or execution."""

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class GuardConfig:
    schema_version: int = 1
    mode: str = "inspection_only"
    max_input_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("Unsupported configuration version")
        if self.mode != "inspection_only":
            raise ValueError("Protected execution is not implemented")
        if type(self.max_input_bytes) is not int or not 1 <= self.max_input_bytes <= 16_777_216:
            raise ValueError("Invalid input limit")


def load_config(path: str | None) -> GuardConfig:
    if path is None:
        return GuardConfig()
    raw = Path(path).read_bytes()
    if len(raw) > 65_536:
        raise ValueError("Configuration too large")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("Duplicate configuration field")
            result[key] = value
        return result
    data = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(data, dict) or set(data) - {"schema_version", "mode", "max_input_bytes"}:
        raise ValueError("Unknown configuration fields")
    return GuardConfig(**data)
