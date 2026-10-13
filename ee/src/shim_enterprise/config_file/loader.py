"""Read a configuration file: one plain YAML document, nothing YAML could surprise with."""

from __future__ import annotations

import re
from typing import Any, Literal
from uuid import UUID

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_FILE_BYTES = 1_000_000
# A full file of 100 rules is about 5,000 nodes; parsing time follows the count.
MAX_NODES = 50_000
_BOOL = "tag:yaml.org,2002:bool"


class ConfigFileError(ValueError):
    def __init__(self, path: str, message: str) -> None:
        super().__init__(message)
        self.path = path


class ConfigLoader(yaml.SafeLoader):
    """SafeLoader without anchors, aliases or duplicate keys.

    Only `true` and `false` (any case) are booleans, so `off`, `on`, `yes` and
    `no` stay the strings a setting such as `response_scan: off` means.
    """

    nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
            raise ComposerError(
                None, None, "anchors and aliases are not allowed", event.start_mark
            )
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise ComposerError(
                None, None, f"a file holds at most {MAX_NODES} nodes", event.start_mark
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


ConfigLoader.yaml_implicit_resolvers = {
    first: [(tag, pattern) for tag, pattern in resolvers if tag != _BOOL]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
ConfigLoader.add_implicit_resolver(
    _BOOL, re.compile(r"^(?:true|false)$", re.IGNORECASE), list("tTfF")
)


class ConfigFileV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["shim.config"]
    version: Literal[1]
    organization_id: UUID
    serial: int = Field(ge=1, le=2**63 - 1)
    exported_from: dict[str, Any] | None = None
    resources: dict[str, Any]


def load_config(data: bytes) -> ConfigFileV1:
    """The file's header and sections; each section is checked by its resource."""
    if len(data) > MAX_FILE_BYTES:
        raise ConfigFileError(
            "file", f"a configuration file is at most {MAX_FILE_BYTES} bytes"
        )
    try:
        document = yaml.load(data.decode("utf-8"), Loader=ConfigLoader)  # noqa: S506
    except UnicodeDecodeError:
        raise ConfigFileError("file", "the file is not UTF-8") from None
    except RecursionError:
        raise ConfigFileError("file", "the file nests too deeply") from None
    except (TypeError, ValueError):
        # An unhashable key (`? [1]`) or an impossible date (2024-02-30).
        raise ConfigFileError(
            "file", "the file holds a key or value YAML cannot read"
        ) from None
    except yaml.MarkedYAMLError as error:
        mark = error.problem_mark or error.context_mark
        where = f"line {mark.line + 1}, column {mark.column + 1}" if mark else "file"
        message = " ".join(part for part in (error.context, error.problem) if part)
        raise ConfigFileError(where, message or "not valid YAML") from None
    except yaml.YAMLError:
        raise ConfigFileError("file", "not valid YAML") from None
    try:
        return ConfigFileV1.model_validate(document)
    except ValidationError as error:
        first = error.errors(include_url=False)[0]
        raise ConfigFileError(
            ".".join(str(part) for part in first["loc"]) or "file", first["msg"]
        ) from None
