"""What the MCP server offers besides tools: one guide, and prompts (none yet)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Any


@dataclass(frozen=True)
class Resource:
    uri: str
    name: str
    description: str
    mime_type: str
    file: str

    def text(self) -> str:
        return files("shim_enterprise.mcp").joinpath(self.file).read_text("utf-8")


def _guide(text: str) -> str:
    return (
        files("shim_enterprise.mcp")
        .joinpath("guides")
        .joinpath(text)
        .read_text("utf-8")
    )


@dataclass(frozen=True)
class Prompt:
    name: str
    description: str
    arguments: tuple[Mapping[str, Any], ...]

    def listing(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "arguments": [dict(argument) for argument in self.arguments],
        }

    def text(self, arguments: Mapping[str, Any]) -> str | None:
        """The prompt's text, or None when an argument is not one it takes."""
        language = arguments.get("language", "tr")
        return _guide(f"rules.{language}.md") if language in ("tr", "en") else None


RESOURCES: tuple[Resource, ...] = (
    Resource(
        uri="shim://guide/agent",
        name="agent guide",
        description="Read first: what each tool is for, the order to use them in, "
        "and what to do when an apply is refused.",
        mime_type="text/markdown",
        file="agent_guide.md",
    ),
    *(
        Resource(
            uri=f"shim://guide/rules/{language}",
            name=f"rule writing guide ({language})",
            description="How to turn the user's sentence into concrete rules with "
            "propose_rules, and what to ask when shim needs examples.",
            mime_type="text/markdown",
            file=f"guides/rules.{language}.md",
        )
        for language in ("tr", "en")
    ),
)
PROMPTS: tuple[Prompt, ...] = (
    Prompt(
        name="write_rules",
        description="Turn the user's own sentence about what is secret into concrete "
        "rules, with examples, for an administrator to approve.",
        arguments=(
            {
                "name": "language",
                "description": "tr (default) or en",
                "required": False,
            },
        ),
    ),
)

INSTRUCTIONS = (
    "shim is an AI gateway. Its findings and their severity come from its own "
    "rules, not from you: explain them in your words, and quote the evidence ids a "
    "finding carries. Every change goes through a plan that a person can see and "
    "undo; read a plan back with get_plan before you call it done. Changes that "
    "loosen protection need a person: when apply_plan answers PLAN_NOT_ALLOWLISTED, "
    "say why and leave the plan for an administrator. shim measures, detects and "
    "enforces the tenant's rules; never say it guarantees or certifies protection. "
    "Read the resource shim://guide/agent first."
)
