"""What the MCP server offers besides tools: one guide, and prompts (none yet)."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files


@dataclass(frozen=True)
class Resource:
    uri: str
    name: str
    description: str
    mime_type: str
    file: str

    def text(self) -> str:
        return files("shim_enterprise.mcp").joinpath(self.file).read_text("utf-8")


RESOURCES: tuple[Resource, ...] = (
    Resource(
        uri="shim://guide/agent",
        name="agent guide",
        description="Read first: what each tool is for, the order to use them in, "
        "and what to do when an apply is refused.",
        mime_type="text/markdown",
        file="agent_guide.md",
    ),
)
# E55 adds the rule-writing prompt.
PROMPTS: tuple[()] = ()

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
