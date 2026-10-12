from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field


class ModelProfile(BaseModel):
    provider: Literal["vllm"] = "vllm"
    name: str
    base_url_env: str
    api_key_env: str
    temperature: float = 0.0
    timeout_seconds: int = 60


class AgentToolBinding(BaseModel):
    """A tool capability intentionally granted to one agent."""

    name: str
    purpose: str = Field(min_length=10)
    input_schema: str = Field(min_length=3)


class ToolDefinition(BaseModel):
    """Global implementation metadata; it does not assign the tool to any agent."""

    adapter: str = Field(min_length=3)
    timeout_seconds: int = Field(default=30, gt=0, le=300)
    result_limit: int = Field(default=100, gt=0, le=10_000)
    classification: str = "internal"
    query_template: str | None = None
    max_hops: int = Field(default=4, ge=1, le=10)
    # Local-only semantic NIST mapping options. They apply only to the deterministic mapper adapter.
    mapping_backend: Literal["lexical", "transformer"] = "lexical"
    embedding_model: str | None = None
    reranker_model: str | None = None
    embedding_cache_dir: str | None = None
    embedding_batch_size: int = Field(default=8, ge=1, le=64)


class AgentDefinition(BaseModel):
    id: str
    display_name: str
    sequence: int = Field(ge=1)
    model_profile: str
    max_tokens: int = Field(gt=0, le=16_384)
    tools: list[AgentToolBinding] = Field(default_factory=list)
    input_keys: list[str]
    output_key: str
    system_prompt: str = Field(min_length=20)
    execution_mode: Literal["llm_agent", "deterministic_nist_mapper"] = "llm_agent"


class WorkflowConfig(BaseModel):
    models: dict[str, ModelProfile]
    tools: dict[str, ToolDefinition]
    agents: list[AgentDefinition]
    topics: dict[str, str]


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as file:
        value = yaml.safe_load(file)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a YAML mapping in {path}")
    return value


def load_workflow_config(config_dir: str | Path = "config") -> WorkflowConfig:
    root = Path(config_dir)
    model_data = _read_yaml(root / "models.yaml")
    topic_data = _read_yaml(root / "topics.yaml")
    tool_data = _read_yaml(root / "tools.yaml")
    agent_dir = root / "agents"
    agents = [AgentDefinition.model_validate(_read_yaml(path)) for path in sorted(agent_dir.glob("*.yaml"))]
    agents.sort(key=lambda agent: agent.sequence)
    if not agents:
        raise ValueError(f"No agent definitions found in {agent_dir}")
    sequences = [agent.sequence for agent in agents]
    if len(sequences) != len(set(sequences)):
        raise ValueError("Every agent must have a unique sequence")
    profiles = model_data.get("models", {})
    tools = tool_data.get("tools", {})
    for agent in agents:
        if agent.model_profile not in profiles:
            raise ValueError(f"Agent {agent.id} references unknown model profile {agent.model_profile}")
        unknown_tools = [tool.name for tool in agent.tools if tool.name not in tools]
        if unknown_tools:
            raise ValueError(f"Agent {agent.id} references unknown tools: {', '.join(unknown_tools)}")
    return WorkflowConfig(
        models=profiles,
        tools=tools,
        agents=agents,
        topics=topic_data.get("topics", {}),
    )
