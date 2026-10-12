from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from security_workflow.agents.base import ConfiguredAgent
from security_workflow.config import WorkflowConfig
from security_workflow.orchestration.nist_mapper_node import DeterministicNistMapperNode
from security_workflow.orchestration.state import WorkflowState
from security_workflow.services.vllm import ModelClient
from security_workflow.tools.registry import ToolRegistry


def build_workflow(
    config: WorkflowConfig, model_client: ModelClient, tool_registry: ToolRegistry | None = None
):
    """Build a sequential graph from agent YAML files.

    The graph intentionally has no hard-coded specialist names: adding an agent configuration changes the
    graph. Future routing rules can introduce parallel branches without changing the agent interface.
    """
    graph = StateGraph(WorkflowState)
    registry = tool_registry or ToolRegistry(config.tools)
    node_names: list[str] = []
    for definition in config.agents:
        if definition.execution_mode == "deterministic_nist_mapper":
            node = DeterministicNistMapperNode(definition, registry)
        else:
            node = ConfiguredAgent(definition, config.models[definition.model_profile], model_client, registry)
        graph.add_node(definition.id, node.invoke)
        node_names.append(definition.id)
    graph.add_node("finalize", _finalize)

    graph.add_edge(START, node_names[0])
    for before, after in zip(node_names, node_names[1:], strict=False):
        graph.add_edge(before, after)
    graph.add_edge(node_names[-1], "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()


async def _finalize(state: WorkflowState) -> dict[str, object]:
    return {
        "status": "review_required" if state.get("requires_human_review") else "completed",
        "errors": state.get("errors", []),
    }
