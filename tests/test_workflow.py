from pathlib import Path

import pytest

from security_workflow.config import load_workflow_config
from security_workflow.contracts import Finding
from security_workflow.orchestration.graph import build_workflow
from security_workflow.services.vllm import DeterministicModelClient


@pytest.mark.asyncio
async def test_dynamic_graph_executes_all_configured_agents() -> None:
    config = load_workflow_config(Path(__file__).parents[1] / "config")
    graph = build_workflow(config, DeterministicModelClient())
    state = await graph.ainvoke(
        {
            "workflow_id": "test-workflow",
            "correlation_id": "test-correlation",
            "classification": "internal",
            "finding": Finding(
                finding_id="F-1",
                cve_id="CVE-2025-0001",
                title="Example test finding",
                source_system="test",
            ),
            "evidence": [],
            "agent_outputs": {},
            "errors": [],
            "requires_human_review": False,
        }
    )

    assert set(state["agent_outputs"]) == {
        "nist_mapping",
        "cisa_assessment",
        "network_overview",
        "network_recommendation",
        "poam",
    }
    assert state["status"] == "review_required"
