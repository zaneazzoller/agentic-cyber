import pytest

from security_workflow.config import AgentToolBinding, ToolDefinition
from security_workflow.tools.registry import ToolRegistry


@pytest.mark.asyncio
async def test_registry_executes_only_a_bound_tool() -> None:
    binding = AgentToolBinding(
        name="test_source", purpose="Retrieve a controlled test result.", input_schema="TestQuery"
    )
    definition = ToolDefinition(adapter="test_adapter", timeout_seconds=5, result_limit=1)

    async def adapter(received_binding, received_definition, inputs):
        assert received_binding == binding
        assert received_definition == definition
        assert inputs == {"finding": "test"}
        return {"data": {"value": "ok"}, "evidence": [{"id": "test:1"}]}

    registry = ToolRegistry({"test_source": definition}, {"test_adapter": adapter})
    result = await registry.invoke(binding, {"finding": "test"})

    assert result["status"] == "success"
    assert result["data"] == {"value": "ok"}
    assert result["tool"]["name"] == "test_source"


@pytest.mark.asyncio
async def test_unconfigured_tool_never_claims_to_have_evidence() -> None:
    binding = AgentToolBinding(
        name="test_source", purpose="Retrieve a controlled test result.", input_schema="TestQuery"
    )
    registry = ToolRegistry({"test_source": ToolDefinition(adapter="not_implemented")})

    result = await registry.invoke(binding, {})

    assert result["status"] == "not_configured"
    assert result["evidence"] == []
