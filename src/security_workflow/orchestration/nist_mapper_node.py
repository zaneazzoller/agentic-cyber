"""A deterministic LangGraph node for NIST candidate mapping; it makes no LLM call."""

from __future__ import annotations

from typing import Any

from security_workflow.config import AgentDefinition
from security_workflow.contracts import AgentResult
from security_workflow.observability.audit_logging import log_audit_event
from security_workflow.orchestration.state import WorkflowState
from security_workflow.tools.registry import ToolRegistry


class DeterministicNistMapperNode:
    def __init__(self, definition: AgentDefinition, tool_registry: ToolRegistry) -> None:
        self.definition = definition
        self.tool_registry = tool_registry
        self.tool_registry.validate_bindings(definition.tools)
        if len(definition.tools) != 1 or definition.tools[0].name != "nist_candidate_control_mapping":
            raise ValueError("The deterministic NIST mapper requires exactly the nist_candidate_control_mapping tool")

    async def invoke(self, state: WorkflowState) -> dict[str, Any]:
        audit = {
            "component": "nist_mapper",
            "workflow_id": state.get("workflow_id"),
            "correlation_id": state.get("correlation_id"),
            "finding_id": getattr(state.get("finding"), "finding_id", None),
            "classification": state.get("classification", "internal"),
        }
        log_audit_event("nist_mapper.started", **audit)
        inputs = {key: state.get(key) for key in self.definition.input_keys}
        tool_result = await self.tool_registry.invoke(self.definition.tools[0], inputs, audit)
        response = tool_result.get("data", {})
        if not response:
            response = {
                "summary": "NIST mapping did not return an assessment payload.",
                "confidence": 0.0,
                "requires_human_review": True,
                "rationale": "The deterministic mapping tool was not able to access its required local data.",
                "findings": [],
                "recommendations": tool_result.get("warnings", []),
                "assumptions": [],
            }
        evidence = list(state.get("evidence", []))
        seen = {item.get("id") for item in evidence}
        for item in tool_result.get("evidence", []):
            if item.get("id") not in seen:
                evidence.append(item)
                seen.add(item.get("id"))
        result = AgentResult(
            agent_id=self.definition.id,
            status="completed",
            result=response,
            evidence_ids=[item["id"] for item in tool_result.get("evidence", []) if item.get("id")],
            confidence=response.get("confidence"),
            requires_human_review=True,
            rationale=response.get("rationale"),
        )
        outputs = dict(state.get("agent_outputs", {}))
        outputs[self.definition.output_key] = result.model_dump(mode="json")
        log_audit_event("nist_mapper.completed", **audit, status="review_required", count=len(result.evidence_ids))
        return {"agent_outputs": outputs, "evidence": evidence, "requires_human_review": True}
