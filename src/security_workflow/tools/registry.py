from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from security_workflow.config import AgentToolBinding, ToolDefinition
from security_workflow.observability.audit_logging import log_audit_event

ToolAdapter = Callable[[AgentToolBinding, ToolDefinition, dict[str, Any]], Awaitable[dict[str, Any]]]


class ToolRegistry:
    """Resolves tools granted in an agent's own configuration.

    The registry contains adapter metadata and safe execution limits only. It never assigns a tool to an
    agent; an agent must explicitly declare every capability it needs in its configuration file.
    """

    def __init__(
        self, definitions: dict[str, ToolDefinition], adapters: dict[str, ToolAdapter] | None = None
    ) -> None:
        self._definitions = definitions
        self._adapters = adapters or {}

    def validate_bindings(self, bindings: list[AgentToolBinding]) -> None:
        unknown = [binding.name for binding in bindings if binding.name not in self._definitions]
        if unknown:
            raise ValueError(f"Unknown tool bindings: {', '.join(unknown)}")

    async def invoke(
        self,
        binding: AgentToolBinding,
        inputs: dict[str, Any],
        audit_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute only a tool already granted to the current agent.

        Unconfigured adapters report an explicit empty result. This keeps local graph validation safe while
        preventing the model from inventing a successful source query.
        """
        definition = self._definitions[binding.name]
        adapter = self._adapters.get(definition.adapter)
        audit = {
            **(audit_context or {}),
            "component": "tool",
            "tool": binding.name,
            "adapter": definition.adapter,
            "classification": definition.classification,
        }
        log_audit_event("tool.started", **audit)
        if not adapter:
            log_audit_event("tool.not_configured", **audit, status="not_configured")
            return {
                "status": "not_configured",
                "data": {},
                "evidence": [],
                "warnings": [f"Adapter '{definition.adapter}' is not configured for tool '{binding.name}'."],
                "tool": {
                    "name": binding.name,
                    "purpose": binding.purpose,
                    "input_schema": binding.input_schema,
                    "classification": definition.classification,
                },
            }
        try:
            result = await adapter(binding, definition, inputs)
        except Exception as exc:
            log_audit_event("tool.failed", **audit, error_type=type(exc).__name__)
            raise
        log_audit_event(
            "tool.completed",
            **audit,
            status=result.get("status", "success"),
            count=len(result.get("evidence", [])),
        )
        return {
            "status": result.get("status", "success"),
            "data": result.get("data", {}),
            "evidence": result.get("evidence", []),
            "warnings": result.get("warnings", []),
            "tool": {
                "name": binding.name,
                "purpose": binding.purpose,
                "input_schema": binding.input_schema,
                "classification": definition.classification,
            },
        }
