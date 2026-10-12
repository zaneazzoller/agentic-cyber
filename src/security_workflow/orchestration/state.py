from typing import Any, TypedDict

from security_workflow.contracts import Finding


class WorkflowState(TypedDict, total=False):
    workflow_id: str
    correlation_id: str
    classification: str
    finding: Finding
    evidence: list[dict[str, Any]]
    agent_outputs: dict[str, dict[str, Any]]
    errors: list[str]
    requires_human_review: bool
    status: str
