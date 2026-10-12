from __future__ import annotations

from security_workflow.contracts import EventType, WorkflowEvent
from security_workflow.observability.audit_logging import log_audit_event
from security_workflow.persistence.repository import WorkflowRepository


class WorkflowService:
    """Coordinates graph execution with durable database state; delivery is handled by an outbox worker."""

    def __init__(self, graph, repository: WorkflowRepository, topics: dict[str, str], agent_profiles: dict[str, str]) -> None:
        self.graph = graph
        self.repository = repository
        self.topics = topics
        self.agent_profiles = agent_profiles

    async def process(self, intake_event: WorkflowEvent) -> dict:
        if intake_event.event_type != EventType.FINDING_RECEIVED:
            raise ValueError("WorkflowService accepts only finding.received events")
        audit = {
            "component": "workflow",
            "workflow_id": intake_event.workflow_id,
            "correlation_id": intake_event.correlation_id,
            "finding_id": intake_event.finding.finding_id,
            "classification": intake_event.classification,
        }
        log_audit_event("workflow.started", **audit)
        self.repository.create_workflow(intake_event)
        self.repository.session.commit()
        log_audit_event("workflow.running_persisted", **audit, status="running")
        try:
            final_state = await self.graph.ainvoke(
                {
                    "workflow_id": str(intake_event.workflow_id),
                    "correlation_id": str(intake_event.correlation_id),
                    "classification": intake_event.classification,
                    "finding": intake_event.finding,
                    "evidence": intake_event.payload.get("evidence", []),
                    "agent_outputs": {},
                    "errors": [],
                    "requires_human_review": False,
                }
            )
        except Exception as exc:
            self.repository.finalize(intake_event.workflow_id, "failed")
            self.repository.session.commit()
            log_audit_event("workflow.failed", **audit, error_type=type(exc).__name__)
            raise
        self.repository.save_agent_outputs(
            intake_event.workflow_id, final_state["agent_outputs"], self.agent_profiles
        )
        self.repository.save_evidence(intake_event.workflow_id, final_state.get("evidence", []))
        status = final_state["status"]
        self.repository.finalize(intake_event.workflow_id, status)
        completion_type = EventType.REVIEW_REQUIRED if status == "review_required" else EventType.POAM_GENERATED
        output_event = WorkflowEvent(
            event_type=completion_type,
            correlation_id=intake_event.correlation_id,
            workflow_id=intake_event.workflow_id,
            finding=intake_event.finding,
            payload={"agent_outputs": final_state["agent_outputs"], "status": status},
            classification=intake_event.classification,
        )
        destination = "review_required" if status == "review_required" else "poam_generated"
        self.repository.add_outbox_event(self.topics[destination], output_event)
        self.repository.session.commit()
        log_audit_event(
            "workflow.completed",
            **audit,
            status=status,
            count=len(final_state["agent_outputs"]),
            topic=self.topics[destination],
        )
        return final_state
