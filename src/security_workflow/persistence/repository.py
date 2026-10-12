from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_workflow.contracts import EventType, WorkflowEvent
from security_workflow.observability.audit_logging import log_audit_event
from security_workflow.persistence.models import AgentRunRecord, EvidenceRecord, OutboxRecord, WorkflowRecord


class WorkflowRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_workflow(self, event: WorkflowEvent) -> WorkflowRecord:
        existing = self.session.get(WorkflowRecord, event.workflow_id)
        if existing:
            log_audit_event(
                "database.workflow_reused",
                component="database",
                table="workflows",
                workflow_id=event.workflow_id,
                correlation_id=event.correlation_id,
                finding_id=event.finding.finding_id,
            )
            return existing
        record = WorkflowRecord(
            id=event.workflow_id,
            correlation_id=event.correlation_id,
            finding_id=event.finding.finding_id,
            status="running",
            classification=event.classification,
            finding=event.finding.model_dump(mode="json"),
        )
        self.session.add(record)
        log_audit_event(
            "database.workflow_created",
            component="database",
            table="workflows",
            workflow_id=event.workflow_id,
            correlation_id=event.correlation_id,
            finding_id=event.finding.finding_id,
            classification=event.classification,
        )
        return record

    def save_agent_outputs(self, workflow_id: UUID, outputs: dict[str, dict], agent_profiles: dict[str, str]) -> None:
        for output_key, payload in outputs.items():
            agent_id = payload["agent_id"]
            existing = self.session.scalar(
                select(AgentRunRecord).where(
                    AgentRunRecord.workflow_id == workflow_id, AgentRunRecord.agent_id == agent_id
                )
            )
            if existing:
                existing.status = payload["status"]
                existing.output = payload
                continue
            self.session.add(
                AgentRunRecord(
                    workflow_id=workflow_id,
                    agent_id=agent_id,
                    status=payload["status"],
                    output=payload,
                    model_profile=agent_profiles.get(agent_id),
                )
            )
            log_audit_event(
                "database.agent_run_saved",
                component="database",
                table="agent_runs",
                workflow_id=workflow_id,
                agent_id=agent_id,
                model_profile=agent_profiles.get(agent_id),
                status=payload["status"],
            )

    def save_evidence(self, workflow_id: UUID, evidence: list[dict]) -> None:
        for item in evidence:
            external_id = item.get("id")
            if not external_id:
                continue
            existing = self.session.scalar(
                select(EvidenceRecord).where(
                    EvidenceRecord.workflow_id == workflow_id, EvidenceRecord.external_id == external_id
                )
            )
            if existing:
                continue
            self.session.add(
                EvidenceRecord(
                    workflow_id=workflow_id,
                    external_id=external_id,
                    source=item.get("source", "unknown"),
                    locator=item.get("locator", external_id),
                    classification=item.get("classification", "internal"),
                    content=item.get("content", {}),
                )
            )
        log_audit_event(
            "database.evidence_saved",
            component="database",
            table="evidence",
            workflow_id=workflow_id,
            count=len(evidence),
        )

    def finalize(self, workflow_id: UUID, status: str) -> None:
        workflow = self.session.get(WorkflowRecord, workflow_id)
        if not workflow:
            raise KeyError(f"Unknown workflow {workflow_id}")
        workflow.status = status
        log_audit_event(
            "database.workflow_finalized",
            component="database",
            table="workflows",
            workflow_id=workflow_id,
            status=status,
        )

    def get_workflow_detail(self, workflow_id: UUID) -> dict | None:
        workflow = self.session.get(WorkflowRecord, workflow_id)
        if not workflow:
            return None
        runs = list(
            self.session.scalars(
                select(AgentRunRecord)
                .where(AgentRunRecord.workflow_id == workflow_id)
                .order_by(AgentRunRecord.created_at)
            )
        )
        evidence = list(
            self.session.scalars(
                select(EvidenceRecord)
                .where(EvidenceRecord.workflow_id == workflow_id)
                .order_by(EvidenceRecord.created_at)
            )
        )
        return {
            "workflow_id": str(workflow.id),
            "correlation_id": str(workflow.correlation_id),
            "finding_id": workflow.finding_id,
            "status": workflow.status,
            "classification": workflow.classification,
            "finding": workflow.finding,
            "created_at": workflow.created_at,
            "updated_at": workflow.updated_at,
            "agent_runs": [
                {
                    "agent_id": run.agent_id,
                    "status": run.status,
                    "model_profile": run.model_profile,
                    "output": run.output,
                    "created_at": run.created_at,
                }
                for run in runs
            ],
            "evidence": [
                {
                    "external_id": item.external_id,
                    "source": item.source,
                    "locator": item.locator,
                    "classification": item.classification,
                    "content": item.content,
                    "created_at": item.created_at,
                }
                for item in evidence
            ],
        }

    def list_workflows(self, limit: int = 50) -> list[dict]:
        workflows = list(
            self.session.scalars(
                select(WorkflowRecord).order_by(WorkflowRecord.created_at.desc()).limit(limit)
            )
        )
        return [
            {
                "workflow_id": str(workflow.id),
                "finding_id": workflow.finding_id,
                "status": workflow.status,
                "classification": workflow.classification,
                "created_at": workflow.created_at,
                "updated_at": workflow.updated_at,
            }
            for workflow in workflows
        ]

    def add_outbox_event(self, topic: str, event: WorkflowEvent) -> None:
        self.session.add(
            OutboxRecord(
                workflow_id=event.workflow_id,
                event_id=event.event_id,
                topic=topic,
                payload=event.model_dump(mode="json"),
            )
        )
        log_audit_event(
            "database.outbox_queued",
            component="database",
            table="outbox_events",
            workflow_id=event.workflow_id,
            event_id=event.event_id,
            topic=topic,
        )

    def pending_outbox(self, limit: int = 100) -> list[OutboxRecord]:
        return list(
            self.session.scalars(
                select(OutboxRecord)
                .where(OutboxRecord.published_at.is_(None))
                .order_by(OutboxRecord.created_at)
                .limit(limit)
            )
        )

    def mark_outbox_published(self, record: OutboxRecord) -> None:
        record.published_at = datetime.now(UTC)
        record.attempts += 1
