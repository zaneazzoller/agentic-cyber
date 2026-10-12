from __future__ import annotations

from security_workflow.contracts import WorkflowEvent
from security_workflow.messaging.kafka import KafkaEventProducer
from security_workflow.observability.audit_logging import log_audit_event
from security_workflow.persistence.repository import WorkflowRepository


def publish_pending_outbox(repository: WorkflowRepository, producer: KafkaEventProducer, limit: int = 100) -> int:
    """Publish committed records and mark them delivered only after Kafka acknowledges the message."""
    count = 0
    for record in repository.pending_outbox(limit):
        event = WorkflowEvent.model_validate(record.payload)
        log_audit_event(
            "outbox.publish_started",
            component="outbox",
            workflow_id=event.workflow_id,
            event_id=event.event_id,
            topic=record.topic,
        )
        producer.publish(record.topic, event)
        repository.mark_outbox_published(record)
        log_audit_event(
            "outbox.published",
            component="outbox",
            workflow_id=event.workflow_id,
            event_id=event.event_id,
            topic=record.topic,
            status="published",
        )
        count += 1
    repository.session.commit()
    return count
