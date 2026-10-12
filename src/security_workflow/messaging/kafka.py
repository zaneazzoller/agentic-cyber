from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from confluent_kafka import Consumer, Producer

from security_workflow.contracts import WorkflowEvent
from security_workflow.observability.audit_logging import log_audit_event


class KafkaEventProducer:
    def __init__(self, bootstrap_servers: str) -> None:
        self._producer = Producer({"bootstrap.servers": bootstrap_servers, "enable.idempotence": True})

    def publish(self, topic: str, event: WorkflowEvent) -> None:
        log_audit_event(
            "kafka.publish_started",
            component="kafka",
            topic=topic,
            workflow_id=event.workflow_id,
            correlation_id=event.correlation_id,
            event_id=event.event_id,
        )
        payload = event.model_dump_json().encode("utf-8")
        self._producer.produce(topic, value=payload, key=str(event.workflow_id).encode("utf-8"))
        pending = self._producer.flush(10)
        if pending:
            raise TimeoutError(f"Kafka did not acknowledge {pending} event(s) within 10 seconds")
        log_audit_event(
            "kafka.published",
            component="kafka",
            topic=topic,
            workflow_id=event.workflow_id,
            correlation_id=event.correlation_id,
            event_id=event.event_id,
            status="published",
        )


class KafkaEventConsumer:
    def __init__(self, bootstrap_servers: str, group_id: str, topic: str) -> None:
        self._topic = topic
        self._consumer = Consumer(
            {
                "bootstrap.servers": bootstrap_servers,
                "group.id": group_id,
                "enable.auto.commit": False,
                "auto.offset.reset": "earliest",
            }
        )
        self._consumer.subscribe([topic])

    def poll_once(self, handler: Callable[[WorkflowEvent], Any], timeout: float = 1.0) -> bool:
        message = self._consumer.poll(timeout)
        if message is None:
            return False
        if message.error():
            raise RuntimeError(str(message.error()))
        event = WorkflowEvent.model_validate(json.loads(message.value()))
        log_audit_event(
            "kafka.received",
            component="kafka",
            topic=self._topic,
            workflow_id=event.workflow_id,
            correlation_id=event.correlation_id,
            event_id=event.event_id,
        )
        handler(event)
        self._consumer.commit(message=message, asynchronous=False)
        log_audit_event(
            "kafka.committed",
            component="kafka",
            topic=self._topic,
            workflow_id=event.workflow_id,
            correlation_id=event.correlation_id,
            event_id=event.event_id,
            status="committed",
        )
        return True

    def close(self) -> None:
        self._consumer.close()
