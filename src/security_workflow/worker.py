"""Runnable Kafka intake and PostgreSQL outbox workers for local and container deployments."""

from __future__ import annotations

import argparse
import asyncio
import time
from collections.abc import Callable

from security_workflow.config import WorkflowConfig, load_workflow_config
from security_workflow.contracts import WorkflowEvent
from security_workflow.messaging.kafka import KafkaEventConsumer, KafkaEventProducer
from security_workflow.observability.audit_logging import configure_audit_logging, log_audit_event
from security_workflow.orchestration.graph import build_workflow
from security_workflow.outbox_worker import publish_pending_outbox
from security_workflow.persistence.database import create_session_factory, create_tables
from security_workflow.persistence.repository import WorkflowRepository
from security_workflow.services.vllm import ProviderRouter
from security_workflow.settings import Settings
from security_workflow.tools.registry import ToolRegistry
from security_workflow.tools.official_intelligence import build_official_intelligence_adapters
from security_workflow.tools.synthetic_adapters import build_synthetic_adapters
from security_workflow.workflow_service import WorkflowService


def _build_workflow_service_factory(
    config: WorkflowConfig, session_factory
) -> Callable[[WorkflowEvent], None]:
    tool_registry = ToolRegistry(
        config.tools,
        {**build_synthetic_adapters(session_factory), **build_official_intelligence_adapters(session_factory)},
    )
    graph = build_workflow(config, ProviderRouter(), tool_registry)
    agent_profiles = {agent.id: agent.model_profile for agent in config.agents}

    def process(event: WorkflowEvent) -> None:
        with session_factory() as session:
            service = WorkflowService(
                graph=graph,
                repository=WorkflowRepository(session),
                topics=config.topics,
                agent_profiles=agent_profiles,
            )
            asyncio.run(service.process(event))

    return process


def run_intake_worker(*, once: bool = False, poll_timeout: float = 1.0) -> None:
    """Consume finding.received events, persist execution state, and commit only after processing."""
    settings = Settings()
    configure_audit_logging(settings.log_level)
    create_tables(settings.database_url)
    config = load_workflow_config()
    session_factory = create_session_factory(settings.database_url)
    processor = _build_workflow_service_factory(config, session_factory)
    consumer = KafkaEventConsumer(
        settings.kafka_bootstrap_servers, settings.kafka_group_id, config.topics["finding_received"]
    )
    log_audit_event("intake_worker.started", component="worker", topic=config.topics["finding_received"])
    try:
        while True:
            processed = consumer.poll_once(processor, timeout=poll_timeout)
            if once:
                log_audit_event(
                    "intake_worker.completed", component="worker", status="processed" if processed else "empty"
                )
                return
    finally:
        consumer.close()


def run_outbox_worker(*, once: bool = False, poll_seconds: float = 1.0) -> None:
    """Publish committed PostgreSQL outbox records to Kafka and mark them delivered on acknowledgement."""
    settings = Settings()
    configure_audit_logging(settings.log_level)
    create_tables(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    producer = KafkaEventProducer(settings.kafka_bootstrap_servers)
    log_audit_event("outbox_worker.started", component="worker")
    while True:
        with session_factory() as session:
            count = publish_pending_outbox(WorkflowRepository(session), producer)
        log_audit_event("outbox_worker.cycle", component="worker", count=count, status="completed")
        if once:
            return
        time.sleep(poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run security-workflow Kafka workers.")
    commands = parser.add_subparsers(dest="command", required=True)
    intake = commands.add_parser("intake", help="Consume finding events and run the workflow.")
    intake.add_argument("--once", action="store_true", help="Poll once and exit.")
    intake.add_argument("--poll-timeout", type=float, default=1.0)
    outbox = commands.add_parser("outbox", help="Publish pending PostgreSQL outbox events.")
    outbox.add_argument("--once", action="store_true", help="Publish one batch and exit.")
    outbox.add_argument("--poll-seconds", type=float, default=1.0)
    args = parser.parse_args()
    if args.command == "intake":
        run_intake_worker(once=args.once, poll_timeout=args.poll_timeout)
    else:
        run_outbox_worker(once=args.once, poll_seconds=args.poll_seconds)


if __name__ == "__main__":
    main()
