from __future__ import annotations

from uuid import UUID, uuid4
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import text

from security_workflow.config import load_workflow_config
from security_workflow.contracts import EventType, Finding, WorkflowEvent
from security_workflow.messaging.kafka import KafkaEventProducer
from security_workflow.orchestration.graph import build_workflow
from security_workflow.observability.audit_logging import configure_audit_logging, log_audit_event
from security_workflow.persistence.database import create_session_factory, create_tables
from security_workflow.persistence.repository import WorkflowRepository
from security_workflow.services.vllm import ProviderRouter
from security_workflow.settings import Settings
from security_workflow.tools.registry import ToolRegistry
from security_workflow.tools.official_intelligence import build_official_intelligence_adapters
from security_workflow.tools.synthetic_adapters import build_synthetic_adapters
from security_workflow.workflow_service import WorkflowService

app = FastAPI(title="Security Agentic Workflow", version="0.1.0")
config = load_workflow_config()
settings = Settings()
session_factory = create_session_factory(settings.database_url)
tool_registry = ToolRegistry(
    config.tools,
    {**build_synthetic_adapters(session_factory), **build_official_intelligence_adapters(session_factory)},
)
graph = build_workflow(config, ProviderRouter(), tool_registry)
dashboard_path = Path(__file__).parent / "ui" / "index.html"


@app.on_event("startup")
async def initialize_development_database() -> None:
    """Create local tables for development only; production must use reviewed Alembic migrations."""
    configure_audit_logging(settings.log_level)
    log_audit_event("api.started", component="api", status="starting")
    if settings.app_env.lower() != "production":
        create_tables(settings.database_url)
        log_audit_event("database.tables.ready", component="database", status="ready")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    try:
        with session_factory() as session:
            session.execute(text("SELECT 1"))
    except Exception as exc:
        log_audit_event("database.health_failed", component="database", error_type=type(exc).__name__)
        raise HTTPException(status_code=503, detail="PostgreSQL is unavailable") from exc
    return {"status": "ok", "database": "ok"}


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(dashboard_path, media_type="text/html")


@app.post("/validate-workflow")
async def validate_workflow(finding: Finding) -> dict:
    """Runs and durably records a local workflow without Kafka or Splunk side effects."""
    workflow_id = uuid4()
    correlation_id = uuid4()
    log_audit_event(
        "workflow.requested",
        component="api",
        workflow_id=workflow_id,
        correlation_id=correlation_id,
        finding_id=finding.finding_id,
        classification="internal",
    )
    try:
        intake_event = WorkflowEvent(
            event_type=EventType.FINDING_RECEIVED,
            correlation_id=correlation_id,
            workflow_id=workflow_id,
            finding=finding,
            payload={"evidence": []},
        )
        with session_factory() as session:
            repository = WorkflowRepository(session)
            service = WorkflowService(
                graph=graph,
                repository=repository,
                topics=config.topics,
                agent_profiles={agent.id: agent.model_profile for agent in config.agents},
            )
            result = await service.process(intake_event)
        log_audit_event(
            "workflow.responded",
            component="api",
            workflow_id=workflow_id,
            correlation_id=correlation_id,
            finding_id=finding.finding_id,
            status=result["status"],
        )
        return {"workflow_id": str(workflow_id), "correlation_id": str(correlation_id), "result": result}
    except Exception as exc:
        log_audit_event(
            "workflow.request_failed",
            component="api",
            workflow_id=workflow_id,
            correlation_id=correlation_id,
            finding_id=finding.finding_id,
            error_type=type(exc).__name__,
        )
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/submit-finding")
async def submit_finding(finding: Finding) -> dict[str, str]:
    """Publish a finding to Kafka; the intake worker performs the durable workflow execution."""
    workflow_id = uuid4()
    correlation_id = uuid4()
    event = WorkflowEvent(
        event_type=EventType.FINDING_RECEIVED,
        correlation_id=correlation_id,
        workflow_id=workflow_id,
        finding=finding,
        payload={"evidence": []},
    )
    try:
        KafkaEventProducer(settings.kafka_bootstrap_servers).publish(config.topics["finding_received"], event)
    except Exception as exc:
        log_audit_event(
            "workflow.submit_failed",
            component="api",
            workflow_id=workflow_id,
            correlation_id=correlation_id,
            finding_id=finding.finding_id,
            error_type=type(exc).__name__,
        )
        raise HTTPException(status_code=502, detail="Kafka submission failed") from exc
    log_audit_event(
        "workflow.submitted",
        component="api",
        workflow_id=workflow_id,
        correlation_id=correlation_id,
        finding_id=finding.finding_id,
        topic=config.topics["finding_received"],
        status="queued",
    )
    return {
        "workflow_id": str(workflow_id),
        "correlation_id": str(correlation_id),
        "status": "queued",
    }


@app.get("/workflows/{workflow_id}")
async def get_workflow(workflow_id: UUID) -> dict:
    with session_factory() as session:
        detail = WorkflowRepository(session).get_workflow_detail(workflow_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return detail


@app.get("/workflows")
async def list_workflows(limit: int = Query(default=50, ge=1, le=200)) -> list[dict]:
    with session_factory() as session:
        return WorkflowRepository(session).list_workflows(limit)
