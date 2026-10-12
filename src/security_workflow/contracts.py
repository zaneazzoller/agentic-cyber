from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator


class EventType(StrEnum):
    FINDING_RECEIVED = "finding.received"
    AGENT_STARTED = "agent.started"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"
    REVIEW_REQUIRED = "review.required"
    POAM_GENERATED = "poam.generated"
    SPLUNK_ENRICHED = "splunk.enriched"


class EvidenceReference(BaseModel):
    id: str
    source: str
    locator: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    classification: str = "internal"
    summary: str | None = None


class Finding(BaseModel):
    """Normalized intake finding with common ACAS/Nessus fields preserved for agent evidence."""

    model_config = ConfigDict(populate_by_name=True)

    finding_id: str
    cve_id: str | None = None
    title: str
    severity: str | None = None
    affected_assets: list[str] = Field(default_factory=list)
    source_system: str
    source_event_id: str | None = None
    discovered_at: datetime | None = None
    # ACAS/Nessus plugin identity and analyst-facing vulnerability context.
    plugin_id: str | None = None
    plugin_name: str | None = None
    plugin_family: str | None = None
    synopsis: str | None = None
    vulnerability_description: str | None = Field(
        default=None,
        validation_alias=AliasChoices("vulnerability_description", "vuln_description", "description"),
    )
    solution: str | None = None
    plugin_output: str | None = None
    see_also: list[str] = Field(default_factory=list)
    # Scanner risk and exploitability details.
    risk_factor: str | None = None
    cvss_base_score: float | None = Field(default=None, ge=0, le=10)
    cvss_temporal_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    exploit_available: bool | None = None
    exploited_by_malware: bool | None = None
    stig_severity: str | None = None
    # Host, service, package, and scan provenance fields commonly supplied by ACAS exports.
    host_fqdn: str | None = None
    host_ip: str | None = None
    operating_system: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    service: str | None = None
    cpe: list[str] = Field(default_factory=list)
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    scan_id: str | None = None
    scan_name: str | None = None
    scan_started_at: datetime | None = None
    scan_completed_at: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def use_acas_host_identity_when_an_asset_list_is_not_provided(self) -> "Finding":
        """Allow a normal scanner export to drive network enrichment without a duplicate asset field."""
        if not self.affected_assets:
            self.affected_assets = [value for value in (self.host_fqdn, self.host_ip) if value]
        return self


class WorkflowEvent(BaseModel):
    """Versioned envelope shared by all Kafka messages."""

    model_config = ConfigDict(use_enum_values=True)

    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    schema_version: int = 1
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    correlation_id: UUID
    workflow_id: UUID
    finding: Finding
    payload: dict[str, Any] = Field(default_factory=dict)
    classification: str = "internal"


class AgentResult(BaseModel):
    agent_id: str
    status: str
    result: dict[str, Any]
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    requires_human_review: bool = False
    rationale: str | None = None
