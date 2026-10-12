from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class WorkflowRecord(Base):
    __tablename__ = "workflows"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    correlation_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), index=True)
    finding_id: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(64), index=True)
    classification: Mapped[str] = mapped_column(String(64), default="internal")
    finding: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AgentRunRecord(Base):
    __tablename__ = "agent_runs"
    __table_args__ = (UniqueConstraint("workflow_id", "agent_id", name="uq_agent_run_per_workflow"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    workflow_id: Mapped[UUID] = mapped_column(ForeignKey("workflows.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(64))
    output: Mapped[dict] = mapped_column(JSON)
    model_profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    config_version: Mapped[str] = mapped_column(String(64), default="v1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidenceRecord(Base):
    __tablename__ = "evidence"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    workflow_id: Mapped[UUID] = mapped_column(ForeignKey("workflows.id"), index=True)
    external_id: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(64))
    locator: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(64), default="internal")
    content: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class OutboxRecord(Base):
    __tablename__ = "outbox_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    workflow_id: Mapped[UUID] = mapped_column(ForeignKey("workflows.id"), index=True)
    event_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), unique=True)
    topic: Mapped[str] = mapped_column(String(255))
    payload: Mapped[dict] = mapped_column(JSON)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DatasetImportRecord(Base):
    __tablename__ = "dataset_imports"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    archive_name: Mapped[str] = mapped_column(String(512))
    archive_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    source_label: Mapped[str] = mapped_column(String(128), default="synthetic")
    record_counts: Mapped[dict] = mapped_column(JSON)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SourceSnapshotRecord(Base):
    """Provenance for an approved external-data snapshot loaded in a connected zone."""

    __tablename__ = "source_snapshots"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    source_name: Mapped[str] = mapped_column(String(128), index=True)
    source_url: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64), index=True)
    source_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    record_count: Mapped[int] = mapped_column(Integer)
    source_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class NistControlRecord(Base):
    """Normalized control text from an official NIST OSCAL snapshot."""

    __tablename__ = "nist_controls"
    __table_args__ = (UniqueConstraint("control_id", "catalog_version", name="uq_nist_control_version"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    control_id: Mapped[str] = mapped_column(String(64), index=True)
    catalog_version: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(Text)
    statement: Mapped[str | None] = mapped_column(Text, nullable=True)
    family: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_snapshot_id: Mapped[UUID] = mapped_column(ForeignKey("source_snapshots.id"), index=True)
    raw: Mapped[dict] = mapped_column(JSON)


class CveIntelligenceRecord(Base):
    """A normalized NVD CVE API record, retained for offline workflow lookup."""

    __tablename__ = "cve_intelligence"

    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_snapshot_id: Mapped[UUID] = mapped_column(ForeignKey("source_snapshots.id"), index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_base_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(512), nullable=True)
    raw: Mapped[dict] = mapped_column(JSON)


class CisaKevRecord(Base):
    """An entry from CISA's KEV JSON catalog, retained for offline workflow lookup."""

    __tablename__ = "cisa_kev"

    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    vendor_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vulnerability_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_added: Mapped[str | None] = mapped_column(String(32), nullable=True)
    due_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    known_ransomware_campaign_use: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_snapshot_id: Mapped[UUID] = mapped_column(ForeignKey("source_snapshots.id"), index=True)
    raw: Mapped[dict] = mapped_column(JSON)


class NetworkAssetRecord(Base):
    __tablename__ = "network_assets"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    source_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    internal_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    node_type: Mapped[str] = mapped_column(String(128))
    zone: Mapped[str] = mapped_column(String(128), index=True)
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    business_criticality: Mapped[str] = mapped_column(String(32), index=True)
    source_import_id: Mapped[UUID] = mapped_column(ForeignKey("dataset_imports.id"), index=True)
    raw: Mapped[dict] = mapped_column(JSON)


class NetworkEdgeRecord(Base):
    __tablename__ = "network_topology_edges"
    __table_args__ = (
        UniqueConstraint("source_key", "target_key", "relationship", "port", name="uq_topology_edge"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    source_key: Mapped[str] = mapped_column(String(255), index=True)
    target_key: Mapped[str] = mapped_column(String(255), index=True)
    relationship: Mapped[str] = mapped_column(String(128))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_import_id: Mapped[UUID] = mapped_column(ForeignKey("dataset_imports.id"), index=True)
    raw: Mapped[dict] = mapped_column(JSON)


class FirewallRuleRecord(Base):
    """Normalized, read-only firewall policy evidence used by passive reachability analysis."""

    __tablename__ = "firewall_rules"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    device: Mapped[str] = mapped_column(String(255), index=True)
    priority: Mapped[int] = mapped_column(Integer)
    source_zone: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    destination_zone: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    source_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    port_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(16), index=True)
    source_import_id: Mapped[UUID] = mapped_column(ForeignKey("dataset_imports.id"), index=True)
    raw: Mapped[dict] = mapped_column(JSON)


class VulnerabilityAlertRecord(Base):
    __tablename__ = "vulnerability_alerts"

    scan_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(64), index=True)
    target_hostname: Mapped[str] = mapped_column(String(255), index=True)
    target_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    severity_tier: Mapped[str] = mapped_column(String(32), index=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    manifest_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitigation: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_import_id: Mapped[UUID] = mapped_column(ForeignKey("dataset_imports.id"), index=True)
    raw: Mapped[dict] = mapped_column(JSON)


class SourceArtifactRecord(Base):
    __tablename__ = "source_artifacts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    artifact_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    content: Mapped[str] = mapped_column(Text)
    source_import_id: Mapped[UUID] = mapped_column(ForeignKey("dataset_imports.id"), index=True)


class MitigationCorpusRecord(Base):
    __tablename__ = "mitigation_corpus"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    corpus_index: Mapped[int] = mapped_column(unique=True, index=True)
    content: Mapped[str] = mapped_column(Text)
    source_import_id: Mapped[UUID] = mapped_column(ForeignKey("dataset_imports.id"), index=True)
