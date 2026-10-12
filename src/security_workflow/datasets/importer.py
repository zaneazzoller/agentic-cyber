from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_workflow.persistence.database import create_session_factory, create_tables
from security_workflow.persistence.models import (
    DatasetImportRecord,
    FirewallRuleRecord,
    MitigationCorpusRecord,
    NetworkAssetRecord,
    NetworkEdgeRecord,
    SourceArtifactRecord,
    VulnerabilityAlertRecord,
)
from security_workflow.settings import Settings


# Development-only policy records. They represent normalized exports from fictional firewall managers;
# they are not inferred from topology and must never be confused with production policy evidence.
SYNTHETIC_FIREWALL_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "SYN-FW-DMZ-HTTPS-ROUTING-ALLOW-001",
        "device": "synthetic-fw-dmz-01",
        "priority": 90,
        "source_zone": "DMZ_Public",
        "destination_zone": "DMZ_Public",
        "source_cidr": "10.100.1.0/24",
        "destination_cidr": "10.100.1.0/24",
        "protocol": "tcp",
        "port_start": 443,
        "port_end": 443,
        "action": "allow",
    },
    {
        "rule_id": "SYN-FW-DMZ-APP-SSH-DENY-001",
        "device": "synthetic-fw-dmz-01",
        "priority": 10,
        "source_zone": "DMZ_Public",
        "destination_zone": "Internal_App_Tier",
        "source_cidr": "10.100.1.0/24",
        "destination_cidr": "10.100.2.0/24",
        "protocol": "tcp",
        "port_start": 22,
        "port_end": 22,
        "action": "deny",
    },
    {
        "rule_id": "SYN-FW-DMZ-APP-WEB-ALLOW-001",
        "device": "synthetic-fw-dmz-01",
        "priority": 100,
        "source_zone": "DMZ_Public",
        "destination_zone": "Internal_App_Tier",
        "source_cidr": "10.100.1.0/24",
        "destination_cidr": "10.100.2.0/24",
        "protocol": "tcp",
        "port_start": 8080,
        "port_end": 8080,
        "action": "allow",
    },
    {
        "rule_id": "SYN-FW-APP-MESH-ALLOW-001",
        "device": "synthetic-fw-internal-01",
        "priority": 100,
        "source_zone": "Internal_App_Tier",
        "destination_zone": "Internal_App_Tier",
        "source_cidr": "10.100.2.0/24",
        "destination_cidr": "10.100.2.0/24",
        "protocol": "tcp",
        "port_start": 5672,
        "port_end": 9092,
        "action": "allow",
    },
    {
        "rule_id": "SYN-FW-APP-DB-POSTGRES-ALLOW-001",
        "device": "synthetic-fw-db-01",
        "priority": 100,
        "source_zone": "Internal_App_Tier",
        "destination_zone": "Restricted_DB_Zone",
        "source_cidr": "10.100.2.0/24",
        "destination_cidr": "10.100.3.0/24",
        "protocol": "tcp",
        "port_start": 5432,
        "port_end": 5432,
        "action": "allow",
    },
    {
        "rule_id": "SYN-FW-APP-DB-MSSQL-ALLOW-001",
        "device": "synthetic-fw-db-01",
        "priority": 110,
        "source_zone": "Internal_App_Tier",
        "destination_zone": "Restricted_DB_Zone",
        "source_cidr": "10.100.2.0/24",
        "destination_cidr": "10.100.3.0/24",
        "protocol": "tcp",
        "port_start": 1433,
        "port_end": 1433,
        "action": "allow",
    },
    {
        "rule_id": "SYN-FW-APP-DB-MYSQL-ALLOW-001",
        "device": "synthetic-fw-db-01",
        "priority": 120,
        "source_zone": "Internal_App_Tier",
        "destination_zone": "Restricted_DB_Zone",
        "source_cidr": "10.100.2.0/24",
        "destination_cidr": "10.100.3.0/24",
        "protocol": "tcp",
        "port_start": 3306,
        "port_end": 3306,
        "action": "allow",
    },
    {
        "rule_id": "SYN-FW-DB-LEGACY-ORACLE-DENY-001",
        "device": "synthetic-fw-legacy-01",
        "priority": 10,
        "source_zone": "Restricted_DB_Zone",
        "destination_zone": "Legacy_OnPrem_Bridge",
        "source_cidr": "10.100.3.0/24",
        "destination_cidr": "192.168.50.0/24",
        "protocol": "tcp",
        "port_start": 1521,
        "port_end": 1521,
        "action": "deny",
    },
    {
        "rule_id": "SYN-FW-LEGACY-INTERNAL-ALLOW-001",
        "device": "synthetic-fw-legacy-01",
        "priority": 100,
        "source_zone": "Legacy_OnPrem_Bridge",
        "destination_zone": "Legacy_OnPrem_Bridge",
        "source_cidr": "192.168.50.0/24",
        "destination_cidr": "192.168.50.0/24",
        "protocol": "tcp",
        "port_start": 1,
        "port_end": 65535,
        "action": "allow",
    },
]


def _read_json(archive: zipfile.ZipFile, suffix: str) -> Any:
    entry = next((entry for entry in archive.infolist() if entry.filename.endswith(suffix)), None)
    if not entry:
        raise ValueError(f"Archive does not contain {suffix}")
    return json.loads(archive.read(entry).decode("utf-8"))


def _archive_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _upsert_asset(session: Session, import_id, source_key: str, value: dict[str, Any]) -> None:
    record = session.scalar(select(NetworkAssetRecord).where(NetworkAssetRecord.source_key == source_key))
    values = {
        "hostname": value["hostname"],
        "internal_ip": value.get("internal_ip"),
        "node_type": value["node_type"],
        "zone": value["zone"],
        "internet_facing": bool(value.get("internet_facing", False)),
        "business_criticality": value["business_criticality"],
        "source_import_id": import_id,
        "raw": value,
    }
    if record:
        for field, field_value in values.items():
            setattr(record, field, field_value)
    else:
        session.add(NetworkAssetRecord(source_key=source_key, **values))


def _upsert_edge(session: Session, import_id, value: dict[str, Any]) -> None:
    port = value.get("port")
    record = session.scalar(
        select(NetworkEdgeRecord).where(
            NetworkEdgeRecord.source_key == value["source"],
            NetworkEdgeRecord.target_key == value["target"],
            NetworkEdgeRecord.relationship == value["type"],
            NetworkEdgeRecord.port == port,
        )
    )
    values = {"source_import_id": import_id, "raw": value}
    if record:
        for field, field_value in values.items():
            setattr(record, field, field_value)
    else:
        session.add(
            NetworkEdgeRecord(
                source_key=value["source"],
                target_key=value["target"],
                relationship=value["type"],
                port=port,
                **values,
            )
        )


def _upsert_firewall_rule(session: Session, import_id, value: dict[str, Any]) -> None:
    record = session.scalar(select(FirewallRuleRecord).where(FirewallRuleRecord.rule_id == value["rule_id"]))
    values = {
        "device": value["device"],
        "priority": value["priority"],
        "source_zone": value.get("source_zone"),
        "destination_zone": value.get("destination_zone"),
        "source_cidr": value.get("source_cidr"),
        "destination_cidr": value.get("destination_cidr"),
        "protocol": value.get("protocol"),
        "port_start": value.get("port_start"),
        "port_end": value.get("port_end"),
        "action": value["action"],
        "source_import_id": import_id,
        "raw": value,
    }
    if record:
        for field, field_value in values.items():
            setattr(record, field, field_value)
    else:
        session.add(FirewallRuleRecord(rule_id=value["rule_id"], **values))


def _seed_synthetic_firewall_rules(session: Session, import_id) -> int:
    for rule in SYNTHETIC_FIREWALL_RULES:
        _upsert_firewall_rule(session, import_id, rule)
    return len(SYNTHETIC_FIREWALL_RULES)


def import_synthetic_archive(archive_path: Path, session: Session) -> dict[str, int]:
    """Import JSON datasets only. Python files and README content in the archive are never executed."""
    archive_hash = _archive_hash(archive_path)
    existing = session.scalar(
        select(DatasetImportRecord).where(DatasetImportRecord.archive_sha256 == archive_hash)
    )
    if existing:
        counts = {**existing.record_counts, "firewall_rules": _seed_synthetic_firewall_rules(session, existing.id)}
        existing.record_counts = counts
        session.commit()
        return counts

    with zipfile.ZipFile(archive_path) as archive:
        topology = _read_json(archive, "network_topology_dataset.json")
        alerts = _read_json(archive, "vulnerability_scan_alerts_with_mitigations.json")
        manifests = _read_json(archive, "manifest_files.json")
        mitigation_corpus = _read_json(archive, "faiss_mitigation_corpus.json")

    counts = {
        "network_assets": len(topology["nodes"]),
        "network_edges": len(topology["edges"]),
        "vulnerability_alerts": len(alerts),
        "source_artifacts": len(manifests),
        "mitigation_corpus": len(mitigation_corpus),
        "firewall_rules": len(SYNTHETIC_FIREWALL_RULES),
    }
    import_record = DatasetImportRecord(
        archive_name=archive_path.name,
        archive_sha256=archive_hash,
        record_counts=counts,
    )
    session.add(import_record)
    session.flush()

    for source_key, asset in topology["nodes"].items():
        _upsert_asset(session, import_record.id, source_key, asset)
    for edge in topology["edges"]:
        _upsert_edge(session, import_record.id, edge)
    _seed_synthetic_firewall_rules(session, import_record.id)
    for alert in alerts:
        record = session.get(VulnerabilityAlertRecord, alert["scan_id"])
        values = {
            "cve_id": alert["cve_id"],
            "target_hostname": alert["target_hostname"],
            "target_ip": alert.get("target_ip"),
            "severity_tier": alert["severity_tier"],
            "package_name": alert.get("package_name"),
            "installed_version": alert.get("installed_version"),
            "fixed_version": alert.get("fixed_version"),
            "manifest_path": alert.get("manifest_path"),
            "mitigation": alert.get("mitigation"),
            "source_import_id": import_record.id,
            "raw": alert,
        }
        if record:
            for field, field_value in values.items():
                setattr(record, field, field_value)
        else:
            session.add(VulnerabilityAlertRecord(scan_id=alert["scan_id"], **values))
    for artifact_key, content in manifests.items():
        record = session.scalar(select(SourceArtifactRecord).where(SourceArtifactRecord.artifact_key == artifact_key))
        if record:
            record.content = content
            record.source_import_id = import_record.id
        else:
            session.add(
                SourceArtifactRecord(
                    artifact_key=artifact_key, content=content, source_import_id=import_record.id
                )
            )
    for corpus_index, content in enumerate(mitigation_corpus):
        record = session.scalar(
            select(MitigationCorpusRecord).where(MitigationCorpusRecord.corpus_index == corpus_index)
        )
        if record:
            record.content = content
            record.source_import_id = import_record.id
        else:
            session.add(
                MitigationCorpusRecord(
                    corpus_index=corpus_index, content=content, source_import_id=import_record.id
                )
            )
    session.commit()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Import a synthetic security dataset ZIP into PostgreSQL.")
    parser.add_argument("--archive", type=Path, required=True, help="Path to the supplied dataset ZIP")
    args = parser.parse_args()
    if not args.archive.is_file():
        parser.error(f"Archive does not exist: {args.archive}")

    settings = Settings()
    create_tables(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        counts = import_synthetic_archive(args.archive, session)
    print(json.dumps({"status": "imported", "records": counts}, sort_keys=True))


if __name__ == "__main__":
    main()
