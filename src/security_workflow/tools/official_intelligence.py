"""Read-only agent tools backed by approved official-source PostgreSQL snapshots."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, sessionmaker

from security_workflow.config import AgentToolBinding, ToolDefinition
from security_workflow.mappers.nist_control_mapper import map_finding_to_controls
from security_workflow.persistence.models import (
    CisaKevRecord,
    CveIntelligenceRecord,
    NistControlRecord,
    SourceSnapshotRecord,
)


def _finding(inputs: dict[str, Any]) -> Any:
    return inputs.get("finding", {})


def _value(finding: Any, key: str, default: Any = None) -> Any:
    return finding.get(key, default) if isinstance(finding, dict) else getattr(finding, key, default)


def _evidence(identifier: str, source: str, locator: str, summary: str, content: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": identifier,
        "source": source,
        "locator": locator,
        "classification": "internal",
        "summary": summary,
        "content": content,
    }


def _snapshot_metadata(session: Session, snapshot_id) -> dict[str, Any]:
    snapshot = session.get(SourceSnapshotRecord, snapshot_id)
    if not snapshot:
        return {"snapshot_status": "missing"}
    return {
        "snapshot_id": str(snapshot.id),
        "source_url": snapshot.source_url,
        "source_version": snapshot.source_version,
        "retrieved_at": snapshot.retrieved_at.isoformat() if snapshot.retrieved_at else None,
        "content_sha256": snapshot.content_sha256,
    }


async def nvd_cve_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    cve_id = _value(_finding(inputs), "cve_id")
    with session_factory() as session:
        record = session.get(CveIntelligenceRecord, cve_id) if cve_id else None
        if not record:
            return {
                "status": "source_data_missing",
                "data": {"cve_id": cve_id, "record_found": False},
                "evidence": [],
                "warnings": [
                    "No approved NVD snapshot is loaded for this CVE. Run the connected-zone official source refresh before assessment."
                ],
            }
        data = {
            "cve_id": record.cve_id,
            "published_at": record.published_at.isoformat() if record.published_at else None,
            "last_modified_at": record.last_modified_at.isoformat() if record.last_modified_at else None,
            "description": record.description,
            "cvss_base_score": record.cvss_base_score,
            "cvss_vector": record.cvss_vector,
            "snapshot": _snapshot_metadata(session, record.source_snapshot_id),
        }
    return {
        "data": {"record": data},
        "evidence": [
            _evidence(
                f"nvd:{cve_id}",
                "nvd_snapshot",
                f"cve_intelligence/{cve_id}",
                f"Official NVD snapshot for {cve_id}",
                data,
            )
        ],
        "warnings": ["This is an approved local NVD snapshot; verify freshness using its retrieved_at value."],
    }


async def nist_control_catalog_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    # These are mapping candidates, not a claim that the organization has violated a control.
    candidate_ids = ("RA-5", "SI-2", "CM-6", "SC-7")
    with session_factory() as session:
        records = list(
            session.scalars(
                select(NistControlRecord)
                .where(NistControlRecord.control_id.in_(candidate_ids))
                .order_by(NistControlRecord.catalog_version.desc())
                .limit(definition.result_limit)
            )
        )
        controls = [
            {
                "control_id": record.control_id,
                "catalog_version": record.catalog_version,
                "family": record.family,
                "title": record.title,
                "statement": record.statement,
                "snapshot": _snapshot_metadata(session, record.source_snapshot_id),
            }
            for record in records
        ]
    return {
        "status": "success" if controls else "source_data_missing",
        "data": {"controls": controls},
        "evidence": [
            _evidence(
                f"nist:{control['catalog_version']}:{control['control_id']}",
                "nist_oscal_snapshot",
                f"nist_controls/{control['catalog_version']}/{control['control_id']}",
                f"Official NIST catalog snapshot control {control['control_id']}",
                control,
            )
            for control in controls
        ],
        "warnings": (
            ["No approved NIST control snapshot is loaded. Run the connected-zone official source refresh."]
            if not controls
            else ["Controls are mapping candidates; assess implementation evidence before declaring a violation."]
        ),
    }


async def approved_mapping_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    return {
        "status": "not_configured",
        "data": {"mappings": []},
        "evidence": [],
        "warnings": [
            "No organization-approved CVE-to-control mapping repository is configured; the NIST agent must create candidate mappings from catalog and implementation evidence."
        ],
    }


async def deterministic_nist_candidate_mapping(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    finding = _finding(inputs)
    with session_factory() as session:
        response, evidence = map_finding_to_controls(
            session,
            finding,
            limit=definition.result_limit,
            backend=definition.mapping_backend,
            embedding_model=definition.embedding_model,
            reranker_model=definition.reranker_model,
            embedding_cache_dir=definition.embedding_cache_dir,
            embedding_batch_size=definition.embedding_batch_size,
        )
    return {
        "data": response,
        "evidence": evidence,
        "warnings": [
            "This local mapper ranks candidate controls only. It does not determine control deficiency or compliance."
        ],
    }


def _latest_kev_snapshot(session: Session) -> SourceSnapshotRecord | None:
    return session.scalar(
        select(SourceSnapshotRecord)
        .where(SourceSnapshotRecord.source_name == "cisa_kev")
        .order_by(desc(SourceSnapshotRecord.retrieved_at))
    )


def _kev_data(session: Session, record: CisaKevRecord) -> dict[str, Any]:
    return {
        "cve_id": record.cve_id,
        "vendor_project": record.vendor_project,
        "product": record.product,
        "vulnerability_name": record.vulnerability_name,
        "date_added": record.date_added,
        "due_date": record.due_date,
        "required_action": record.required_action,
        "known_ransomware_campaign_use": record.known_ransomware_campaign_use,
        "notes": record.notes,
        "snapshot": _snapshot_metadata(session, record.source_snapshot_id),
    }


async def cisa_kev_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    cve_id = _value(_finding(inputs), "cve_id")
    with session_factory() as session:
        snapshot = _latest_kev_snapshot(session)
        record = session.get(CisaKevRecord, cve_id) if cve_id else None
        if not snapshot:
            return {
                "status": "source_data_missing",
                "data": {"cve_id": cve_id, "kev_status": "unknown_no_loaded_catalog"},
                "evidence": [],
                "warnings": ["No approved CISA KEV snapshot is loaded. Run the connected-zone official source refresh."],
            }
        snapshot_info = _snapshot_metadata(session, snapshot.id)
        if not record:
            return {
                "data": {
                    "cve_id": cve_id,
                    "kev_status": "not_present_in_loaded_catalog",
                    "catalog_snapshot": snapshot_info,
                },
                "evidence": [],
                "warnings": ["The local KEV snapshot is authoritative only as of retrieved_at; validate freshness before relying on absence."],
            }
        data = _kev_data(session, record)
    return {
        "data": {"kev_status": "listed", "record": data},
        "evidence": [
            _evidence(
                f"cisa-kev:{cve_id}",
                "cisa_kev_snapshot",
                f"cisa_kev/{cve_id}",
                f"Official CISA KEV snapshot entry for {cve_id}",
                data,
            )
        ],
        "warnings": ["KEV presence informs prioritization; policy applicability must be assessed separately."],
    }


async def cisa_mandate_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    cve_id = _value(_finding(inputs), "cve_id")
    with session_factory() as session:
        record = session.get(CisaKevRecord, cve_id) if cve_id else None
        if not record:
            return {
                "data": {"cve_id": cve_id, "policy_applicability": "not_determined"},
                "evidence": [],
                "warnings": ["No KEV entry is loaded for this CVE; no federal mandate conclusion can be made."],
            }
        kev = _kev_data(session, record)
    data = {
        "cve_id": cve_id,
        "policy_applicability": "requires_organization_scope_validation",
        "cisa_kev_due_date": kev["due_date"],
        "cisa_required_action": kev["required_action"],
        "required_validations": ["agency or organization scope", "current governing directive", "asset ownership", "approved exception status"],
        "source_snapshot": kev["snapshot"],
    }
    return {
        "data": {"mandate_assessment_input": data},
        "evidence": [
            _evidence(
                f"cisa-kev-policy-input:{cve_id}",
                "cisa_kev_snapshot",
                f"cisa_kev/{cve_id}/policy-input",
                f"CISA KEV remediation metadata requiring organization scope validation for {cve_id}",
                data,
            )
        ],
        "warnings": ["CISA KEV remediation metadata is not, by itself, an applicability determination for this organization."],
    }


def build_official_intelligence_adapters(session_factory: sessionmaker) -> dict[str, Callable[..., Any]]:
    def bind(handler):
        async def adapter(binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any]) -> dict[str, Any]:
            return await handler(binding, definition, inputs, session_factory)

        return adapter

    return {
        "official_nvd_snapshot": bind(nvd_cve_lookup),
        "official_nist_oscal_snapshot": bind(nist_control_catalog_lookup),
        "deterministic_nist_candidate_mapper": bind(deterministic_nist_candidate_mapping),
        "approved_control_mapping_repository": bind(approved_mapping_lookup),
        "official_cisa_kev_snapshot": bind(cisa_kev_lookup),
        "official_cisa_policy_input": bind(cisa_mandate_lookup),
    }
