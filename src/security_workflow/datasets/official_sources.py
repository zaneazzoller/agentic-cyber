"""Connected-zone importer for authoritative vulnerability and control snapshots.

This module is intentionally a CLI, not an agent tool. Run it from an approved connected
environment, validate the imported records, and then allow the air-gapped workflow to read the
PostgreSQL snapshots. It never makes internet requests while a workflow is executing.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from datetime import datetime
from typing import Any, Iterable

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from security_workflow.persistence.database import create_session_factory, create_tables
from security_workflow.persistence.models import (
    CisaKevRecord,
    CveIntelligenceRecord,
    NistControlRecord,
    SourceSnapshotRecord,
)
from security_workflow.settings import Settings


NIST_OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# CISA maintains this mirror of its canonical feed. It is only used if a connected host cannot retrieve
# cisa.gov directly (for example, due to an enterprise web gateway's bot protection policy).
CISA_KEV_MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
)
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "security-workflow-source-refresh/1.0"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _snapshot(
    session: Session,
    *,
    source_name: str,
    source_url: str,
    content: bytes,
    source_version: str | None,
    record_count: int,
    metadata: dict[str, Any] | None = None,
) -> SourceSnapshotRecord:
    record = SourceSnapshotRecord(
        source_name=source_name,
        source_url=source_url,
        content_sha256=_sha256(content),
        source_version=source_version,
        record_count=record_count,
        source_metadata=metadata or {},
    )
    session.add(record)
    session.flush()
    return record


def _part_text(parts: Iterable[dict[str, Any]]) -> str | None:
    fragments: list[str] = []
    for part in parts:
        if part.get("name") == "statement" and part.get("prose"):
            fragments.append(str(part["prose"]))
        fragments.extend(filter(None, [_part_text(part.get("parts", []))]))
    return "\n".join(fragments) or None


def _iter_controls(groups: Iterable[dict[str, Any]]) -> Iterable[tuple[str | None, dict[str, Any]]]:
    for group in groups:
        family = group.get("id")
        for control in group.get("controls", []):
            yield family, control
        yield from _iter_controls(group.get("groups", []))


def import_nist_catalog(session: Session, content: bytes) -> int:
    document = httpx.Response(200, content=content).json()
    catalog = document["catalog"]
    metadata = catalog.get("metadata", {})
    version = str(metadata.get("version") or "SP800-53-rev5")
    controls = list(_iter_controls(catalog.get("groups", [])))
    snapshot = _snapshot(
        session,
        source_name="nist_sp_800_53_oscal",
        source_url=NIST_OSCAL_URL,
        content=content,
        source_version=version,
        record_count=len(controls),
        metadata={"title": metadata.get("title"), "last_modified": metadata.get("last-modified")},
    )
    for family, control in controls:
        control_id = str(control["id"]).upper()
        existing = session.scalar(
            select(NistControlRecord).where(
                NistControlRecord.control_id == control_id,
                NistControlRecord.catalog_version == version,
            )
        )
        values = {
            "title": str(control.get("title", control_id)),
            "statement": _part_text(control.get("parts", [])),
            "family": str(family).upper() if family else None,
            "source_snapshot_id": snapshot.id,
            "raw": control,
        }
        if existing:
            for field, field_value in values.items():
                setattr(existing, field, field_value)
        else:
            session.add(NistControlRecord(control_id=control_id, catalog_version=version, **values))
    session.commit()
    return len(controls)


def import_cisa_kev(session: Session, content: bytes, source_url: str = CISA_KEV_URL) -> int:
    document = httpx.Response(200, content=content).json()
    vulnerabilities = document.get("vulnerabilities", [])
    snapshot = _snapshot(
        session,
        source_name="cisa_kev",
        source_url=source_url,
        content=content,
        source_version=document.get("catalogVersion"),
        record_count=len(vulnerabilities),
        metadata={"date_released": document.get("dateReleased")},
    )
    for item in vulnerabilities:
        cve_id = item["cveID"]
        existing = session.get(CisaKevRecord, cve_id)
        values = {
            "vendor_project": item.get("vendorProject"),
            "product": item.get("product"),
            "vulnerability_name": item.get("vulnerabilityName"),
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "required_action": item.get("requiredAction"),
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
            "notes": item.get("notes"),
            "source_snapshot_id": snapshot.id,
            "raw": item,
        }
        if existing:
            for field, field_value in values.items():
                setattr(existing, field, field_value)
        else:
            session.add(CisaKevRecord(cve_id=cve_id, **values))
    session.commit()
    return len(vulnerabilities)


def _cvss(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric_name, [])
        if metrics:
            data = metrics[0].get("cvssData", {})
            return data.get("baseScore"), data.get("vectorString")
    return None, None


def import_nvd_cve(session: Session, content: bytes, source_url: str) -> str:
    document = httpx.Response(200, content=content).json()
    vulnerabilities = document.get("vulnerabilities", [])
    if len(vulnerabilities) != 1:
        raise ValueError("NVD CVE API response did not contain exactly one vulnerability")
    cve = vulnerabilities[0]["cve"]
    cve_id = cve["id"]
    score, vector = _cvss(cve)
    description = next(
        (item.get("value") for item in cve.get("descriptions", []) if item.get("lang") == "en"), None
    )
    snapshot = _snapshot(
        session,
        source_name="nvd_cve_api_2",
        source_url=source_url,
        content=content,
        source_version=document.get("version"),
        record_count=1,
        metadata={"nvd_timestamp": document.get("timestamp")},
    )
    existing = session.get(CveIntelligenceRecord, cve_id)
    values = {
        "source_snapshot_id": snapshot.id,
        "published_at": _parse_timestamp(cve.get("published")),
        "last_modified_at": _parse_timestamp(cve.get("lastModified")),
        "description": description,
        "cvss_base_score": score,
        "cvss_vector": vector,
        "raw": cve,
    }
    if existing:
        for field, field_value in values.items():
            setattr(existing, field, field_value)
    else:
        session.add(CveIntelligenceRecord(cve_id=cve_id, **values))
    session.commit()
    return cve_id


def _download(client: httpx.Client, url: str) -> bytes:
    response = client.get(url)
    response.raise_for_status()
    return response.content


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download official NIST, CISA, and selected NVD records into local PostgreSQL snapshots."
    )
    parser.add_argument("--cve-id", action="append", required=True, help="CVE ID to fetch from NVD; repeatable.")
    parser.add_argument("--timeout", type=float, default=60, help="HTTP timeout in seconds.")
    args = parser.parse_args()

    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    nvd_api_key = os.environ.get("NVD_API_KEY")
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    settings = Settings()
    create_tables(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with httpx.Client(headers=headers, timeout=args.timeout, follow_redirects=True) as client:
        nist_content = _download(client, NIST_OSCAL_URL)
        try:
            kev_content = _download(client, CISA_KEV_URL)
            kev_source_url = CISA_KEV_URL
        except httpx.HTTPError:
            kev_content = _download(client, CISA_KEV_MIRROR_URL)
            kev_source_url = CISA_KEV_MIRROR_URL
        with session_factory() as session:
            nist_count = import_nist_catalog(session, nist_content)
            kev_count = import_cisa_kev(session, kev_content, kev_source_url)
            imported_cves: list[str] = []
            for cve_id in args.cve_id:
                url = f"{NVD_CVE_URL}?cveId={cve_id}"
                imported_cves.append(import_nvd_cve(session, _download(client, url), url))

    print(
        {
            "status": "imported",
            "nist_controls": nist_count,
            "cisa_kev_entries": kev_count,
            "nvd_cves": imported_cves,
        }
    )


if __name__ == "__main__":
    main()
