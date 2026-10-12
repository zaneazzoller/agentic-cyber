from __future__ import annotations

from typing import Any

import httpx

from security_workflow.observability.audit_logging import log_audit_event


class SplunkClient:
    """Narrow Splunk boundary; callers should use approved query templates, not raw user-provided SPL."""

    def __init__(self, base_url: str, hec_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.hec_url = hec_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}

    async def run_saved_search(self, search_name: str, parameters: dict[str, str]) -> list[dict[str, Any]]:
        if not search_name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Search name must be an approved identifier")
        url = f"{self.base_url}/services/saved/searches/{search_name}/dispatch"
        log_audit_event("splunk.search_started", component="splunk", status="started")
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(url, headers=self.headers, data={"output_mode": "json", **parameters})
                response.raise_for_status()
        except Exception as exc:
            log_audit_event("splunk.search_failed", component="splunk", error_type=type(exc).__name__)
            raise
        log_audit_event("splunk.search_dispatched", component="splunk", status="dispatched")
        # Retrieval of job results belongs in the next integration increment.
        return [{"sid": response.json().get("sid"), "search_name": search_name}]

    async def publish_enrichment(self, event: dict[str, Any]) -> None:
        log_audit_event("splunk.publish_started", component="splunk", status="started")
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(self.hec_url, headers=self.headers, json={"event": event})
                response.raise_for_status()
        except Exception as exc:
            log_audit_event("splunk.publish_failed", component="splunk", error_type=type(exc).__name__)
            raise
        log_audit_event("splunk.published", component="splunk", status="published")
