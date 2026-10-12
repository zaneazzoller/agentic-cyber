"""Correlation-aware JSON logging that excludes sensitive workflow content."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

_LOGGER = logging.getLogger("security_workflow.audit")
_ALLOWED_FIELDS = {
    "adapter",
    "agent_id",
    "classification",
    "component",
    "correlation_id",
    "count",
    "duration_ms",
    "error_type",
    "event_id",
    "finding_id",
    "model_profile",
    "output_key",
    "status",
    "table",
    "tool",
    "topic",
    "workflow_id",
}


def configure_audit_logging(level: str = "INFO") -> None:
    """Configure a dedicated JSON logger once without changing Uvicorn's request log format."""
    if _LOGGER.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.addHandler(handler)
    _LOGGER.setLevel(level.upper())
    _LOGGER.propagate = False


def log_audit_event(event: str, **fields: Any) -> None:
    """Log allowlisted metadata only; callers must never pass raw external/source content."""
    safe_fields = {key: value for key, value in fields.items() if key in _ALLOWED_FIELDS and value is not None}
    _LOGGER.info(json.dumps({"event": event, **safe_fields}, default=str, sort_keys=True))
