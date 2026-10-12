"""Structured audit logs for LLM calls without recording sensitive prompts or outputs."""

from __future__ import annotations

import json
import logging
from typing import Any

_LOGGER = logging.getLogger("security_workflow.llm")
_ALLOWED_FIELDS = {
    "agent_id",
    "classification",
    "correlation_id",
    "duration_ms",
    "error_type",
    "max_tokens",
    "model",
    "response_tokens",
    "status_code",
    "workflow_id",
}


def log_llm_call(event: str, **fields: Any) -> None:
    """Emit metadata only. Prompts, responses, URLs, credentials, and evidence are intentionally excluded."""
    safe_fields = {key: value for key, value in fields.items() if key in _ALLOWED_FIELDS and value is not None}
    _LOGGER.info(json.dumps({"event": event, **safe_fields}, default=str, sort_keys=True))
