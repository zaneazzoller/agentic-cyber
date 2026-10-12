import json
import logging

from security_workflow.observability.llm_logging import log_llm_call


def test_llm_logs_exclude_sensitive_fields(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="security_workflow.llm"):
        log_llm_call(
            "llm.call.completed",
            workflow_id="workflow-1",
            model="test-model",
            prompt="secret prompt that must not log",
            response="secret answer that must not log",
        )

    message = caplog.records[0].message
    payload = json.loads(message)
    assert payload["workflow_id"] == "workflow-1"
    assert "prompt" not in payload
    assert "response" not in payload
