import json
import logging

from security_workflow.observability.audit_logging import log_audit_event


def test_audit_logs_keep_only_allowlisted_metadata(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="security_workflow.audit"):
        log_audit_event(
            "tool.completed",
            workflow_id="workflow-1",
            tool="nist_control_catalog",
            count=3,
            sql="SELECT confidential_data",
            evidence={"secret": "must-not-log"},
        )

    payload = json.loads(caplog.records[0].message)
    assert payload["workflow_id"] == "workflow-1"
    assert payload["tool"] == "nist_control_catalog"
    assert "sql" not in payload
    assert "evidence" not in payload
