from __future__ import annotations

from typing import Any

from security_workflow.config import AgentDefinition, ModelProfile
from security_workflow.contracts import AgentResult
from security_workflow.orchestration.state import WorkflowState
from security_workflow.observability.audit_logging import log_audit_event
from security_workflow.services.vllm import ModelClient, ModelResponseError
from security_workflow.tools.registry import ToolRegistry


_OUTPUT_CONTRACT = """
Return exactly one JSON object and no Markdown. Use this minimum shape:
{
  "summary": "short evidence-based assessment",
  "confidence": 0.0,
  "requires_human_review": true,
  "rationale": "why the assessment needs review",
  "findings": [],
  "recommendations": [],
  "assumptions": []
}
`confidence` must be a number from 0 through 1. If evidence is missing, state that in `assumptions` and
set `requires_human_review` to true. Do not claim that a remediation is complete.
""".strip()


def _confidence(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value) if 0 <= value <= 1 else None
    if isinstance(value, str):
        try:
            parsed = float(value)
        except ValueError:
            return None
        return parsed if 0 <= parsed <= 1 else None
    return None


def _review_required(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}
    return bool(value)


def _tool_data(tool_results: dict[str, Any], name: str) -> dict[str, Any]:
    result = tool_results.get(name, {})
    value = result.get("data", {}) if isinstance(result, dict) else {}
    return value if isinstance(value, dict) else {}


def _finding_value(finding: Any, key: str) -> Any:
    return finding.get(key) if isinstance(finding, dict) else getattr(finding, key, None)


def _acas_observation(finding: Any) -> dict[str, Any]:
    """Expose scanner facts in a fallback draft without copying arbitrary raw scanner payloads."""
    keys = (
        "plugin_id",
        "plugin_name",
        "plugin_family",
        "vulnerability_description",
        "solution",
        "risk_factor",
        "cvss_base_score",
        "cvss_vector",
        "exploit_available",
        "exploited_by_malware",
        "stig_severity",
        "host_fqdn",
        "host_ip",
        "operating_system",
        "port",
        "protocol",
        "service",
        "package_name",
        "installed_version",
        "fixed_version",
        "scan_id",
        "scan_name",
    )
    return {key: value for key in keys if (value := _finding_value(finding, key)) is not None}


def _bounded_text(value: Any, limit: int = 1_200) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return value if len(value) <= limit else f"{value[:limit]}… [truncated]"


def _model_output_for_review(content: str | None) -> str | None:
    """Keep a bounded model reply in the durable result, never in application logs."""
    return _bounded_text(content, limit=3_000)


def _unparsed_model_fallback(
    agent_id: str,
    inputs: dict[str, Any],
    tool_results: dict[str, Any],
    model_content: str | None,
) -> dict[str, Any]:
    """Produce a useful, source-grounded draft if a small local model ignores the JSON contract."""
    finding = inputs.get("finding", {})
    cve_id = _finding_value(finding, "cve_id")
    raw_output = _model_output_for_review(model_content)
    common = {
        "confidence": 0.35,
        "requires_human_review": True,
        "rationale": "The local model returned unstructured text, so this draft was assembled directly from supplied evidence and requires reviewer approval.",
        "assumptions": [
            "This is a deterministic evidence-backed fallback, not an accepted model conclusion.",
            "All remediation, control-violation, and policy-applicability decisions require human validation.",
        ],
    }
    if raw_output:
        common["unstructured_model_output_for_review"] = raw_output

    if agent_id == "nist_control_mapper":
        nvd_record = _tool_data(tool_results, "cve_lookup").get("record", {})
        controls = _tool_data(tool_results, "nist_control_catalog").get("controls", [])
        findings = [
            {
                "type": "candidate_control_mapping",
                "control_id": control.get("control_id"),
                "title": control.get("title"),
                "catalog_version": control.get("catalog_version"),
                "assessment_status": "candidate_requires_implementation_evidence",
                "rationale": "The official catalog control is relevant to vulnerability discovery, remediation, configuration, or boundary protection; implementation evidence is required to determine a violation.",
                "evidence_id": f"nist:{control.get('catalog_version')}:{control.get('control_id')}",
            }
            for control in controls
            if isinstance(control, dict)
        ]
        return {
            "summary": (
                f"Evidence-backed NIST mapping draft for {cve_id or 'the finding'} using the local official NVD and NIST snapshots. "
                f"{len(findings)} control candidates require implementation assessment."
            ),
            "findings": findings,
            "recommendations": [
                "Validate the affected product and installed version against the NVD snapshot and local asset evidence.",
                "Collect vulnerability-management, patch, configuration, and boundary-control evidence before recording any control deficiency.",
                "Have an authorized assessor review the candidate mappings and evidence freshness.",
            ],
            "nvd_snapshot": {
                "cve_id": nvd_record.get("cve_id"),
                "cvss_base_score": nvd_record.get("cvss_base_score"),
                "last_modified_at": nvd_record.get("last_modified_at"),
            },
            "acas_scan_observation": _acas_observation(finding),
            **common,
        }

    if agent_id == "cisa_mandate_assessor":
        kev_data = _tool_data(tool_results, "cisa_kev_lookup")
        kev_record = kev_data.get("record", {}) if isinstance(kev_data, dict) else {}
        policy_data = _tool_data(tool_results, "cisa_mandate_lookup")
        listed = kev_data.get("kev_status") == "listed" if isinstance(kev_data, dict) else False
        return {
            "summary": f"Evidence-backed CISA assessment for {cve_id or 'the finding'}: {'listed in the loaded KEV snapshot' if listed else 'not listed in the loaded KEV snapshot'}.",
            "findings": [{
                "kev_status": kev_data.get("kev_status"),
                "due_date": kev_record.get("due_date"),
                "required_action": kev_record.get("required_action"),
                "policy_input": policy_data.get("mandate_assessment_input"),
                "assessment_status": "requires_organization_scope_validation",
            }],
            "recommendations": [
                "Verify the CISA snapshot retrieval time and current catalog state.",
                "Have the policy owner determine directive applicability, organization scope, and exception status.",
            ],
            **common,
        }

    if agent_id == "network_overseer":
        assets = _tool_data(tool_results, "asset_inventory_lookup").get("assets", [])
        cmdb = _tool_data(tool_results, "cmdb_lookup").get("configuration_items", [])
        return {
            "summary": f"Evidence-backed network triage draft for {len(assets)} affected asset(s).",
            "findings": [{"assets": assets, "configuration_items": cmdb, "assessment_status": "owner_and_exposure_validation_required"}],
            "recommendations": [
                "Confirm affected-service ownership and emergency-change authority.",
                "Validate exposure and active exploitation signals with the network and SOC owners.",
            ],
            **common,
        }

    if agent_id == "network_expert":
        crawl = _tool_data(tool_results, "network_reachability_crawl")
        blast_radius = crawl.get("blast_radius", {}) if isinstance(crawl, dict) else {}
        return {
            "summary": f"Evidence-backed remediation draft with a passive policy-aware blast radius of {blast_radius.get('policy_reachable_asset_count', 0)} reachable asset(s).",
            "findings": [{"blast_radius": blast_radius, "denied_or_unknown_hops": crawl.get("denied_or_unknown_hops", [])}],
            "recommendations": [
                "Apply the vendor-approved remediation through the accountable change process.",
                "Validate each containment or segmentation action against the named firewall rule and service dependency.",
                "Verify remediation with approved vulnerability and operational checks; do not treat passive topology as live reachability.",
            ],
            **common,
        }

    if agent_id == "poam_writer":
        return {
            "summary": f"Evidence-backed POA&M draft shell for {cve_id or 'the finding'}; upstream assessments require human approval.",
            "findings": [{"upstream_assessment_keys": sorted(key for key in inputs if key != "finding")}],
            "recommendations": [
                "Assign an accountable owner and milestone dates through the approved governance process.",
                "Attach validated NIST, CISA, asset, network, and remediation evidence before accepting residual risk or closing the item.",
            ],
            **common,
        }

    return {
        "summary": "Evidence-backed fallback generated because the local model response was not structured JSON.",
        "findings": [],
        "recommendations": ["Review available evidence and the retained unstructured model output."],
        **common,
    }
    return {
        "summary": "The model response could not be parsed as structured JSON.",
        "confidence": 0.0,
        "requires_human_review": True,
        "rationale": "The configured model returned an unusable structured response.",
        "findings": [],
        "recommendations": [],
        "assumptions": ["No model-generated conclusion was accepted because its response was not valid JSON."],
    }


class ConfiguredAgent:
    def __init__(
        self,
        definition: AgentDefinition,
        profile: ModelProfile,
        model_client: ModelClient,
        tool_registry: ToolRegistry,
    ) -> None:
        self.definition = definition
        self.profile = profile
        self.model_client = model_client
        self.tool_registry = tool_registry
        self.tool_registry.validate_bindings(definition.tools)

    async def invoke(self, state: WorkflowState) -> dict[str, Any]:
        audit = {
            "component": "agent",
            "agent_id": self.definition.id,
            "workflow_id": state.get("workflow_id"),
            "correlation_id": state.get("correlation_id"),
            "finding_id": getattr(state.get("finding"), "finding_id", None),
            "classification": state.get("classification", "internal"),
            "model_profile": self.definition.model_profile,
        }
        log_audit_event("agent.started", **audit)
        inputs = self._build_inputs(state)
        try:
            tool_results = await self._run_tools(inputs, audit)
            if tool_results:
                inputs["tool_results"] = tool_results
            try:
                response = await self.model_client.structured_completion(
                    profile=self.profile,
                    system_prompt=f"{self.definition.system_prompt}\n\n{_OUTPUT_CONTRACT}",
                    user_payload=inputs,
                    max_tokens=self.definition.max_tokens,
                    audit_context={
                        "agent_id": self.definition.id,
                        "workflow_id": state.get("workflow_id", "unknown"),
                        "correlation_id": state.get("correlation_id", "unknown"),
                        "classification": state.get("classification", "internal"),
                    },
                )
            except ModelResponseError as exc:
                log_audit_event("agent.unparsed_model_response", **audit, error_type=type(exc).__name__)
                response = _unparsed_model_fallback(self.definition.id, inputs, tool_results, exc.content)
            result = AgentResult(
                agent_id=self.definition.id,
                status="completed",
                result=response,
                evidence_ids=[item["id"] for item in state.get("evidence", []) if "id" in item]
                + [
                    item["id"]
                    for tool_result in tool_results.values()
                    for item in tool_result.get("evidence", [])
                    if "id" in item
                ],
                confidence=_confidence(response.get("confidence")),
                requires_human_review=_review_required(response.get("requires_human_review")),
                rationale=response.get("rationale") if isinstance(response.get("rationale"), str) else None,
            )
            outputs = dict(state.get("agent_outputs", {}))
            outputs[self.definition.output_key] = result.model_dump(mode="json")
            evidence = list(state.get("evidence", []))
            seen_evidence = {item.get("id") for item in evidence}
            for tool_result in tool_results.values():
                for item in tool_result.get("evidence", []):
                    if item.get("id") and item["id"] not in seen_evidence:
                        evidence.append(item)
                        seen_evidence.add(item["id"])
            log_audit_event(
                "agent.completed",
                **audit,
                output_key=self.definition.output_key,
                count=len(tool_results),
                status="review_required" if result.requires_human_review else "completed",
            )
            return {
                "agent_outputs": outputs,
                "evidence": evidence,
                "requires_human_review": state.get("requires_human_review", False)
                or result.requires_human_review,
            }
        except Exception as exc:
            log_audit_event("agent.failed", **audit, error_type=type(exc).__name__)
            raise RuntimeError(f"Agent '{self.definition.id}' failed: {exc}") from exc

    def _build_inputs(self, state: WorkflowState) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for key in self.definition.input_keys:
            if key in {"finding", "evidence"}:
                values[key] = state.get(key)
            else:
                values[key] = state.get("agent_outputs", {}).get(key)
        return values

    async def _run_tools(self, inputs: dict[str, Any], audit_context: dict[str, Any]) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for binding in self.definition.tools:
            results[binding.name] = await self.tool_registry.invoke(binding, inputs, audit_context)
        return results
