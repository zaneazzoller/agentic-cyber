from security_workflow.agents.base import _unparsed_model_fallback


def test_nist_fallback_returns_candidate_mappings_from_official_control_evidence() -> None:
    response = _unparsed_model_fallback(
        "nist_control_mapper",
        {"finding": {"cve_id": "CVE-2022-1388"}},
        {
            "cve_lookup": {"data": {"record": {"cve_id": "CVE-2022-1388", "cvss_base_score": 9.8}}},
            "nist_control_catalog": {
                "data": {
                    "controls": [
                        {"control_id": "SI-2", "catalog_version": "5.2.0", "title": "Flaw Remediation"}
                    ]
                }
            },
        },
        "The local model supplied prose instead of JSON.",
    )

    assert response["requires_human_review"] is True
    assert response["findings"][0]["control_id"] == "SI-2"
    assert response["findings"][0]["assessment_status"] == "candidate_requires_implementation_evidence"
    assert response["nvd_snapshot"]["cvss_base_score"] == 9.8
    assert response["unstructured_model_output_for_review"] == "The local model supplied prose instead of JSON."
