from security_workflow.contracts import Finding


def test_acas_fields_are_accepted_and_vulnerability_description_alias_is_normalized() -> None:
    finding = Finding.model_validate(
        {
            "finding_id": "acas-123",
            "cve_id": "CVE-2022-1388",
            "title": "F5 BIG-IP authentication bypass",
            "source_system": "acas",
            "plugin_id": "161455",
            "plugin_family": "Web Servers",
            "vuln_description": "The appliance permits an authentication bypass through iControl REST.",
            "solution": "Apply the vendor update.",
            "plugin_output": "Installed version: 16.1.1.",
            "cvss_base_score": "9.8",
            "exploit_available": True,
            "host_fqdn": "prd-eus-lb-01.example.internal",
            "host_ip": "10.100.1.10",
            "port": 443,
            "protocol": "tcp",
            "scan_id": "scan-2026-10-12",
        }
    )

    assert finding.vulnerability_description == "The appliance permits an authentication bypass through iControl REST."
    assert finding.cvss_base_score == 9.8
    assert finding.port == 443
    assert finding.affected_assets == ["prd-eus-lb-01.example.internal", "10.100.1.10"]
