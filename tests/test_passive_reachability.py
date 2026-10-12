from types import SimpleNamespace

from security_workflow.tools.synthetic_adapters import (
    calculate_passive_reachability,
    calculate_policy_aware_reachability,
)


def test_passive_reachability_returns_shortest_directed_paths_with_hop_limit() -> None:
    edges = [
        SimpleNamespace(source_key="web", target_key="app"),
        SimpleNamespace(source_key="web", target_key="jump"),
        SimpleNamespace(source_key="app", target_key="database"),
        SimpleNamespace(source_key="jump", target_key="database"),
        SimpleNamespace(source_key="database", target_key="archive"),
    ]

    paths = calculate_passive_reachability({"web"}, edges, max_hops=2)

    assert paths["web"] == ["web"]
    assert paths["database"] == ["web", "app", "database"]
    assert "archive" not in paths


def test_passive_reachability_respects_direction_of_imported_edges() -> None:
    edges = [SimpleNamespace(source_key="web", target_key="database")]

    assert calculate_passive_reachability({"database"}, edges) == {"database": ["database"]}


def test_policy_aware_reachability_captures_firewall_rule_for_each_hop() -> None:
    assets = {
        "web": SimpleNamespace(
            source_key="web",
            hostname="web",
            internal_ip="10.10.1.10",
            zone="dmz",
            node_type="web",
            internet_facing=True,
            business_criticality="HIGH",
        ),
        "app": SimpleNamespace(
            source_key="app",
            hostname="app",
            internal_ip="10.10.2.10",
            zone="app",
            node_type="app",
            internet_facing=False,
            business_criticality="CRITICAL",
        ),
        "database": SimpleNamespace(
            source_key="database",
            hostname="database",
            internal_ip="10.10.3.10",
            zone="database",
            node_type="database",
            internet_facing=False,
            business_criticality="CRITICAL",
        ),
    }
    edges = [
        SimpleNamespace(source_key="web", target_key="app", relationship="routes", port=443),
        SimpleNamespace(source_key="app", target_key="database", relationship="connects", port=5432),
    ]
    rules = [
        SimpleNamespace(
            rule_id="allow-web-app",
            device="fw-01",
            priority=100,
            source_zone="dmz",
            destination_zone="app",
            source_cidr="10.10.1.0/24",
            destination_cidr="10.10.2.0/24",
            protocol="tcp",
            port_start=443,
            port_end=443,
            action="allow",
        ),
        SimpleNamespace(
            rule_id="deny-app-db",
            device="fw-02",
            priority=10,
            source_zone="app",
            destination_zone="database",
            source_cidr="10.10.2.0/24",
            destination_cidr="10.10.3.0/24",
            protocol="tcp",
            port_start=5432,
            port_end=5432,
            action="deny",
        ),
    ]

    result = calculate_policy_aware_reachability({"web"}, assets, edges, rules, max_hops=4)

    assert result["paths"]["app"] == ["web", "app"]
    assert "database" not in result["paths"]
    assert result["evaluated_hops"][0]["rule"]["rule_id"] == "allow-web-app"
    assert result["evaluated_hops"][1]["policy_status"] == "deny"
