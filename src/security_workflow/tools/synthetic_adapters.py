"""Read-only synthetic-data tools used for local agent and graph validation."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from hashlib import sha256
from ipaddress import ip_address, ip_network
from typing import Any, Protocol

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from security_workflow.config import AgentToolBinding, ToolDefinition
from security_workflow.persistence.models import (
    FirewallRuleRecord,
    MitigationCorpusRecord,
    NetworkAssetRecord,
    NetworkEdgeRecord,
    SourceArtifactRecord,
    VulnerabilityAlertRecord,
)


def _finding(inputs: dict[str, Any]) -> Any:
    return inputs.get("finding", {})


def _value(finding: Any, key: str, default: Any = None) -> Any:
    return finding.get(key, default) if isinstance(finding, dict) else getattr(finding, key, default)


def _evidence(
    identifier: str,
    locator: str,
    summary: str,
    content: dict[str, Any] | None = None,
    *,
    source: str = "synthetic_dataset",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "source": source,
        "locator": locator,
        "classification": "internal",
        "summary": summary,
        "content": content or {},
    }


class TopologyEdge(Protocol):
    source_key: str
    target_key: str


class TopologyAsset(Protocol):
    source_key: str
    hostname: str
    internal_ip: str | None
    zone: str
    node_type: str
    internet_facing: bool
    business_criticality: str


class FirewallRule(Protocol):
    rule_id: str
    device: str
    priority: int
    source_zone: str | None
    destination_zone: str | None
    source_cidr: str | None
    destination_cidr: str | None
    protocol: str | None
    port_start: int | None
    port_end: int | None
    action: str


def calculate_passive_reachability(
    seed_keys: set[str],
    edges: list[TopologyEdge],
    *,
    max_hops: int = 4,
) -> dict[str, list[str]]:
    """Return shortest directed paths using inventory edges only.

    This deliberately performs graph analysis rather than host, network, or DNS probing.
    """
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        adjacency[edge.source_key].append(edge.target_key)
    paths: dict[str, list[str]] = {}
    queue: deque[tuple[str, list[str]]] = deque((key, [key]) for key in sorted(seed_keys))
    while queue:
        current, path = queue.popleft()
        if current in paths and len(paths[current]) <= len(path):
            continue
        paths[current] = path
        if len(path) - 1 >= max_hops:
            continue
        for target in adjacency.get(current, []):
            if target not in path:
                queue.append((target, [*path, target]))
    return paths


def _cidr_matches(address: str | None, cidr: str | None) -> bool:
    if not cidr:
        return True
    if not address:
        return False
    try:
        return ip_address(address) in ip_network(cidr, strict=False)
    except ValueError:
        return False


def _firewall_decision(
    source: TopologyAsset, target: TopologyAsset, edge: TopologyEdge, rules: list[FirewallRule]
) -> dict[str, Any]:
    """Match the highest-priority synthetic policy record for one directed topology edge."""
    port = getattr(edge, "port", None)
    protocol = "tcp" if port is not None else None
    matches = [
        rule
        for rule in rules
        if (rule.source_zone is None or rule.source_zone == source.zone)
        and (rule.destination_zone is None or rule.destination_zone == target.zone)
        and (rule.protocol is None or rule.protocol.lower() == protocol)
        and (rule.port_start is None or (port is not None and rule.port_start <= port))
        and (rule.port_end is None or (port is not None and port <= rule.port_end))
        and _cidr_matches(source.internal_ip, rule.source_cidr)
        and _cidr_matches(target.internal_ip, rule.destination_cidr)
    ]
    if not matches:
        return {
            "policy_status": "unknown",
            "traversal_decision": "stopped_policy_unknown",
            "policy_source": "synthetic_firewall_rules",
            "protocol": protocol,
            "port": port,
            "rule": None,
        }
    rule = min(matches, key=lambda candidate: candidate.priority)
    action = rule.action.lower()
    return {
        "policy_status": action,
        "traversal_decision": "continued" if action == "allow" else "stopped_policy_denied",
        "policy_source": "synthetic_firewall_rules",
        "protocol": protocol,
        "port": port,
        "rule": {
            "rule_id": rule.rule_id,
            "device": rule.device,
            "priority": rule.priority,
            "source_zone": rule.source_zone,
            "destination_zone": rule.destination_zone,
            "source_cidr": rule.source_cidr,
            "destination_cidr": rule.destination_cidr,
            "action": action,
        },
    }


def calculate_policy_aware_reachability(
    seed_keys: set[str],
    assets: dict[str, TopologyAsset],
    edges: list[TopologyEdge],
    rules: list[FirewallRule],
    *,
    max_hops: int = 4,
) -> dict[str, Any]:
    """Traverse only directed edges allowed by imported policy, retaining denied and unknown hop evidence."""
    adjacency: dict[str, list[TopologyEdge]] = defaultdict(list)
    for edge in edges:
        adjacency[edge.source_key].append(edge)

    paths: dict[str, list[str]] = {}
    evaluated_hops: list[dict[str, Any]] = []
    queue: deque[tuple[str, list[str]]] = deque((key, [key]) for key in sorted(seed_keys))
    while queue:
        current, path = queue.popleft()
        if current in paths and len(paths[current]) <= len(path):
            continue
        paths[current] = path
        if len(path) - 1 >= max_hops or current not in assets:
            continue
        for edge in adjacency.get(current, []):
            if edge.target_key in path or edge.target_key not in assets:
                continue
            decision = _firewall_decision(assets[current], assets[edge.target_key], edge, rules)
            hop = {
                "hop": len(path),
                "source": {
                    "asset_key": current,
                    "hostname": assets[current].hostname,
                    "internal_ip": assets[current].internal_ip,
                    "zone": assets[current].zone,
                },
                "target": {
                    "asset_key": edge.target_key,
                    "hostname": assets[edge.target_key].hostname,
                    "internal_ip": assets[edge.target_key].internal_ip,
                    "zone": assets[edge.target_key].zone,
                },
                "relationship": getattr(edge, "relationship", "unknown"),
                **decision,
            }
            evaluated_hops.append(hop)
            if decision["policy_status"] == "allow":
                queue.append((edge.target_key, [*path, edge.target_key]))
    return {"paths": paths, "evaluated_hops": evaluated_hops}


def _asset_records(session: Session, finding: Any) -> list[NetworkAssetRecord]:
    selectors = list(_value(finding, "affected_assets", []) or [])
    if not selectors and _value(finding, "cve_id"):
        selectors = list(
            session.scalars(
                select(VulnerabilityAlertRecord.target_hostname).where(
                    VulnerabilityAlertRecord.cve_id == _value(finding, "cve_id")
                )
            )
        )
    if not selectors:
        return []
    return list(
        session.scalars(
            select(NetworkAssetRecord).where(
                or_(
                    NetworkAssetRecord.hostname.in_(selectors),
                    NetworkAssetRecord.internal_ip.in_(selectors),
                    NetworkAssetRecord.source_key.in_(selectors),
                )
            )
        )
    )


def _asset_data(record: NetworkAssetRecord) -> dict[str, Any]:
    return {
        "asset_key": record.source_key,
        "hostname": record.hostname,
        "internal_ip": record.internal_ip,
        "node_type": record.node_type,
        "zone": record.zone,
        "internet_facing": record.internet_facing,
        "business_criticality": record.business_criticality,
        "synthetic": True,
    }


async def vulnerability_scan_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    finding = _finding(inputs)
    cve_id = _value(finding, "cve_id")
    assets = _value(finding, "affected_assets", []) or []
    with session_factory() as session:
        statement = select(VulnerabilityAlertRecord)
        if cve_id:
            statement = statement.where(VulnerabilityAlertRecord.cve_id == cve_id)
        if assets:
            statement = statement.where(
                or_(
                    VulnerabilityAlertRecord.target_hostname.in_(assets),
                    VulnerabilityAlertRecord.target_ip.in_(assets),
                )
            )
        records = list(session.scalars(statement.limit(definition.result_limit)))
    data = [
        {
            "scan_id": record.scan_id,
            "cve_id": record.cve_id,
            "target_hostname": record.target_hostname,
            "target_ip": record.target_ip,
            "severity_tier": record.severity_tier,
            "package_name": record.package_name,
            "installed_version": record.installed_version,
            "fixed_version": record.fixed_version,
            "manifest_path": record.manifest_path,
            "raw_description": record.raw.get("raw_description"),
            "synthetic": True,
        }
        for record in records
    ]
    return {
        "data": {"alerts": data, "synthetic": True},
        "evidence": [
            _evidence(
                f"synthetic:vulnerability-alert:{record.scan_id}",
                f"vulnerability_alerts/{record.scan_id}",
                f"Synthetic {record.severity_tier} alert for {record.cve_id} on {record.target_hostname}",
            )
            for record in records
        ],
        "warnings": ["Synthetic dataset result; do not use as production incident evidence."] if records else ["No matching synthetic alert found."],
    }


async def asset_inventory_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    with session_factory() as session:
        records = _asset_records(session, _finding(inputs))[: definition.result_limit]
    return {
        "data": {"assets": [_asset_data(record) for record in records], "synthetic": True},
        "evidence": [
            _evidence(
                f"synthetic:asset:{record.source_key}",
                f"network_assets/{record.source_key}",
                f"Synthetic asset {record.hostname} in {record.zone}",
            )
            for record in records
        ],
        "warnings": [] if records else ["No affected asset matched the synthetic inventory."],
    }


async def network_topology_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    with session_factory() as session:
        assets = _asset_records(session, _finding(inputs))
        keys = [asset.source_key for asset in assets]
        edges = list(
            session.scalars(
                select(NetworkEdgeRecord)
                .where(or_(NetworkEdgeRecord.source_key.in_(keys), NetworkEdgeRecord.target_key.in_(keys)))
                .limit(definition.result_limit)
            )
        ) if keys else []
    edge_data = [
        {"source": edge.source_key, "target": edge.target_key, "relationship": edge.relationship, "port": edge.port}
        for edge in edges
    ]
    return {
        "data": {"assets": [_asset_data(asset) for asset in assets], "direct_edges": edge_data, "synthetic": True},
        "evidence": [
            _evidence(
                f"synthetic:topology:{edge.source_key}:{edge.target_key}:{edge.relationship}:{edge.port}",
                "network_topology_edges",
                f"Synthetic directed {edge.relationship} edge {edge.source_key} to {edge.target_key} on {edge.port}",
            )
            for edge in edges
        ],
        "warnings": ["Topology includes known directed edges only; an absent edge is not proof of isolation."],
    }


async def network_reachability_crawl(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    """Passive, policy-aware directed traversal; it performs no packet, port, DNS, or host probing."""
    with session_factory() as session:
        seeds = _asset_records(session, _finding(inputs))
        assets = {asset.source_key: asset for asset in session.scalars(select(NetworkAssetRecord))}
        edges = list(session.scalars(select(NetworkEdgeRecord)))
        rules = list(session.scalars(select(FirewallRuleRecord).order_by(FirewallRuleRecord.priority)))

    seed_keys = {seed.source_key for seed in seeds}
    traversal = calculate_policy_aware_reachability(
        seed_keys, assets, edges, rules, max_hops=definition.max_hops
    )
    paths = traversal["paths"]

    reached = [assets[key] for key in paths if key in assets]
    policy_reachable_assets = [
        {**_asset_data(asset), "hop_count": len(paths[asset.source_key]) - 1, "path": paths[asset.source_key]}
        for asset in reached
        if asset.source_key not in seed_keys
    ]
    critical = [asset for asset in policy_reachable_assets if asset["business_criticality"] == "CRITICAL"]
    zones = sorted({asset["zone"] for asset in policy_reachable_assets})
    evaluated_hops = traversal["evaluated_hops"]
    denied_or_unknown_hops = [
        hop for hop in evaluated_hops if hop["policy_status"] in {"deny", "unknown"}
    ]
    warnings = [
        "Passive synthetic topology and policy traversal only; no live network probe was performed.",
        "Only edges with a matching synthetic allow rule contribute to policy-reachable blast radius.",
        "An absent topology edge or firewall rule is an inventory gap, not proof of isolation or denial.",
    ]
    if not seeds:
        warnings.append("No finding asset or matching CVE target resolved to a synthetic topology node.")
    crawl_data = {
        "seed_assets": [_asset_data(seed) for seed in seeds],
        "max_hops": definition.max_hops,
        "policy_reachable_assets": policy_reachable_assets[: definition.result_limit],
        "reachable_assets": policy_reachable_assets[: definition.result_limit],
        "evaluated_hops": evaluated_hops[: definition.result_limit],
        "denied_or_unknown_hops": denied_or_unknown_hops[: definition.result_limit],
        "blast_radius": {
            "policy_reachable_asset_count": len(policy_reachable_assets),
            "critical_asset_count": len(critical),
            "zones_touched": zones,
            "max_policy_hops": max((asset["hop_count"] for asset in policy_reachable_assets), default=0),
            "evaluated_hop_count": len(evaluated_hops),
            "denied_or_unknown_hop_count": len(denied_or_unknown_hops),
        },
        "synthetic": True,
    }
    seed_fingerprint = sha256("|".join(sorted(seed_keys)).encode()).hexdigest()[:16]
    evidence_id = f"synthetic:reachability:{seed_fingerprint}"
    return {
        "data": crawl_data,
        "evidence": [
            _evidence(
                evidence_id,
                "network_topology_edges/passive-crawl",
                f"Passive policy-aware crawl from {len(seeds)} seed asset(s) reached {len(policy_reachable_assets)} allowed assets",
                content=crawl_data,
            )
        ] if seeds else [],
        "warnings": warnings,
    }


async def manifest_artifact_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    finding = _finding(inputs)
    with session_factory() as session:
        alerts = list(
            session.scalars(
                select(VulnerabilityAlertRecord).where(
                    VulnerabilityAlertRecord.cve_id == _value(finding, "cve_id")
                )
            )
        )
        terms = {alert.package_name.lower() for alert in alerts if alert.package_name}
        artifacts = list(session.scalars(select(SourceArtifactRecord)))
    matches = [artifact for artifact in artifacts if any(term in artifact.content.lower() for term in terms)]
    matches = matches[: definition.result_limit]
    return {
        "data": {
            "alert_manifest_paths": [alert.manifest_path for alert in alerts if alert.manifest_path],
            "artifacts": [
                {"artifact_key": artifact.artifact_key, "content": artifact.content[:8000], "synthetic": True}
                for artifact in matches
            ],
            "synthetic": True,
        },
        "evidence": [
            _evidence(
                f"synthetic:manifest:{artifact.artifact_key}",
                f"source_artifacts/{artifact.artifact_key}",
                f"Synthetic manifest artifact {artifact.artifact_key}",
            )
            for artifact in matches
        ],
        "warnings": [] if matches else ["No synthetic manifest artifact matched the vulnerability package."],
    }


async def historical_mitigation_search(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    finding = _finding(inputs)
    query_tokens = {
        token.lower()
        for value in (_value(finding, "cve_id", ""), _value(finding, "title", ""), _value(finding, "severity", ""))
        for token in str(value).replace("-", " ").split()
        if len(token) > 2
    }
    with session_factory() as session:
        corpus = list(session.scalars(select(MitigationCorpusRecord)))
    ranked = sorted(
        ((sum(token in record.content.lower() for token in query_tokens), record) for record in corpus),
        key=lambda item: item[0],
        reverse=True,
    )
    ranked = [(score, record) for score, record in ranked if score > 0][: definition.result_limit]
    return {
        "data": {
            "matches": [
                {"corpus_index": record.corpus_index, "score": score, "content": record.content, "synthetic": True}
                for score, record in ranked
            ],
            "retrieval_mode": "lexical_baseline",
            "synthetic": True,
        },
        "evidence": [
            _evidence(
                f"synthetic:mitigation:{record.corpus_index}",
                f"mitigation_corpus/{record.corpus_index}",
                "Synthetic historical mitigation example; advisory only",
            )
            for _, record in ranked
        ],
        "warnings": (
            ["Historical mitigation examples are advisory and cannot automatically close or accept risk."]
            if ranked
            else ["No relevant synthetic historical mitigation example was found."]
        ),
    }


def _exercise_provenance(source_name: str) -> dict[str, str]:
    """Make exercise records useful without representing them as a live upstream system."""
    return {
        "mode": "synthetic_exercise",
        "source_simulation": source_name,
        "live_query": "not_performed",
        "operator_action": "Validate against the approved live source before operational use.",
    }


def _control_candidates(cve_id: str | None) -> list[dict[str, str]]:
    """Production-shaped NIST mapping candidates for a clearly labelled exercise snapshot."""
    return [
        {
            "control_id": "RA-5",
            "revision": "NIST SP 800-53 Rev. 5",
            "title": "Vulnerability Monitoring and Scanning",
            "description": "Assess whether the organization detects, prioritizes, and tracks remediation of the affected component.",
            "mapping_rationale": f"{cve_id or 'The finding'} requires evidence of vulnerability identification and remediation tracking.",
        },
        {
            "control_id": "SI-2",
            "revision": "NIST SP 800-53 Rev. 5",
            "title": "Flaw Remediation",
            "description": "Assess whether the affected system receives, tests, and installs security-relevant updates within approved timelines.",
            "mapping_rationale": "The finding indicates a possible gap in patch or compensating-control execution.",
        },
        {
            "control_id": "CM-6",
            "revision": "NIST SP 800-53 Rev. 5",
            "title": "Configuration Settings",
            "description": "Assess whether secure configuration and documented exceptions constrain exposure while remediation is pending.",
            "mapping_rationale": "Interim restrictions and configuration changes may be required before a permanent fix is validated.",
        },
        {
            "control_id": "SC-7",
            "revision": "NIST SP 800-53 Rev. 5",
            "title": "Boundary Protection",
            "description": "Assess whether boundary controls restrict untrusted or unnecessary communications to the affected service.",
            "mapping_rationale": "Topology and firewall policy should be examined for containment and blast-radius reduction.",
        },
    ]


async def simulated_cve_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    finding = _finding(inputs)
    cve_id = _value(finding, "cve_id")
    with session_factory() as session:
        alerts = list(
            session.scalars(
                select(VulnerabilityAlertRecord).where(VulnerabilityAlertRecord.cve_id == cve_id).limit(
                    definition.result_limit
                )
            )
        ) if cve_id else []
    products = sorted({alert.package_name for alert in alerts if alert.package_name})
    record = {
        "cve_id": cve_id,
        "record_state": "simulated_intelligence_record",
        "affected_products_observed": products,
        "affected_asset_count": len({alert.target_hostname for alert in alerts}),
        "severity_from_finding": _value(finding, "severity"),
        "exploit_status": "unverified_in_exercise",
        "provenance": _exercise_provenance("NVD/CVE intelligence feed"),
    }
    return {
        "data": {"record": record},
        "evidence": [
            _evidence(
                f"exercise:cve:{cve_id or 'missing'}",
                f"simulated-cve-intelligence/{cve_id or 'missing'}",
                f"Exercise CVE intelligence record for {cve_id or 'an unspecified CVE'}",
                record,
                source="synthetic_cve_intelligence",
            )
        ],
        "warnings": ["This is a production-shaped simulation, not a live CVE/NVD query."],
    }


async def simulated_nist_catalog(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    cve_id = _value(_finding(inputs), "cve_id")
    controls = _control_candidates(cve_id)[: definition.result_limit]
    data = {
        "catalog_revision": "NIST SP 800-53 Rev. 5",
        "controls": controls,
        "provenance": _exercise_provenance("versioned NIST control catalog"),
    }
    return {
        "data": data,
        "evidence": [
            _evidence(
                f"exercise:nist-800-53r5:{control['control_id']}",
                f"simulated-nist-800-53-rev5/{control['control_id']}",
                f"Exercise catalog candidate {control['control_id']} ({control['title']})",
                control,
                source="synthetic_nist_catalog",
            )
            for control in controls
        ],
        "warnings": ["Control text is an exercise summary; validate against the approved catalog before an assessment."],
    }


async def simulated_cve_control_mapping(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    cve_id = _value(_finding(inputs), "cve_id")
    mappings = [
        {
            "mapping_id": f"exercise-map-{cve_id or 'unknown'}-{control['control_id'].lower()}",
            "cve_id": cve_id,
            "control_id": control["control_id"],
            "review_status": "exercise_reviewed_example",
            "confidence": "candidate_only",
            "rationale": control["mapping_rationale"],
        }
        for control in _control_candidates(cve_id)[: definition.result_limit]
    ]
    return {
        "data": {"mappings": mappings, "provenance": _exercise_provenance("reviewed control mapping repository")},
        "evidence": [
            _evidence(
                mapping["mapping_id"],
                f"simulated-control-mappings/{mapping['mapping_id']}",
                f"Exercise historical mapping candidate for {mapping['control_id']}",
                mapping,
                source="synthetic_control_mapping",
            )
            for mapping in mappings
        ],
        "warnings": ["Historical mappings are comparison aids and are not assessment determinations."],
    }


async def simulated_cisa_kev_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    cve_id = _value(_finding(inputs), "cve_id")
    # This known test case exercises the urgent KEV branch, but remains explicitly non-live.
    listed = cve_id == "CVE-2022-1388"
    record = {
        "cve_id": cve_id,
        "kev_status": "listed_in_simulated_snapshot" if listed else "not_listed_in_simulated_snapshot",
        "known_exploited": listed,
        "decision": "expedite_review" if listed else "standard_priority_review",
        "provenance": _exercise_provenance("CISA KEV catalog snapshot"),
    }
    return {
        "data": {"record": record},
        "evidence": [
            _evidence(
                f"exercise:cisa-kev:{cve_id or 'missing'}",
                f"simulated-cisa-kev/{cve_id or 'missing'}",
                f"Exercise KEV result: {record['kev_status']}",
                record,
                source="synthetic_cisa_kev",
            )
        ],
        "warnings": ["KEV status is simulated; query the current approved CISA source before response action."],
    }


async def simulated_cisa_mandate_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    cve_id = _value(_finding(inputs), "cve_id")
    record = {
        "cve_id": cve_id,
        "applicability": "conditional_on_federal_scope",
        "policy_decision": "human_validation_required",
        "simulated_response_target": "Urgent remediation review within 14 calendar days when an approved policy applies.",
        "required_checks": ["agency scope", "current directive", "asset ownership", "approved exception process"],
        "provenance": _exercise_provenance("federal mandate and directive register"),
    }
    return {
        "data": {"mandates": [record]},
        "evidence": [
            _evidence(
                f"exercise:mandate:{cve_id or 'missing'}",
                f"simulated-mandate-register/{cve_id or 'missing'}",
                "Exercise mandate applicability record requiring policy validation",
                record,
                source="synthetic_mandate_register",
            )
        ],
        "warnings": ["No live federal mandate determination was performed."],
    }


async def simulated_cmdb_lookup(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    with session_factory() as session:
        assets = _asset_records(session, _finding(inputs))[: definition.result_limit]
    services = [
        {
            "ci_id": f"exercise-ci-{asset.source_key}",
            "hostname": asset.hostname,
            "service_tier": asset.business_criticality,
            "environment": "production_simulation",
            "support_group": "Network and Platform Operations",
            "change_window": "Approved emergency change process required for critical exposure.",
            "provenance": _exercise_provenance("CMDB and service ownership system"),
        }
        for asset in assets
    ]
    return {
        "data": {"configuration_items": services},
        "evidence": [
            _evidence(
                service["ci_id"],
                f"simulated-cmdb/{service['ci_id']}",
                f"Exercise CMDB record for {service['hostname']}",
                service,
                source="synthetic_cmdb",
            )
            for service in services
        ],
        "warnings": ["Ownership and change data are simulated and require CMDB validation."],
    }


async def simulated_splunk_asset_context(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    finding = _finding(inputs)
    with session_factory() as session:
        assets = _asset_records(session, finding)[: definition.result_limit]
        alerts = list(
            session.scalars(
                select(VulnerabilityAlertRecord).where(VulnerabilityAlertRecord.cve_id == _value(finding, "cve_id"))
            )
        )
    records = [
        {
            "event_type": "vulnerability_context",
            "asset": asset.hostname,
            "zone": asset.zone,
            "internet_facing": asset.internet_facing,
            "correlated_alert_count": sum(alert.target_hostname == asset.hostname for alert in alerts),
            "provenance": _exercise_provenance("Splunk saved search: security_asset_context"),
        }
        for asset in assets
    ]
    return {
        "data": {"search_name": "security_asset_context", "records": records},
        "evidence": [
            _evidence(
                f"exercise:splunk:asset:{record['asset']}",
                f"simulated-splunk/security_asset_context/{record['asset']}",
                f"Exercise Splunk asset-context event for {record['asset']}",
                record,
                source="synthetic_splunk",
            )
            for record in records
        ],
        "warnings": ["This output simulates an approved Splunk saved search; no Splunk query was sent."],
    }


async def simulated_splunk_network_artifacts(
    binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any], session_factory: sessionmaker
) -> dict[str, Any]:
    with session_factory() as session:
        assets = _asset_records(session, _finding(inputs))
        keys = [asset.source_key for asset in assets]
        edges = list(
            session.scalars(
                select(NetworkEdgeRecord)
                .where(or_(NetworkEdgeRecord.source_key.in_(keys), NetworkEdgeRecord.target_key.in_(keys)))
                .limit(definition.result_limit)
            )
        ) if keys else []
    records = [
        {
            "event_type": "network_dependency",
            "source": edge.source_key,
            "destination": edge.target_key,
            "relationship": edge.relationship,
            "port": edge.port,
            "provenance": _exercise_provenance("Splunk saved search: security_network_artifacts_by_asset"),
        }
        for edge in edges
    ]
    return {
        "data": {"search_name": "security_network_artifacts_by_asset", "records": records},
        "evidence": [
            _evidence(
                f"exercise:splunk:network:{record['source']}:{record['destination']}:{record['port']}",
                f"simulated-splunk/security_network_artifacts_by_asset/{record['source']}",
                f"Exercise Splunk network dependency from {record['source']} to {record['destination']}",
                record,
                source="synthetic_splunk",
            )
            for record in records
        ],
        "warnings": ["This output simulates an approved Splunk saved search; no Splunk query was sent."],
    }


def build_synthetic_adapters(session_factory: sessionmaker) -> dict[str, Callable[..., Any]]:
    """Return read-only adapters keyed by the tool-registry adapter name."""

    def bind(handler):
        async def adapter(binding: AgentToolBinding, definition: ToolDefinition, inputs: dict[str, Any]) -> dict[str, Any]:
            return await handler(binding, definition, inputs, session_factory)

        return adapter

    return {
        "synthetic_vulnerability": bind(vulnerability_scan_lookup),
        "synthetic_cve_intelligence": bind(simulated_cve_lookup),
        "synthetic_nist_catalog": bind(simulated_nist_catalog),
        "synthetic_control_mapping": bind(simulated_cve_control_mapping),
        "synthetic_cisa_kev": bind(simulated_cisa_kev_lookup),
        "synthetic_mandate": bind(simulated_cisa_mandate_lookup),
        "synthetic_asset_inventory": bind(asset_inventory_lookup),
        "synthetic_cmdb": bind(simulated_cmdb_lookup),
        "synthetic_network_topology": bind(network_topology_lookup),
        "synthetic_reachability": bind(network_reachability_crawl),
        "synthetic_manifest": bind(manifest_artifact_lookup),
        "synthetic_mitigation_retrieval": bind(historical_mitigation_search),
        "synthetic_splunk_asset": bind(simulated_splunk_asset_context),
        "synthetic_splunk_network": bind(simulated_splunk_network_artifacts),
    }
