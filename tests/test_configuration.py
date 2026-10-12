from pathlib import Path

from security_workflow.config import load_workflow_config


def test_agent_configuration_is_complete() -> None:
    root = Path(__file__).parents[1] / "config"
    config = load_workflow_config(root)

    assert [agent.id for agent in config.agents] == [
        "nist_control_mapper",
        "cisa_mandate_assessor",
        "network_overseer",
        "network_expert",
        "poam_writer",
    ]
    assert set(config.topics) >= {"finding_received", "poam_generated", "review_required"}
    assert {profile.provider for profile in config.models.values()} == {"vllm"}
    assert {profile.name for profile in config.models.values()} == {"meta-llama/Llama-3.2-1B-Instruct"}
    assert all(not agent.model_profile.startswith("openai-") for agent in config.agents)
    nist_tools = {tool.name for tool in config.agents[0].tools}
    assert nist_tools == {"nist_candidate_control_mapping"}
    assert config.agents[0].execution_mode == "deterministic_nist_mapper"
    nist_mapper = config.tools["nist_candidate_control_mapping"]
    assert nist_mapper.mapping_backend == "transformer"
    assert nist_mapper.embedding_model == "models/nist/all-mpnet-base-v2"
    assert nist_mapper.reranker_model == "models/nist/ms-marco-MiniLM-L6-v2"
    network_expert_tools = {tool.name for tool in config.agents[3].tools}
    assert "network_reachability_crawl" in network_expert_tools
    assert all(tool.name in config.tools for agent in config.agents for tool in agent.tools)


def test_configuration_uses_official_snapshots_for_nist_and_cisa_intelligence() -> None:
    config = load_workflow_config(Path(__file__).parents[1] / "config")

    assert {
        name: config.tools[name].adapter
        for name in (
            "cve_lookup",
            "nist_control_catalog",
            "cve_control_mapping_lookup",
            "cisa_kev_lookup",
            "cisa_mandate_lookup",
            "cmdb_lookup",
            "splunk_asset_context",
            "splunk_network_artifacts",
        )
    } == {
        "cve_lookup": "official_nvd_snapshot",
        "nist_control_catalog": "official_nist_oscal_snapshot",
        "cve_control_mapping_lookup": "approved_control_mapping_repository",
        "cisa_kev_lookup": "official_cisa_kev_snapshot",
        "cisa_mandate_lookup": "official_cisa_policy_input",
        "cmdb_lookup": "synthetic_cmdb",
        "splunk_asset_context": "synthetic_splunk_asset",
        "splunk_network_artifacts": "synthetic_splunk_network",
    }
