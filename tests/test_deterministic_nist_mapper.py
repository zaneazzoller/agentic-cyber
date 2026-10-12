from types import SimpleNamespace

from security_workflow.mappers.nist_control_mapper import _CWE_CONTROL_CANDIDATES, _control_passages


def test_supplied_mapper_cwe_candidate_rules_remain_review_only_retrieval_expansion() -> None:
    assert "SI-10" in _CWE_CONTROL_CANDIDATES["CWE-89"]
    assert "AC-3" in _CWE_CONTROL_CANDIDATES["CWE-287"]


def test_control_passages_are_title_anchored_and_split_without_finding_data() -> None:
    control = SimpleNamespace(control_id="SI-2", title="Flaw Remediation", statement="a" * 1_001)

    passages, control_ids = _control_passages([control])

    assert control_ids == ["SI-2", "SI-2"]
    assert all(passage.startswith("SI-2 Flaw Remediation. Statement: ") for passage in passages)
    assert len(passages[0].removeprefix("SI-2 Flaw Remediation. Statement: ")) == 1_000
