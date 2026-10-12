import pytest

from security_workflow.services.vllm import (
    ModelResponseError,
    _chat_completions_endpoint,
    _compact_payload_for_model,
    _parse_json_object,
    _payload_json,
)


def test_vllm_endpoint_is_built_without_http_client_path_joining() -> None:
    assert _chat_completions_endpoint("http://127.0.0.1:8000/v1") == (
        "http://127.0.0.1:8000/v1/chat/completions"
    )


def test_model_response_parser_accepts_fenced_or_prefixed_json() -> None:
    assert _parse_json_object("```json\n{\"confidence\": 0.5}\n```") == {"confidence": 0.5}
    assert _parse_json_object("Result: {\"requires_human_review\": true}") == {
        "requires_human_review": True
    }


def test_model_response_parser_rejects_non_json_content() -> None:
    with pytest.raises(ModelResponseError):
        _parse_json_object("I cannot provide JSON")


def test_payload_serializer_uses_pydantic_json_mode() -> None:
    class Serializable:
        def model_dump(self, *, mode: str):
            assert mode == "json"
            return {"value": "serialized"}

    assert _payload_json({"finding": Serializable()}) == '{"finding":{"value":"serialized"}}'


def test_model_payload_compaction_keeps_valid_json_and_marks_omitted_records() -> None:
    payload = {
        "finding": {"finding_id": "demo-1"},
        "tool_results": {"network": {"data": {"records": [{"content": "x" * 500} for _ in range(10)]}}},
    }

    compacted, was_compacted = _compact_payload_for_model(payload, max_chars=600)

    assert was_compacted is True
    assert len(_payload_json(compacted)) <= 600
    assert compacted["tool_results"]["network"]["data"]["records"][-1] == {"_omitted_item_count": 8}
