from __future__ import annotations

import json
import time
from typing import Any, Protocol

import httpx

from security_workflow.config import ModelProfile
from security_workflow.observability.llm_logging import log_llm_call


class ModelResponseError(RuntimeError):
    """An unusable model response whose content may be recovered by the calling workflow.

    The content is deliberately not included in the exception message or LLM audit logs. A caller may
    preserve a bounded copy in its durable, access-controlled workflow result for human review.
    """

    def __init__(self, message: str, content: str | None = None) -> None:
        super().__init__(message)
        self.content = content


# The local Llama 1B deployment is commonly configured with a 4,096-token context window.
# These leave room for the system prompt and avoid the sum of input and completion tokens exceeding it.
_DEFAULT_MAX_INPUT_CHARS = 8_000
_DEFAULT_MAX_COMPLETION_TOKENS = 768
_CONTEXT_RETRY_MAX_INPUT_CHARS = 6_000
_CONTEXT_RETRY_MAX_COMPLETION_TOKENS = 512


def _json_ready(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _json_ready(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _payload_json(value: dict[str, Any]) -> str:
    return json.dumps(_json_ready(value), default=str, separators=(",", ":"))


def _positive_int_from_environment(name: str, default: int) -> int:
    """Read an optional local runtime limit without making a malformed value fatal."""
    import os

    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _compact_value(value: Any, *, string_limit: int, list_limit: int) -> Any:
    """Retain a representative, valid-JSON evidence set for a small local model context."""
    if isinstance(value, str):
        return value if len(value) <= string_limit else f"{value[:string_limit]}… [truncated]"
    if isinstance(value, dict):
        return {
            str(key): _compact_value(item, string_limit=string_limit, list_limit=list_limit)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        compacted = [
            _compact_value(item, string_limit=string_limit, list_limit=list_limit)
            for item in value[:list_limit]
        ]
        if len(value) > list_limit:
            compacted.append({"_omitted_item_count": len(value) - list_limit})
        return compacted
    return value


def _compact_payload_for_model(value: dict[str, Any], max_chars: int) -> tuple[dict[str, Any], bool]:
    """Bound model input while preserving the original evidence for persistence and audit.

    Network topology, manifests, and historical data can exceed the context window of a 1B local
    model. This projection is used only for the LLM request; workflow state and PostgreSQL retain
    the complete tool result and evidence.
    """
    original = _json_ready(value)
    if len(_payload_json(original)) <= max_chars:
        return original, False

    for string_limit, list_limit in ((1_000, 12), (600, 8), (300, 5), (160, 3), (80, 2)):
        compacted = _compact_value(original, string_limit=string_limit, list_limit=list_limit)
        if len(_payload_json(compacted)) <= max_chars:
            return compacted, True

    # The last-resort shape makes compaction explicit rather than sending invalid JSON or an
    # arbitrary slice of evidence.
    return {
        "finding": _compact_value(original.get("finding", {}), string_limit=160, list_limit=3),
        "model_input_notice": (
            "The full tool result set exceeded this local model's context budget. "
            "Use only the included representative records and require human review."
        ),
        "available_input_sections": sorted(original),
    }, True


def _chat_completions_endpoint(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    return normalized if normalized.endswith("/chat/completions") else f"{normalized}/chat/completions"


def _parse_json_object(content: Any) -> dict[str, Any]:
    """Accept normal JSON or a fenced/prefixed JSON object returned by smaller local models."""
    if isinstance(content, dict):
        return content
    if not isinstance(content, str) or not content.strip():
        raise ModelResponseError("Model returned empty or non-text response content")
    candidate = content.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        candidate = "\n".join(lines[1:-1] if lines[-1].strip().startswith("```") else lines[1:]).strip()
    starts = [0]
    object_start = candidate.find("{")
    if object_start > 0:
        starts.append(object_start)
    decoder = json.JSONDecoder()
    for start in starts:
        try:
            parsed, _ = decoder.raw_decode(candidate[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ModelResponseError("Model response did not contain a JSON object", content=candidate)


def _response_content(response_body: dict[str, Any]) -> Any:
    try:
        return response_body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ModelResponseError("Model response did not contain a chat completion") from exc


class ModelClient(Protocol):
    async def structured_completion(
        self,
        *,
        profile: ModelProfile,
        system_prompt: str,
        user_payload: dict[str, Any],
        max_tokens: int,
        audit_context: dict[str, str] | None = None,
    ) -> dict[str, Any]: ...


class VllmClient:
    """Minimal client for the local vLLM chat-completions endpoint."""

    async def structured_completion(
        self,
        *,
        profile: ModelProfile,
        system_prompt: str,
        user_payload: dict[str, Any],
        max_tokens: int,
        audit_context: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        import os

        base_url = os.environ.get(profile.base_url_env)
        if not base_url:
            raise RuntimeError(f"Missing vLLM URL in environment variable {profile.base_url_env}")
        api_key = os.environ.get(profile.api_key_env)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        model_name = os.environ.get("VLLM_MODEL_NAME", profile.name)
        input_budget = _positive_int_from_environment("VLLM_MAX_INPUT_CHARS", _DEFAULT_MAX_INPUT_CHARS)
        completion_cap = _positive_int_from_environment(
            "VLLM_MAX_COMPLETION_TOKENS", _DEFAULT_MAX_COMPLETION_TOKENS
        )
        compacted_payload, input_compacted = _compact_payload_for_model(user_payload, input_budget)
        effective_max_tokens = min(max_tokens, completion_cap)
        audit = {
            "model": model_name,
            "max_tokens": effective_max_tokens,
            "requested_max_tokens": max_tokens,
            "input_compacted": input_compacted,
            **(audit_context or {}),
        }
        log_llm_call("llm.call.started", **audit)
        started_at = time.perf_counter()
        request = {
            "model": model_name,
            "temperature": profile.temperature,
            "max_tokens": effective_max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": _payload_json(compacted_payload)},
            ],
        }
        try:
            endpoint = _chat_completions_endpoint(base_url)
            # vLLM is intentionally local/air-gapped. Ignore HTTP(S)_PROXY and ALL_PROXY so a loopback
            # request cannot be redirected to a proxy that happens to return a different 404 response.
            async with httpx.AsyncClient(timeout=profile.timeout_seconds, trust_env=False) as client:
                response = await client.post(endpoint, headers=headers, json=request)
                # A model server may have a smaller context window than its model profile advertises.
                # Retry once with a smaller, still-valid evidence projection instead of failing a long
                # workflow after earlier agents have completed successfully.
                if response.status_code == 400 and "maximum context length" in response.text.lower():
                    retry_input_budget = min(input_budget, _CONTEXT_RETRY_MAX_INPUT_CHARS)
                    retry_max_tokens = min(effective_max_tokens, _CONTEXT_RETRY_MAX_COMPLETION_TOKENS)
                    retry_payload, retry_compacted = _compact_payload_for_model(user_payload, retry_input_budget)
                    request["max_tokens"] = retry_max_tokens
                    request["messages"][1]["content"] = _payload_json(retry_payload)
                    log_llm_call(
                        "llm.call.context_retry",
                        **audit,
                        retry_max_tokens=retry_max_tokens,
                        retry_input_compacted=retry_compacted,
                    )
                    response = await client.post(endpoint, headers=headers, json=request)
            if response.is_error:
                # vLLM's 400 body normally identifies the concrete request constraint (for example,
                # a context-window overflow). Keep it short because this exception is returned by API.
                detail = response.text.replace("\n", " ").strip()[:600]
                raise RuntimeError(f"vLLM returned HTTP {response.status_code}: {detail or 'no error detail'}")
            response_body = response.json()
            output = _parse_json_object(_response_content(response_body))
        except Exception as exc:
            log_llm_call(
                "llm.call.failed",
                **audit,
                duration_ms=round((time.perf_counter() - started_at) * 1000),
                error_type=type(exc).__name__,
            )
            raise
        usage = response_body.get("usage", {})
        log_llm_call(
            "llm.call.completed",
            **audit,
            duration_ms=round((time.perf_counter() - started_at) * 1000),
            status_code=response.status_code,
            response_tokens=usage.get("completion_tokens"),
        )
        return output


class ProviderRouter:
    """Dispatches all configured agents to the local vLLM endpoint."""

    def __init__(self) -> None:
        self._client = VllmClient()

    async def structured_completion(self, **kwargs: Any) -> dict[str, Any]:
        profile: ModelProfile = kwargs["profile"]
        if profile.provider != "vllm":
            raise ValueError(f"Unsupported model provider '{profile.provider}'; only local vLLM is enabled")
        return await self._client.structured_completion(**kwargs)


class DeterministicModelClient:
    """Non-production client used for tests and local graph validation."""

    async def structured_completion(
        self,
        *,
        profile: ModelProfile,
        system_prompt: str,
        user_payload: dict[str, Any],
        max_tokens: int,
        audit_context: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        log_llm_call(
            "llm.call.completed",
            model=profile.name,
            max_tokens=max_tokens,
            **(audit_context or {}),
            duration_ms=0,
        )
        finding = user_payload.get("finding", {})
        finding_id = (
            finding.get("finding_id", "unknown finding")
            if isinstance(finding, dict)
            else getattr(finding, "finding_id", "unknown finding")
        )
        return {
            "summary": f"Local validation response for {finding_id}",
            "confidence": 0.0,
            "requires_human_review": True,
            "assumptions": ["Generated by deterministic local model mode; no external evidence was queried."],
        }
