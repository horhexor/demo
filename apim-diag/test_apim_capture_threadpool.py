"""Stage 7.1 — TDD for APIM-header capture across the structured-output threadpool.

Root cause: langchain_openai's `with_structured_output(include_raw=True)` uses
RunnableParallel which dispatches the LLM call onto a ThreadPoolExecutor
worker. Our previous thread-local-based capture lived on the worker thread;
the caller (which reads `take_last_apim_capture()` on the main thread) saw
NULL.

Fix: move capture state to a contextvar holding a mutable dict. langchain's
threadpool executor uses `contextvars.copy_context().run()`, which snapshots
the parent's contextvar values into the worker. Because the contextvar's
value is a mutable dict (not a primitive), mutations made by the worker
hooks are visible to the parent through the same dict reference.

These tests pin that behavior so it stays fixed.
"""
from __future__ import annotations

import httpx
import json
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

import corp_diag_lib as L


class _Out(BaseModel):
    x: int


def _build_fake_http_client():
    """An httpx.Client wired with the lib's diag hooks + a fake transport that
    returns a tool_call-shaped response with realistic APIM headers."""

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            return httpx.Response(
                200,
                content=json.dumps({
                    "id": "resp-id",
                    "choices": [{
                        "message": {
                            "content": "",
                            "role": "assistant",
                            "tool_calls": [{
                                "id": "c",
                                "type": "function",
                                "function": {"name": "_Out", "arguments": '{"x": 1}'},
                            }],
                        },
                        "finish_reason": "tool_calls",
                        "index": 0,
                    }],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    "model": "gpt-4",
                    "object": "chat.completion",
                }).encode(),
                headers={
                    "content-type": "application/json",
                    "apim-request-id": "test-apim-id-12345",
                    "x-request-id": "test-x-request-id",
                    "x-ms-client-request-id": "test-cid-67890",
                    "x-ratelimit-remaining-tokens": "999000",
                    "x-ratelimit-remaining-requests": "49999",
                    "x-ratelimit-limit-tokens": "1000000",
                    "x-ratelimit-limit-requests": "50000",
                    "request-context": "test-context",
                    "date": "Mon, 01 Jan 2026 12:00:00 GMT",
                },
            )

    return httpx.Client(
        transport=T(),
        event_hooks={
            "request": [L._diag_request_hook],
            "response": [L._diag_response_hook],
        },
    )


def _build_llm():
    return ChatOpenAI(
        model="gpt-4",
        base_url="http://fake-test/",
        api_key="dummy",
        max_completion_tokens=1024,
        http_client=_build_fake_http_client(),
    )


def test_apim_capture_on_plain_invoke():
    """Baseline: hooks populate state when LLM is invoked directly (no structured)."""
    llm = _build_llm()
    L.reset_thread_apim_state()
    llm.invoke([HumanMessage("hi")])
    cap = L.take_last_apim_capture()
    assert cap["apim_request_id"] == "test-apim-id-12345"
    assert cap["x_request_id"] == "test-x-request-id"
    assert cap["ratelimit_remaining_tokens"] == 999000


def test_apim_capture_on_structured_output_with_include_raw():
    """Critical: hooks must populate state even when langchain uses a threadpool."""
    llm = _build_llm()
    L.reset_thread_apim_state()
    llm.with_structured_output(_Out, include_raw=True, method="function_calling").invoke(
        [HumanMessage("hi")]
    )
    cap = L.take_last_apim_capture()
    assert cap["apim_request_id"] == "test-apim-id-12345", (
        f"APIM header lost across threadpool boundary: {cap}"
    )
    assert cap["x_request_id"] == "test-x-request-id"
    assert cap["ratelimit_remaining_tokens"] == 999000
    assert cap["http_status"] == 200


def test_apim_capture_on_structured_output_after_model_copy():
    """The Stage 6 pattern (model_copy + with_structured_output) must also capture."""
    llm = _build_llm()
    L.reset_thread_apim_state()
    copied = llm.model_copy(update={"max_tokens": 2048})
    copied.with_structured_output(_Out, include_raw=True, method="function_calling").invoke(
        [HumanMessage("hi")]
    )
    cap = L.take_last_apim_capture()
    assert cap["apim_request_id"] == "test-apim-id-12345"


def test_client_request_id_injected_into_request_header():
    """The hook injects a UUID as x-ms-client-request-id and records it in state."""
    llm = _build_llm()
    L.reset_thread_apim_state()
    llm.with_structured_output(_Out, include_raw=True, method="function_calling").invoke(
        [HumanMessage("hi")]
    )
    cap = L.take_last_apim_capture()
    assert cap["client_request_id"] is not None
    # 32-char hex from uuid4().hex
    assert len(cap["client_request_id"]) == 32


def test_reset_between_calls_isolates_state():
    """Sequential calls don't leak state if reset is called between them."""
    llm = _build_llm()
    L.reset_thread_apim_state()
    llm.invoke([HumanMessage("hi")])
    cap1 = L.take_last_apim_capture()

    L.reset_thread_apim_state()
    cap2 = L.take_last_apim_capture()  # before any invoke
    assert cap2["apim_request_id"] is None
    assert cap2["client_request_id"] is None
