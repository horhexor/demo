"""Tests for chaos primitives synced from wolfpack into corp_diag_lib.

Each test block mirrors a wolfpack test file. Verifying that diag and
wolfpack classify errors the same way is what makes the single-file
diag a faithful corp-validation tool.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import corp_diag_lib as L


# ============================================================================
# Section A — classify_error: openai SDK + azure-identity exception types
# (mirrors wolfpack tests/test_classify_error_exception_types.py)
# ============================================================================


def _openai_internal_server_error():
    import httpx
    from openai import InternalServerError
    req = httpx.Request("POST", "http://x/chat/completions")
    resp = httpx.Response(500, request=req)
    return InternalServerError("Internal Server Error", response=resp, body={})


def _openai_rate_limit_error():
    import httpx
    from openai import RateLimitError
    req = httpx.Request("POST", "http://x/chat/completions")
    resp = httpx.Response(429, request=req)
    return RateLimitError("Rate limit reached", response=resp, body={})


def _openai_api_timeout_error():
    import httpx
    from openai import APITimeoutError
    req = httpx.Request("POST", "http://x/chat/completions")
    return APITimeoutError(req)


def _openai_api_connection_error():
    import httpx
    from openai import APIConnectionError
    req = httpx.Request("POST", "http://x/chat/completions")
    return APIConnectionError(request=req)


def _openai_not_found_error():
    import httpx
    from openai import NotFoundError
    req = httpx.Request("POST", "http://x/chat/completions")
    resp = httpx.Response(404, request=req)
    return NotFoundError("Not found", response=resp, body={})


def test_internal_server_error_classified_as_http_500():
    assert L.classify_error(_openai_internal_server_error()) == "http_500"
    assert "http_500" in L._TRANSIENT_CLASSES


def test_rate_limit_error_classified_as_rate_limit():
    assert L.classify_error(_openai_rate_limit_error()) == "rate_limit"
    assert "rate_limit" in L._TRANSIENT_CLASSES


def test_api_timeout_error_classified_as_timeout():
    assert L.classify_error(_openai_api_timeout_error()) == "timeout"


def test_api_connection_error_classified_as_connection():
    assert L.classify_error(_openai_api_connection_error()) == "connection"


def test_not_found_error_stays_non_transient():
    cls = L.classify_error(_openai_not_found_error())
    assert cls not in L._TRANSIENT_CLASSES, (
        f"NotFoundError classified as {cls!r}, which is in _TRANSIENT_CLASSES "
        f"— diag would retry a 404 forever. That's wrong."
    )


def test_credential_unavailable_error_classified_as_token_acquisition_failed():
    """Wolfpack-side injection type. Diag must classify same way for cross-tool consistency."""
    from azure.identity import CredentialUnavailableError
    cls = L.classify_error(CredentialUnavailableError("DefaultAzureCredential chain failed: ..."))
    assert cls == "token_acquisition_failed", f"expected token_acquisition_failed, got {cls!r}"
    assert "token_acquisition_failed" in L._TRANSIENT_CLASSES


def test_client_authentication_error_classified_as_token_acquisition_failed():
    """The exception type diag's own make_chaotic_token_provider raises for
    auth_error chaos. Must be classified as transient so tenacity retries."""
    from azure.core.exceptions import ClientAuthenticationError
    assert L.classify_error(ClientAuthenticationError("Authentication failed")) == "token_acquisition_failed"


def test_existing_string_patterns_still_work():
    """Don't regress the existing substring matchers."""
    assert L.classify_error(Exception("HTTP 504 from upstream")) == "http_504"
    assert L.classify_error(Exception("application gateway timeout")) == "gateway_504_html"
    assert L.classify_error(Exception("connection reset by peer")) == "transport_disconnect"
    assert L.classify_error(Exception("plain old garbage")) == "non_transient"


# ============================================================================
# Section B — max_retries=0 on ChatOpenAI so tenacity is sole retry layer
# (mirrors wolfpack tests/test_llm_resilience_disable_sdk_retry.py)
# ============================================================================


def _fake_config():
    cfg = L.Config()
    cfg.auth.endpoint = "http://127.0.0.1:9999"
    cfg.auth.deployment = "gpt-5-4"
    cfg.auth.credential = "DefaultAzureCredential"
    cfg.auth.scope = "https://ai.azure.com/.default"
    cfg.llm.request_timeout_s = 60
    cfg.llm.max_completion_tokens = 1024
    return cfg


def test_build_openai_compat_client_passes_max_retries_zero():
    """ChatOpenAI must be constructed with max_retries=0 so openai SDK doesn't
    silently retry below tenacity, hiding chaos events from CallMetric."""
    cfg = _fake_config()

    fake_token_provider = MagicMock(return_value="dummy-token")
    with patch.object(L, "build_azure_token_provider", return_value=fake_token_provider), \
         patch.object(L, "ChatOpenAI") as mocked:
        L.build_openai_compat_client(cfg)

    assert mocked.called, "ChatOpenAI should have been called"
    kwargs = mocked.call_args.kwargs
    assert kwargs.get("max_retries") == 0, (
        f"expected max_retries=0 to silence openai SDK's silent retries; "
        f"got kwargs keys={sorted(kwargs.keys())}, max_retries={kwargs.get('max_retries')!r}"
    )


# ============================================================================
# Section C — _salvage_truncated_json_array
# (mirrors wolfpack/pipeline/deepagent_runtime.py:230 brace-balance salvage)
# ============================================================================


def test_salvage_returns_full_list_on_complete_input():
    """Already-complete JSON: round-trips with empty remaining."""
    text = '[{"a": 1}, {"b": 2}]'
    items, remaining = L._salvage_truncated_json_array(text)
    assert items == [{"a": 1}, {"b": 2}]
    assert remaining == ""


def test_salvage_recovers_prefix_when_truncated_mid_item():
    """Classic truncation: 2 complete items + a half-emitted third."""
    text = '[{"a": 1}, {"b": 2}, {"c":'
    items, remaining = L._salvage_truncated_json_array(text)
    assert items == [{"a": 1}, {"b": 2}]
    # remaining includes the unfinished item so caller can decide to retry
    assert '{"c":' in remaining


def test_salvage_recovers_prefix_when_truncated_between_items():
    """Truncation right after a comma, before the next object opens."""
    text = '[{"a": 1}, {"b": 2}, '
    items, _ = L._salvage_truncated_json_array(text)
    assert items == [{"a": 1}, {"b": 2}]


def test_salvage_returns_empty_when_no_array_found():
    text = 'this is not json at all'
    items, remaining = L._salvage_truncated_json_array(text)
    assert items == []
    assert remaining == text


def test_salvage_returns_empty_when_only_array_opener():
    text = '['
    items, _ = L._salvage_truncated_json_array(text)
    assert items == []


def test_salvage_handles_quoted_brackets_in_strings():
    """Strings inside items may contain { } [ ] — depth tracker must ignore them."""
    text = '[{"path": "a/[b]/{c}/d"}, {"x": 2},'
    items, _ = L._salvage_truncated_json_array(text)
    assert items == [{"path": "a/[b]/{c}/d"}, {"x": 2}]


def test_salvage_handles_escaped_quotes_in_strings():
    text = r'[{"q": "he said \"hi\""}, {"y":'
    items, _ = L._salvage_truncated_json_array(text)
    assert items == [{"q": 'he said "hi"'}]


def test_salvage_handles_nested_objects():
    """Nested object closing depths shouldn't be mistaken for item-end."""
    text = '[{"a": {"b": {"c": 1}}}, {"d": 2}, {"oops":'
    items, _ = L._salvage_truncated_json_array(text)
    assert items == [{"a": {"b": {"c": 1}}}, {"d": 2}]
