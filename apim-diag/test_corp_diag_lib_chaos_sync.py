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


# ============================================================================
# Section D — Stage 5g.1: compute_call_batch_key + compute_report_id
# (mirrors wolfpack tests/test_extraction_cache_primitives.py)
# ============================================================================


def test_call_batch_key_is_stable_hex_of_expected_length():
    """16-char hex digest, deterministic for the same input."""
    key1 = L.compute_call_batch_key(
        {"phase": "exec", "ix": 0},
        call_type="per_phase",
        prompt_version="refined-v3",
        deployment="gpt-5.4",
        max_completion_tokens=2048,
    )
    key2 = L.compute_call_batch_key(
        {"phase": "exec", "ix": 0},
        call_type="per_phase",
        prompt_version="refined-v3",
        deployment="gpt-5.4",
        max_completion_tokens=2048,
    )
    assert key1 == key2
    assert len(key1) == 16
    assert all(c in "0123456789abcdef" for c in key1)


def test_call_batch_key_stable_across_dict_key_ordering():
    """Sort-order changes in input dict must not change the key."""
    k_a = L.compute_call_batch_key(
        {"a": 1, "b": 2, "c": 3},
        call_type="t", prompt_version="v", deployment="d", max_completion_tokens=1,
    )
    k_b = L.compute_call_batch_key(
        {"c": 3, "b": 2, "a": 1},
        call_type="t", prompt_version="v", deployment="d", max_completion_tokens=1,
    )
    assert k_a == k_b


def test_call_batch_key_sensitive_to_call_type():
    """Different call_type → different key (otherwise per_phase + bridge collide)."""
    base = dict(
        input_data={"x": 1}, prompt_version="v", deployment="d", max_completion_tokens=1,
    )
    assert L.compute_call_batch_key(call_type="per_phase", **base) \
        != L.compute_call_batch_key(call_type="bridge", **base)


def test_call_batch_key_sensitive_to_prompt_version():
    """Prompt-version change must miss cache (semantics changed)."""
    base = dict(
        input_data={"x": 1}, call_type="t", deployment="d", max_completion_tokens=1,
    )
    assert L.compute_call_batch_key(prompt_version="v1", **base) \
        != L.compute_call_batch_key(prompt_version="v2", **base)


def test_call_batch_key_sensitive_to_deployment_and_max_tokens():
    base = dict(input_data={"x": 1}, call_type="t", prompt_version="v")
    assert L.compute_call_batch_key(deployment="d1", max_completion_tokens=1, **base) \
        != L.compute_call_batch_key(deployment="d2", max_completion_tokens=1, **base)
    assert L.compute_call_batch_key(deployment="d", max_completion_tokens=1, **base) \
        != L.compute_call_batch_key(deployment="d", max_completion_tokens=2, **base)


def test_call_batch_key_input_data_change_changes_key():
    base = dict(call_type="t", prompt_version="v", deployment="d", max_completion_tokens=1)
    assert L.compute_call_batch_key(input_data={"x": 1}, **base) \
        != L.compute_call_batch_key(input_data={"x": 2}, **base)


def test_report_id_is_stable_hex_of_expected_length(tmp_path):
    """16-char hex of the file's sha256; deterministic for the same bytes."""
    p = tmp_path / "report.json"
    p.write_bytes(b'{"hello":"world"}')
    rid1 = L.compute_report_id(p)
    rid2 = L.compute_report_id(p)
    assert rid1 == rid2
    assert len(rid1) == 16
    assert all(c in "0123456789abcdef" for c in rid1)


def test_report_id_changes_when_file_content_changes(tmp_path):
    p = tmp_path / "report.json"
    p.write_bytes(b"v1")
    rid_v1 = L.compute_report_id(p)
    p.write_bytes(b"v2")
    rid_v2 = L.compute_report_id(p)
    assert rid_v1 != rid_v2


# ============================================================================
# Section E — Stage 5g.2: StatusLedger
# (mirrors wolfpack tests/test_extraction_cache_status_ledger.py)
# ============================================================================


def test_ledger_append_creates_parent_dir_and_writes_jsonl(tmp_path):
    ledger_path = tmp_path / "nested" / "ledger.jsonl"
    ledger = L.StatusLedger(path=ledger_path)
    ledger.append({"report_id": "r1", "batch_key": "bk1", "status": "ok"})
    assert ledger_path.is_file()
    rows = [json.loads(line) for line in ledger_path.read_text().splitlines() if line]
    assert len(rows) == 1
    assert rows[0]["report_id"] == "r1"
    assert rows[0]["batch_key"] == "bk1"
    assert rows[0]["status"] == "ok"
    # ts auto-injected
    assert "ts" in rows[0]


def test_ledger_append_does_not_overwrite_existing_ts(tmp_path):
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    ledger.append({"report_id": "r", "batch_key": "bk", "status": "ok", "ts": "2025-01-01T00:00:00Z"})
    row = json.loads((tmp_path / "ledger.jsonl").read_text().strip())
    assert row["ts"] == "2025-01-01T00:00:00Z"


def test_latest_per_batch_returns_last_row_per_batch_key(tmp_path):
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    ledger.append({"report_id": "r1", "batch_key": "bk1", "status": "exhausted"})
    ledger.append({"report_id": "r1", "batch_key": "bk1", "status": "ok"})
    ledger.append({"report_id": "r1", "batch_key": "bk2", "status": "ok"})
    latest = ledger.latest_per_batch("r1")
    assert set(latest.keys()) == {"bk1", "bk2"}
    assert latest["bk1"]["status"] == "ok"  # last-write-wins
    assert latest["bk2"]["status"] == "ok"


def test_latest_per_batch_filters_by_report_id(tmp_path):
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    ledger.append({"report_id": "r1", "batch_key": "bk1", "status": "ok"})
    ledger.append({"report_id": "r2", "batch_key": "bk1", "status": "exhausted"})
    assert ledger.latest_per_batch("r1")["bk1"]["status"] == "ok"
    assert ledger.latest_per_batch("r2")["bk1"]["status"] == "exhausted"
    assert "bk1" in ledger.latest_per_batch("r1")
    assert ledger.latest_per_batch("r99") == {}


def test_pending_batches_returns_only_non_ok(tmp_path):
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    ledger.append({"report_id": "r1", "batch_key": "ok_bk", "status": "ok"})
    ledger.append({"report_id": "r1", "batch_key": "exhausted_bk", "status": "exhausted"})
    ledger.append({"report_id": "r1", "batch_key": "non_transient_bk", "status": "non_transient"})
    pending = ledger.pending_batches("r1")
    assert pending == {"exhausted_bk", "non_transient_bk"}


def test_pending_batches_uses_latest_status_only(tmp_path):
    """A batch that failed then succeeded must NOT appear pending."""
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    ledger.append({"report_id": "r1", "batch_key": "bk1", "status": "exhausted"})
    ledger.append({"report_id": "r1", "batch_key": "bk1", "status": "ok"})
    assert ledger.pending_batches("r1") == set()


def test_ledger_missing_file_returns_empty(tmp_path):
    """Querying a fresh ledger that hasn't been written to is safe."""
    ledger = L.StatusLedger(path=tmp_path / "never_written.jsonl")
    assert ledger.latest_per_batch("any") == {}
    assert ledger.pending_batches("any") == set()


def test_ledger_skips_corrupt_lines(tmp_path):
    """Malformed JSON lines should be ignored, not raise."""
    p = tmp_path / "ledger.jsonl"
    p.write_text(
        '{"report_id":"r","batch_key":"bk","status":"ok"}\n'
        "not json\n"
        '{"report_id":"r","batch_key":"bk2","status":"exhausted"}\n'
    )
    ledger = L.StatusLedger(path=p)
    assert set(ledger.latest_per_batch("r").keys()) == {"bk", "bk2"}


# ============================================================================
# Section F — Stage 5g.3: write_decomposer_ledger_entry helper
# ============================================================================


def _make_ok_metric(call_type="per_phase", payload=None, error_class=None):
    """Helper: build a minimal CallMetric with one attempt."""
    metric = L.CallMetric(
        call_type=call_type,
        call_label="phase[execution][bundle=0]",
        started_at="2025-01-01T00:00:00Z",
        final_status="ok",
        payload=payload or {},
    )
    metric.attempts.append(L.CallAttempt(
        attempt_number=1,
        started_at="2025-01-01T00:00:00Z",
        elapsed_s=1.5,
        status="ok",
        error_class=error_class,
        error_message=None,
    ))
    return metric


def test_write_ledger_entry_noop_when_ledger_is_none(tmp_path):
    """No-op when ledger is None (opt-in: not configured)."""
    metric = _make_ok_metric()
    L.write_decomposer_ledger_entry(
        ledger=None, report_id="r1", run_id="run-1",
        call_type="per_phase", batch_key="bk1", context_label="exec",
        metric=metric,
    )
    # No exception raised, no file created — passing without error proves it.


def test_write_ledger_entry_noop_when_report_id_is_none(tmp_path):
    """No-op when report_id is None (caller didn't compute one)."""
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    metric = _make_ok_metric()
    L.write_decomposer_ledger_entry(
        ledger=ledger, report_id=None, run_id="run-1",
        call_type="per_phase", batch_key="bk1", context_label="exec",
        metric=metric,
    )
    assert not (tmp_path / "ledger.jsonl").is_file()


def test_write_ledger_entry_writes_ok_status(tmp_path):
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    metric = _make_ok_metric(payload={"trailheads_produced": 4, "phase": "execution"})
    L.write_decomposer_ledger_entry(
        ledger=ledger, report_id="r1", run_id="run-1",
        call_type="per_phase", batch_key="bk1", context_label="execution",
        metric=metric,
    )
    rows = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines() if line]
    assert len(rows) == 1
    row = rows[0]
    assert row["report_id"] == "r1"
    assert row["batch_key"] == "bk1"
    assert row["status"] == "ok"
    assert row["run_id"] == "run-1"
    assert row["call_type"] == "per_phase"
    assert row["anchors"] == ["execution"]
    assert row["behaviors_count"] == 4
    assert row["error_class"] is None


def test_write_ledger_entry_carries_error_class_on_failure(tmp_path):
    """When metric.final_status != ok, error_class from last attempt."""
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    metric = L.CallMetric(
        call_type="per_phase", call_label="x", started_at="now",
        final_status="exhausted",
    )
    metric.attempts.append(L.CallAttempt(
        attempt_number=1, started_at="now", elapsed_s=1.0,
        status="transient_error", error_class="http_504",
        error_message="gateway",
    ))
    L.write_decomposer_ledger_entry(
        ledger=ledger, report_id="r", run_id="run", call_type="per_phase",
        batch_key="bk", context_label="exec", metric=metric,
    )
    row = json.loads((tmp_path / "ledger.jsonl").read_text().strip())
    assert row["status"] == "exhausted"
    assert row["error_class"] == "http_504"


def test_write_ledger_entry_defaults_run_id_to_unknown(tmp_path):
    """If run_id is None, store 'unknown' rather than null."""
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    metric = _make_ok_metric()
    L.write_decomposer_ledger_entry(
        ledger=ledger, report_id="r", run_id=None, call_type="per_phase",
        batch_key="bk", context_label="exec", metric=metric,
    )
    row = json.loads((tmp_path / "ledger.jsonl").read_text().strip())
    assert row["run_id"] == "unknown"


def test_write_ledger_entry_handles_missing_trailheads_produced(tmp_path):
    """payload without trailheads_produced → behaviors_count=0, not KeyError."""
    ledger = L.StatusLedger(path=tmp_path / "ledger.jsonl")
    metric = _make_ok_metric(payload={"phase": "lateral"})
    L.write_decomposer_ledger_entry(
        ledger=ledger, report_id="r", run_id="run", call_type="bridge",
        batch_key="bk", context_label="bridges", metric=metric,
    )
    row = json.loads((tmp_path / "ledger.jsonl").read_text().strip())
    assert row["behaviors_count"] == 0


# ============================================================================
# Section G — Stage 5g.4: per_phase cache (parsed-output flavor)
# Diag's per_phase returns parsed ChatRecipeGeneratorOutput directly, so the
# cache stores pydantic model_dump() (simpler than wolfpack's _Attempt cache).
# ============================================================================


def _make_tiny_pydantic_model():
    """Small pydantic model for cache round-trip tests (independent of
    the heavy ChatRecipeGeneratorOutput)."""
    from pydantic import BaseModel

    class Tiny(BaseModel):
        phase: str
        count: int
        items: list[str]
    return Tiny


def test_read_cached_returns_none_on_miss(tmp_path):
    Tiny = _make_tiny_pydantic_model()
    got = L.read_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r1", batch_key="bk1",
        output_model=Tiny,
    )
    assert got is None


def test_write_then_read_round_trips_parsed_model(tmp_path):
    Tiny = _make_tiny_pydantic_model()
    original = Tiny(phase="exec", count=3, items=["a", "b", "c"])
    L.write_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r1", batch_key="bk1",
        parsed=original,
    )
    got = L.read_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r1", batch_key="bk1",
        output_model=Tiny,
    )
    assert got is not None
    assert got.phase == "exec"
    assert got.count == 3
    assert got.items == ["a", "b", "c"]


def test_write_creates_report_id_subdir(tmp_path):
    Tiny = _make_tiny_pydantic_model()
    L.write_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r-abc", batch_key="bk",
        parsed=Tiny(phase="p", count=0, items=[]),
    )
    assert (tmp_path / "r-abc").is_dir()
    assert (tmp_path / "r-abc" / "bk.json").is_file()


def test_write_uses_atomic_tmp_then_replace(tmp_path):
    """Cache write should not leave a .tmp file behind on success."""
    Tiny = _make_tiny_pydantic_model()
    L.write_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r", batch_key="bk",
        parsed=Tiny(phase="p", count=0, items=[]),
    )
    files = list((tmp_path / "r").iterdir())
    assert [f.name for f in files] == ["bk.json"]


def test_read_returns_none_on_corrupt_json(tmp_path):
    """Corrupt cache entry must be treated as a miss, not raise."""
    Tiny = _make_tiny_pydantic_model()
    (tmp_path / "r1").mkdir()
    (tmp_path / "r1" / "bk1.json").write_text("not json {{")
    got = L.read_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r1", batch_key="bk1",
        output_model=Tiny,
    )
    assert got is None


def test_read_returns_none_on_model_validation_failure(tmp_path):
    """Cache entry that doesn't match the expected model → treated as miss."""
    Tiny = _make_tiny_pydantic_model()
    (tmp_path / "r1").mkdir()
    (tmp_path / "r1" / "bk1.json").write_text('{"unrelated": "schema"}')
    got = L.read_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r1", batch_key="bk1",
        output_model=Tiny,
    )
    assert got is None


def test_isolation_by_report_id(tmp_path):
    """Different report_ids must not see each other's entries."""
    Tiny = _make_tiny_pydantic_model()
    L.write_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r1", batch_key="bk",
        parsed=Tiny(phase="p1", count=1, items=[]),
    )
    got = L.read_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r2", batch_key="bk",
        output_model=Tiny,
    )
    assert got is None


# ============================================================================
# Section H — Stage 5g.5: cached_per_phase_dispatch
# (testable seam: encapsulates cache-check → invoke → cache-write so the
# wiring inside invoke_per_phase is one line.)
# ============================================================================


def test_dispatch_no_cache_root_calls_invoke_and_returns_fresh(tmp_path):
    """When cache_root is None, dispatch always invokes (and never reads/writes)."""
    Tiny = _make_tiny_pydantic_model()
    invoke_count = {"n": 0}

    def invoke_fn():
        invoke_count["n"] += 1
        return Tiny(phase="exec", count=1, items=["x"])

    result, source = L.cached_per_phase_dispatch(
        batch_key="bk1", report_id="r1", cache_root=None,
        output_model=Tiny, invoke_fn=invoke_fn,
    )
    assert result.phase == "exec"
    assert source == "fresh"
    assert invoke_count["n"] == 1


def test_dispatch_no_report_id_calls_invoke_and_returns_fresh(tmp_path):
    """When report_id is None, dispatch also bypasses cache."""
    Tiny = _make_tiny_pydantic_model()

    result, source = L.cached_per_phase_dispatch(
        batch_key="bk", report_id=None, cache_root=tmp_path,
        output_model=Tiny,
        invoke_fn=lambda: Tiny(phase="x", count=0, items=[]),
    )
    assert source == "fresh"
    assert result.phase == "x"


def test_dispatch_cache_miss_invokes_and_writes(tmp_path):
    """First call: cache miss → invoke → cache write."""
    Tiny = _make_tiny_pydantic_model()

    result, source = L.cached_per_phase_dispatch(
        batch_key="bk1", report_id="r1", cache_root=tmp_path,
        output_model=Tiny,
        invoke_fn=lambda: Tiny(phase="execution", count=2, items=["a", "b"]),
    )
    assert source == "fresh"
    assert result.phase == "execution"
    # The write happened — second dispatch with same key should hit cache.
    assert (tmp_path / "r1" / "bk1.json").is_file()


def test_dispatch_cache_hit_skips_invoke(tmp_path):
    """Second call with same key: cache hit → no invoke."""
    Tiny = _make_tiny_pydantic_model()
    # Prime cache
    L.write_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r1", batch_key="bk1",
        parsed=Tiny(phase="cached", count=99, items=["primed"]),
    )

    invoke_count = {"n": 0}
    def invoke_fn():
        invoke_count["n"] += 1
        raise AssertionError("invoke must not be called on cache hit")

    result, source = L.cached_per_phase_dispatch(
        batch_key="bk1", report_id="r1", cache_root=tmp_path,
        output_model=Tiny, invoke_fn=invoke_fn,
    )
    assert source == "cache"
    assert invoke_count["n"] == 0
    assert result.phase == "cached"
    assert result.count == 99


def test_dispatch_failed_invoke_returns_none_and_does_not_cache(tmp_path):
    """invoke_fn returning None (LLM failure) must not write cache."""
    Tiny = _make_tiny_pydantic_model()
    result, source = L.cached_per_phase_dispatch(
        batch_key="bk", report_id="r", cache_root=tmp_path,
        output_model=Tiny, invoke_fn=lambda: None,
    )
    assert result is None
    assert source == "failed"
    # No file written.
    assert not (tmp_path / "r" / "bk.json").exists()


def test_dispatch_different_batch_keys_independent(tmp_path):
    """Cache is per (report_id, batch_key) — different keys are independent."""
    Tiny = _make_tiny_pydantic_model()
    L.write_cached_per_phase_parsed(
        cache_root=tmp_path, report_id="r1", batch_key="bk_a",
        parsed=Tiny(phase="A", count=1, items=[]),
    )
    # bk_b is fresh:
    result, source = L.cached_per_phase_dispatch(
        batch_key="bk_b", report_id="r1", cache_root=tmp_path,
        output_model=Tiny,
        invoke_fn=lambda: Tiny(phase="B", count=2, items=[]),
    )
    assert source == "fresh"
    assert result.phase == "B"
