"""TDD tests for apim_mimic logging additions.

Each test exercises one pure function. We TDD piece-by-piece so we never
end up with untested code in apim_mimic.py.

Run from the apim-mimic directory:
    pytest test_apim_mimic.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import apim_mimic as M


# ============================================================================
# Chunk 1: _build_request_trace — builds the JSONL record dict
# ============================================================================


def test_build_request_trace_success_path():
    """Forwarded-to-Foundry success: no chaos, foundry returned 200."""
    trace = M._build_request_trace(
        request_id="ab123456",
        apim_request_id="4f2c0000-aaaa-bbbb-cccc-1234567890ab",
        client_request_id="82fef1a924f440e59b57a68cd2b52b82",
        method="POST",
        path="/chat/completions",
        deployment="gpt-5-4",
        body_kb_in=1.3,
        user_agent="python-httpx/0.28.1",
        front_door_delay_ms=12000,
        chaos_mode=None,
        chaos_delay_s=None,
        foundry_status=200,
        foundry_body_size_out=4096,
        final_status=200,
        elapsed_ms=12150,
        error=None,
        ts_iso="2026-05-22T18:00:00.000Z",
    )

    # Every field must round-trip through JSONL — no datetimes, no objects.
    json.dumps(trace)  # raises if non-serializable

    assert trace["ts"] == "2026-05-22T18:00:00.000Z"
    assert trace["request_id"] == "ab123456"
    assert trace["apim_request_id"] == "4f2c0000-aaaa-bbbb-cccc-1234567890ab"
    assert trace["client_request_id"] == "82fef1a924f440e59b57a68cd2b52b82"
    assert trace["method"] == "POST"
    assert trace["path"] == "/chat/completions"
    assert trace["deployment"] == "gpt-5-4"
    assert trace["body_kb_in"] == 1.3
    assert trace["user_agent"] == "python-httpx/0.28.1"
    assert trace["front_door_delay_ms"] == 12000
    assert trace["chaos_mode"] is None
    assert trace["chaos_delay_s"] is None
    assert trace["foundry_status"] == 200
    assert trace["foundry_body_size_out"] == 4096
    assert trace["final_status"] == 200
    assert trace["elapsed_ms"] == 12150
    assert trace["error"] is None


def test_build_request_trace_chaos_injected():
    """Chaos path: foundry never called; final_status is the injected one."""
    trace = M._build_request_trace(
        request_id="cd789012",
        apim_request_id="ffff0000-1111-2222-3333-444455556666",
        client_request_id="not-set",
        method="POST",
        path="/chat/completions",
        deployment="gpt-5-4",
        body_kb_in=1.3,
        user_agent="python-httpx/0.28.1",
        front_door_delay_ms=12000,
        chaos_mode="html_gateway_504",
        chaos_delay_s=30.1,
        foundry_status=None,
        foundry_body_size_out=None,
        final_status=504,
        elapsed_ms=42150,
        error="chaos-injected:html_gateway_504",
        ts_iso="2026-05-22T18:00:00.000Z",
    )

    json.dumps(trace)  # must serialize

    assert trace["chaos_mode"] == "html_gateway_504"
    assert trace["chaos_delay_s"] == 30.1
    assert trace["foundry_status"] is None
    assert trace["foundry_body_size_out"] is None
    assert trace["final_status"] == 504
    assert trace["error"] == "chaos-injected:html_gateway_504"


def test_build_request_trace_foundry_error():
    """Foundry forwarding failed (e.g. network error). final_status=502."""
    trace = M._build_request_trace(
        request_id="ef345678",
        apim_request_id="aaaa1111-2222-3333-4444-555566667777",
        client_request_id="not-set",
        method="POST",
        path="/chat/completions",
        deployment="gpt-5-4",
        body_kb_in=1.3,
        user_agent="python-httpx/0.28.1",
        front_door_delay_ms=0,
        chaos_mode=None,
        chaos_delay_s=None,
        foundry_status=None,
        foundry_body_size_out=None,
        final_status=502,
        elapsed_ms=1500,
        error="ConnectError: foundry unreachable",
        ts_iso="2026-05-22T18:00:00.000Z",
    )

    json.dumps(trace)

    assert trace["final_status"] == 502
    assert trace["error"] == "ConnectError: foundry unreachable"
    assert trace["chaos_mode"] is None


# ============================================================================
# Chunk 2: log path resolver, authorization redactor, log prefix formatter
# ============================================================================


def test_resolve_log_paths_default_layout(tmp_path: Path):
    """Given a base logs dir and a date string, returns the canonical paths."""
    paths = M._resolve_log_paths(tmp_path, date_str="2026-05-22")
    assert paths.log_file == tmp_path / "apim_mimic-2026-05-22.log"
    assert paths.jsonl_file == tmp_path / "requests-2026-05-22.jsonl"
    assert paths.bodies_dir == tmp_path / "bodies"


def test_resolve_log_paths_creates_parent_dir(tmp_path: Path):
    """Creates logs_dir if it doesn't exist (so callers don't have to)."""
    logs_dir = tmp_path / "logs-not-yet-here"
    assert not logs_dir.exists()
    paths = M._resolve_log_paths(logs_dir, date_str="2026-05-22")
    assert logs_dir.exists()
    assert paths.log_file.parent == logs_dir


def test_redact_authorization_bearer_token():
    """Bearer tokens are masked except for first few chars to keep grep-ability."""
    out = M._redact_authorization("Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.long-token-here")
    assert out.startswith("Bearer eyJ")  # first 3 chars after prefix kept
    assert "long-token-here" not in out
    assert "[redacted" in out


def test_redact_authorization_no_bearer():
    """Non-Bearer values are still redacted but tagged so we know."""
    out = M._redact_authorization("Basic dXNlcjpwYXNz")
    assert "dXNlcjpwYXNz" not in out
    assert "[redacted" in out


def test_redact_authorization_none():
    """None auth returns a stable sentinel, not a crash."""
    assert M._redact_authorization(None) == "(no-auth)"


def test_format_log_prefix_short_apim_id():
    """Format: [req=<8> apim-id=<first8>..<last4>] — compact, greppable."""
    out = M._format_log_prefix(
        request_id="ab123456",
        apim_request_id="4f2c0000-aaaa-bbbb-cccc-1234567890ab",
    )
    assert "req=ab123456" in out
    assert "4f2c0000" in out  # first 8 chars of apim-id present
    assert "90ab" in out      # last 4 chars present
    assert out.startswith("[") and out.endswith("]")


def test_format_log_prefix_handles_missing_apim_id():
    """If APIM ID hasn't been generated yet (early in handler), don't blow up."""
    out = M._format_log_prefix(request_id="ab123456", apim_request_id=None)
    assert "req=ab123456" in out
    assert "apim-id=-" in out  # explicit unset marker


# ============================================================================
# Chunk 3: body capture writer
# ============================================================================


def test_write_body_capture_writes_file_with_predictable_name(tmp_path: Path):
    """File pattern: <bodies_dir>/<request_id>-{in,out}.<ext>"""
    target = M._write_body_capture(
        bodies_dir=tmp_path,
        request_id="ab123456",
        kind="in",
        content=b'{"model": "gpt-5-4"}',
        content_type="application/json",
    )
    assert target == tmp_path / "ab123456-in.json"
    assert target.read_bytes() == b'{"model": "gpt-5-4"}'


def test_write_body_capture_creates_bodies_dir_if_missing(tmp_path: Path):
    """The handler may pass a not-yet-existing dir; writer must create it."""
    bodies_dir = tmp_path / "bodies-fresh"
    assert not bodies_dir.exists()
    target = M._write_body_capture(
        bodies_dir=bodies_dir,
        request_id="ab123456",
        kind="out",
        content=b'{"choices": []}',
        content_type="application/json",
    )
    assert bodies_dir.is_dir()
    assert target == bodies_dir / "ab123456-out.json"


def test_write_body_capture_picks_extension_from_content_type(tmp_path: Path):
    """text/html content types should get .html, plain text gets .txt."""
    html = M._write_body_capture(
        bodies_dir=tmp_path, request_id="cd789012", kind="out",
        content=b"<html><body>504</body></html>", content_type="text/html",
    )
    assert html.suffix == ".html"

    plain = M._write_body_capture(
        bodies_dir=tmp_path, request_id="ef345678", kind="out",
        content=b"plain error", content_type="text/plain",
    )
    assert plain.suffix == ".txt"


def test_write_body_capture_falls_back_to_bin_for_unknown_types(tmp_path: Path):
    """Unrecognized content-types → .bin so we never lose data."""
    target = M._write_body_capture(
        bodies_dir=tmp_path, request_id="ab123456", kind="in",
        content=b"\x00\x01\x02binary", content_type="application/x-protobuf",
    )
    assert target.suffix == ".bin"
    assert target.read_bytes() == b"\x00\x01\x02binary"


# ============================================================================
# Chunk 4: shutdown summary text builder
# ============================================================================


def test_shutdown_summary_text_includes_counters_and_paths(tmp_path: Path):
    counters = M.RequestCounters(
        served=29,
        chaos_injected=2,
        foundry_errors=0,
        non_2xx_returned=2,
    )
    paths = M.LogPaths(
        log_file=tmp_path / "apim_mimic-2026-05-22.log",
        jsonl_file=tmp_path / "requests-2026-05-22.jsonl",
        bodies_dir=tmp_path / "bodies",
    )
    text = M._shutdown_summary_text(counters=counters, runtime_s=123.4, paths=paths)
    assert "29" in text  # served
    assert "2" in text   # chaos / non_2xx
    assert "123.4" in text or "123" in text  # runtime
    assert str(paths.log_file) in text
    assert str(paths.jsonl_file) in text


def test_shutdown_summary_text_renders_three_contiguous_bars(tmp_path: Path):
    """The summary should have exactly THREE 78-= horizontal rules (top,
    under-title, bottom). The earlier ``\"\\n\" \"=\" * 78`` typo produced 78
    instances of ``\\n=`` for the first bar — runs of length 1 — but still
    contained a 78-= second bar, so an ``in`` check wouldn't catch it. Count
    bars instead."""
    counters = M.RequestCounters(served=1, chaos_injected=1, foundry_errors=0, non_2xx_returned=1)
    paths = M.LogPaths(
        log_file=tmp_path / "a.log",
        jsonl_file=tmp_path / "b.jsonl",
        bodies_dir=tmp_path / "bodies",
    )
    text = M._shutdown_summary_text(counters=counters, runtime_s=1.0, paths=paths)
    import re
    runs_of_78 = [m for m in re.finditer(r"=+", text) if len(m.group()) == 78]
    assert len(runs_of_78) == 3, (
        f"expected 3 contiguous 78-= bars, got {len(runs_of_78)}. "
        f"All = runs: {[len(m.group()) for m in re.finditer('=+', text)]}"
    )


def test_shutdown_summary_text_handles_zero_requests(tmp_path: Path):
    """No-traffic shutdown shouldn't divide-by-zero or crash."""
    counters = M.RequestCounters(served=0, chaos_injected=0, foundry_errors=0, non_2xx_returned=0)
    paths = M.LogPaths(
        log_file=tmp_path / "a.log",
        jsonl_file=tmp_path / "b.jsonl",
        bodies_dir=tmp_path / "bodies",
    )
    text = M._shutdown_summary_text(counters=counters, runtime_s=5.0, paths=paths)
    assert "0" in text  # served=0 visible


# ============================================================================
# Chunk 5: JSONL emitter + handler integration
# ============================================================================


def test_emit_request_trace_appends_one_jsonl_line(tmp_path: Path):
    """Writing 3 traces → 3 lines, each round-trips through json.loads."""
    jsonl_path = tmp_path / "requests.jsonl"
    for i in range(3):
        trace = M._build_request_trace(
            request_id=f"r{i}",
            apim_request_id=f"aaa{i}",
            client_request_id="cc",
            method="POST",
            path="/chat/completions",
            deployment="gpt-5-4",
            body_kb_in=0.5,
            user_agent="ua",
            front_door_delay_ms=0,
            chaos_mode=None,
            chaos_delay_s=None,
            foundry_status=200,
            foundry_body_size_out=10,
            final_status=200,
            elapsed_ms=10,
            error=None,
            ts_iso="2026-05-22T00:00:00Z",
        )
        M._emit_request_trace(trace, jsonl_path)

    lines = jsonl_path.read_text().splitlines()
    assert len(lines) == 3
    decoded = [json.loads(ln) for ln in lines]
    assert [d["request_id"] for d in decoded] == ["r0", "r1", "r2"]


def test_disconnect_chaos_does_not_raise_through_fastapi(tmp_path: Path):
    """The ``disconnect`` chaos mode used to ``raise ConnectionError`` which
    Starlette has no handler for, surfacing as a full 500 stack trace in the
    mimic console. After the fix, the handler should return a response that
    simulates a wire-level disconnect (StreamingResponse that aborts mid-stream)
    instead of letting an unhandled exception propagate.

    We can't easily observe TCP-level disconnect through TestClient (in-process
    ASGI), so we assert the response either:
      - succeeds in TestClient with a partial/empty body and a marker indicating
        the disconnect was simulated, OR
      - raises a transport-flavored exception (RemoteProtocolError, etc.) —
        NOT a generic Python ConnectionError leaking out of the handler.
    """
    from fastapi.testclient import TestClient

    config = M.MimicConfig(
        host="127.0.0.1", port=0,
        foundry_endpoint="http://unused.invalid",
        api_version="2024-12-01-preview",
        load_mode=None, delay_min_ms=0, delay_max_ms=0,
        failure_rate=1.0,
        failure_mode="disconnect",
        seed=42, verbose=False,
        rate_limit=M.RateLimits(),
        # Override the band so the test isn't a 2-minute sleep:
        failure_bands={"disconnect": M.FailureBand(min_s=0.01, max_s=0.05)},
        load_presets={},
    )
    config.logs_dir = str(tmp_path)
    config.capture_bodies = False
    M._init_state(config)
    M._setup_logging(verbose=False, log_file=M._state.log_paths.log_file)

    client = TestClient(M.app, raise_server_exceptions=False)
    resp = client.post(
        "/chat/completions",
        headers={"Authorization": "Bearer t", "Content-Type": "application/json"},
        json={"model": "gpt-5-4", "messages": []},
    )

    # The bug signature: Starlette's unhandled-exception fallback returns
    # 500 with body "Internal Server Error" (plain text). After the fix the
    # disconnect chaos should be HANDLED — returning an empty body, a partial
    # body, or a deliberate 502, but never that fallback signature.
    body_text = (resp.text or "").strip()
    is_starlette_500_fallback = (
        resp.status_code == 500 and body_text == "Internal Server Error"
    )
    assert not is_starlette_500_fallback, (
        f"got Starlette's unhandled-exception fallback (500 + 'Internal Server Error'); "
        f"means ConnectionError still propagates out of the handler. "
        f"Expected an intentional disconnect simulation."
    )


def test_handler_emits_trace_and_log_on_chaos(tmp_path: Path, monkeypatch):
    """End-to-end: a single /chat/completions call with chaos=1.0 produces
    a JSONL line, a log line, and (with --capture-bodies on) two body files.

    We don't hit Foundry — chaos is set to ``auth_error`` so the handler
    short-circuits before forwarding."""
    from fastapi.testclient import TestClient

    config = M.MimicConfig(
        host="127.0.0.1",
        port=0,
        foundry_endpoint="http://unused.invalid",
        api_version="2024-12-01-preview",
        load_mode=None,
        delay_min_ms=0,
        delay_max_ms=0,
        failure_rate=1.0,           # force chaos
        failure_mode="auth_error",  # fastest chaos path (~0.05–0.5s)
        seed=42,
        verbose=False,
        rate_limit=M.RateLimits(),
        failure_bands={},
        load_presets={},
    )
    config.logs_dir = str(tmp_path)
    config.capture_bodies = True

    M._init_state(config)
    M._setup_logging(verbose=False, log_file=M._state.log_paths.log_file)

    client = TestClient(M.app)
    resp = client.post(
        "/chat/completions",
        headers={
            "Authorization": "Bearer abctoken1234",
            "x-ms-client-request-id": "82fef1a9-test",
            "User-Agent": "pytest-tc/1.0",
        },
        json={"model": "gpt-5-4", "messages": [{"role": "user", "content": "hi"}]},
    )

    # Chaos path returned non-2xx with corp-shaped headers.
    assert resp.status_code == 401
    assert "apim-request-id" in resp.headers
    apim_uuid_from_header = resp.headers["apim-request-id"]

    # JSONL trace exists with exactly one row, correctly shaped.
    paths = M._resolve_log_paths(tmp_path, date_str=M._today_str())
    assert paths.jsonl_file.exists(), f"expected {paths.jsonl_file} to exist"
    lines = paths.jsonl_file.read_text().splitlines()
    assert len(lines) == 1
    trace = json.loads(lines[0])
    assert trace["apim_request_id"] == apim_uuid_from_header  # CROSS-REF works
    assert trace["chaos_mode"] == "auth_error"
    assert trace["final_status"] == 401
    assert trace["deployment"] == "gpt-5-4"
    assert trace["client_request_id"] == "82fef1a9-test"
    assert trace["user_agent"] == "pytest-tc/1.0"

    # .log file exists and contains the request ID.
    assert paths.log_file.exists()
    log_text = paths.log_file.read_text()
    assert "req=" in log_text
    assert apim_uuid_from_header[:8] in log_text  # prefix grep-matches

    # Body capture (because capture_bodies=True): both IN and OUT body files.
    assert paths.bodies_dir.is_dir()
    captured = list(paths.bodies_dir.iterdir())
    in_files = [p for p in captured if "-in." in p.name]
    out_files = [p for p in captured if "-out." in p.name]
    assert len(in_files) == 1
    assert len(out_files) == 1
    in_body = json.loads(in_files[0].read_text())
    assert in_body["model"] == "gpt-5-4"
