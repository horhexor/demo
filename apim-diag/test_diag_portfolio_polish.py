"""Stage 9.3 — TDD for portfolio polish in the diag.

Wolfpack defaults portfolio polish ON; the diag previously hard-coded
it OFF (`--no-portfolio-polish` was always set). With Layer 1+2 +
ledger/cache safety nets, the wall-time assumption that drove the
opt-out no longer holds. Wire it in, default it ON, mirror wolfpack.

Tests:
1. Config knobs exist with the right defaults (polish ON, budget 2048).
2. `invoke_portfolio_polish` callable + correct signature.
3. With a mocked LLM that returns a valid revised portfolio, the
   function returns the revised trailheads.
4. With a mocked LLM that raises, the function returns the original
   draft trailheads (graceful degradation, like per-trailhead polish).
"""
from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import httpx
import pytest
from langchain_openai import ChatOpenAI

_DIAG_DIR = Path(__file__).resolve().parent
if str(_DIAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DIAG_DIR))

import corp_diag_lib as lib  # noqa: E402
from diag_repro_decomposer import (  # noqa: E402
    ChatRecipePortfolio,
    ChatRecipeTrailhead,
)


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: config defaults
# ─────────────────────────────────────────────────────────────────────────────


def test_config_has_portfolio_initial_budget():
    """Portfolio polish has a larger initial budget than per-trailhead
    polish because the output (full revised portfolio) is bigger."""
    cfg = lib.LLMConfig()
    assert hasattr(cfg, "portfolio_initial_budget"), (
        "config.llm.portfolio_initial_budget not defined"
    )
    assert cfg.portfolio_initial_budget == 2048, (
        f"portfolio_initial_budget default should be 2048, got "
        f"{cfg.portfolio_initial_budget}"
    )


def test_config_no_portfolio_polish_default_is_false():
    """Stage 9.3: flip the default — polish should run by default,
    mirroring wolfpack's polish_enabled=True default. The yaml's
    'always true' comment was from before Layer 1+2 made polish viable."""
    cfg = lib.DiagConfig()
    assert cfg.no_portfolio_polish is False, (
        f"diag.no_portfolio_polish default should be False (polish ON), "
        f"got {cfg.no_portfolio_polish}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: function exists
# ─────────────────────────────────────────────────────────────────────────────


def test_invoke_portfolio_polish_exists_with_expected_signature():
    """The function must exist and accept these parameters at minimum:
    llm, draft (list of trailheads), threat_reports_block, metrics_writer,
    config. ledger/report_id/run_id are optional (for ledger writes)."""
    from diag_repro_decomposer import invoke_portfolio_polish
    sig = inspect.signature(invoke_portfolio_polish)
    params = set(sig.parameters)
    required = {"llm", "draft", "threat_reports_block",
                "metrics_writer", "config"}
    missing = required - params
    assert not missing, f"invoke_portfolio_polish missing params: {missing}"


# ─────────────────────────────────────────────────────────────────────────────
# Tests 3 + 4: behavior with mocked LLM
# ─────────────────────────────────────────────────────────────────────────────


def _make_draft_trailhead(tid: str, role: str = "primary_detection",
                          phase: str = "initial_access") -> ChatRecipeTrailhead:
    return ChatRecipeTrailhead(
        trailhead_id=tid,
        title=f"Draft {tid}",
        claim=f"Draft claim for {tid}.",
        kill_chain_phase=phase,
        role=role,
    )


def _build_polish_response_body(revised_trailheads: list[dict]) -> bytes:
    """Build a fake OpenAI tool_calls response that langchain's
    with_structured_output(method='function_calling') can parse into
    ChatRecipeGeneratorOutput."""
    args = json.dumps({
        "portfolio": {
            "campaign_slug": "test-campaign",
            "trailheads": revised_trailheads,
            "portfolio_notes": "",
        },
        "self_grade": None,
    })
    return json.dumps({
        "id": "resp-polish",
        "choices": [{
            "message": {
                "content": "",
                "role": "assistant",
                "tool_calls": [{
                    "id": "c1",
                    "type": "function",
                    "function": {
                        "name": "ChatRecipeGeneratorOutput",
                        "arguments": args,
                    },
                }],
            },
            "finish_reason": "tool_calls",
            "index": 0,
        }],
        "usage": {"prompt_tokens": 100, "completion_tokens": 100,
                  "total_tokens": 200},
        "model": "gpt-4",
        "object": "chat.completion",
    }).encode()


def _build_llm_with_transport(transport: httpx.BaseTransport) -> ChatOpenAI:
    http_client = httpx.Client(
        transport=transport,
        event_hooks={
            "request": [lib._diag_request_hook],
            "response": [lib._diag_response_hook],
        },
    )
    return ChatOpenAI(
        model="gpt-4",
        base_url="http://fake/",
        api_key="dummy",
        max_completion_tokens=2048,
        http_client=http_client,
    )


def _build_metrics_writer() -> lib.MetricsWriter:
    """A minimal MetricsWriter that doesn't write to disk."""
    class _NoopWriter:
        def __init__(self):
            self.metrics: list[lib.CallMetric] = []

        def write(self, metric):
            self.metrics.append(metric)
    return _NoopWriter()  # type: ignore[return-value]


def test_invoke_portfolio_polish_returns_revised_on_success():
    from diag_repro_decomposer import invoke_portfolio_polish

    revised_args = [
        {
            "trailhead_id": "TH-P-001",
            "title": "Revised TH-P-001 — sharper claim",
            "claim": "Revised claim with explicit window and FP controls.",
            "kill_chain_phase": "initial_access",
            "role": "primary_detection",
            "false_positive_controls": ["explicit-control-1", "explicit-control-2"],
        },
    ]

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            return httpx.Response(
                200,
                content=_build_polish_response_body(revised_args),
                headers={
                    "content-type": "application/json",
                    "apim-request-id": "test-apim-polish",
                    "x-request-id": "test-x-polish",
                    "x-ratelimit-remaining-tokens": "999000",
                    "x-ratelimit-remaining-requests": "49999",
                    "x-ratelimit-limit-tokens": "1000000",
                    "x-ratelimit-limit-requests": "50000",
                },
            )

    llm = _build_llm_with_transport(T())
    config = lib.Config()
    config.llm.portfolio_initial_budget = 2048

    draft = [_make_draft_trailhead("TH-P-001")]
    result = invoke_portfolio_polish(
        llm,
        draft=draft,
        threat_reports_block="(test reports)",
        metrics_writer=_build_metrics_writer(),
        config=config,
    )

    # Result must be the revised list, not the original
    assert isinstance(result, list)
    assert len(result) == 1
    assert "Revised" in result[0].title


def test_invoke_portfolio_polish_returns_original_on_failure():
    """Graceful degradation: when the LLM call raises, return the original
    draft trailheads unchanged so the pipeline can still ship a portfolio."""
    from diag_repro_decomposer import invoke_portfolio_polish

    class FailT(httpx.BaseTransport):
        def handle_request(self, request):
            raise httpx.ConnectError("synthetic mock failure")

    llm = _build_llm_with_transport(FailT())
    config = lib.Config()

    draft = [
        _make_draft_trailhead("TH-P-001"),
        _make_draft_trailhead("TH-P-002", phase="execution"),
    ]
    result = invoke_portfolio_polish(
        llm,
        draft=draft,
        threat_reports_block="(test reports)",
        metrics_writer=_build_metrics_writer(),
        config=config,
    )

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0].trailhead_id == "TH-P-001"
    assert result[1].trailhead_id == "TH-P-002"
    # Titles unchanged (no LLM revision happened)
    assert result[0].title == "Draft TH-P-001"
    assert result[1].title == "Draft TH-P-002"
