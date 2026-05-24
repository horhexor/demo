"""Tests for the continuation logic ported into diag_repro.py.

Mirrors wolfpack tests/test_extraction_continuation_semantics.py — the key
contract is that `_invoke_continuation_for_extraction` returns
`(items, ok_status: bool)` where ok_status=True means the invoke + parse
round-tripped cleanly even if `items` is empty (model legitimately said
"no more behaviors").
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# diag_repro is a script; add its directory to path so we can import.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import diag_repro as D


def _make_aimessage(content: str, finish_reason: str = "stop",
                    prompt_tokens: int = 100, completion_tokens: int = 10):
    msg = MagicMock()
    msg.content = content
    msg.response_metadata = {"finish_reason": finish_reason}
    msg.usage_metadata = {
        "input_tokens": prompt_tokens,
        "output_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }
    return msg


def _window(anchor: str = "a1"):
    return {
        "stable_anchor": anchor,
        "line_start": 1,
        "line_end": 10,
        "snippet": "snippet body",
        "ttp_ids": [],
    }


def _prefix_item(behavior_id: str = "B1"):
    """Fixture: a valid behavior dict shaped like diag's _AtomicBehaviorCandidate."""
    return {
        "behavior_id": behavior_id,
        "claim": "salvaged from truncated array",
        "evidence_refs": [
            {"stable_anchor": "a1", "line_start": 1, "line_end": 5,
             "snippet": "evidence text", "linked_ttp_ids": ["T1059"],
             "source_kind": "understand_section"}
        ],
        "observables": ["cmd.exe"],
        "telemetry_requirements": {"log_sources": ["sysmon"], "required_fields": ["Image"]},
        "source_agent": "extraction_agent",
        "confidence": 0.8,
    }


# ============================================================================
# _build_continuation_prompt — shape contract
# ============================================================================


def test_continuation_prompt_includes_original_extraction_prompt():
    """Continuation prompt = original prompt + a continuation block. The
    original context (threat-report sections) must still be there so the
    model can extract from it."""
    windows = [_window()]
    prefix = [_prefix_item("B1"), _prefix_item("B2")]

    cont = D._build_continuation_prompt(windows, prefix)
    original = D.build_extraction_prompt(windows)

    assert original in cont
    assert "[CONTINUATION REQUEST]" in cont
    assert "B1" in cont and "B2" in cont
    # Model is told the next id starts at B3
    assert "B3" in cont


def test_continuation_prompt_handles_empty_prefix():
    """Defensive: even if prefix is empty for some reason, the prompt still builds."""
    cont = D._build_continuation_prompt([_window()], prefix_items=[])
    assert "[CONTINUATION REQUEST]" in cont
    assert "(none)" in cont  # explicit none-marker for empty prefix


# ============================================================================
# _invoke_continuation_for_extraction — (items, ok_status) tuple contract
# ============================================================================


def test_continuation_returns_ok_true_when_model_returns_empty_list_cleanly():
    """Model says 'nothing more to extract' → returns ([], True)."""
    fake_response = _make_aimessage("[]", finish_reason="stop", completion_tokens=5)

    cfg = D.lib.Config()
    metrics_writer = D.lib.MetricsWriter()
    llm = MagicMock()

    with patch.object(D.lib, "resilient_invoke", return_value=fake_response):
        items, ok_status = D._invoke_continuation_for_extraction(
            llm,
            context_windows=[_window()],
            prefix_items=[_prefix_item()],
            config=cfg,
            metrics_writer=metrics_writer,
            parent_label="parent_test",
        )

    assert items == []
    assert ok_status is True, "empty-but-clean continuation must report ok_status=True"


def test_continuation_returns_ok_false_when_invoke_raises():
    """Transport / HTTP failure → returns ([], False)."""
    cfg = D.lib.Config()
    metrics_writer = D.lib.MetricsWriter()
    llm = MagicMock()

    with patch.object(D.lib, "resilient_invoke", side_effect=RuntimeError("HTTP 500")):
        items, ok_status = D._invoke_continuation_for_extraction(
            llm,
            context_windows=[_window()],
            prefix_items=[_prefix_item()],
            config=cfg,
            metrics_writer=metrics_writer,
            parent_label="parent_test",
        )

    assert items == []
    assert ok_status is False


def test_continuation_returns_ok_false_when_parse_fails():
    """Non-truncated garbage JSON → returns ([], False)."""
    fake_response = _make_aimessage("not json at all", finish_reason="stop")

    cfg = D.lib.Config()
    metrics_writer = D.lib.MetricsWriter()
    llm = MagicMock()

    with patch.object(D.lib, "resilient_invoke", return_value=fake_response):
        items, ok_status = D._invoke_continuation_for_extraction(
            llm,
            context_windows=[_window()],
            prefix_items=[_prefix_item()],
            config=cfg,
            metrics_writer=metrics_writer,
            parent_label="parent_test",
        )

    assert items == []
    assert ok_status is False


def test_continuation_returns_ok_true_with_validated_items():
    """Happy path: model returns valid behavior list → (items, True)."""
    payload = json.dumps([_prefix_item(behavior_id="B2")])
    fake_response = _make_aimessage(payload, finish_reason="stop", completion_tokens=200)

    cfg = D.lib.Config()
    metrics_writer = D.lib.MetricsWriter()
    llm = MagicMock()

    with patch.object(D.lib, "resilient_invoke", return_value=fake_response):
        items, ok_status = D._invoke_continuation_for_extraction(
            llm,
            context_windows=[_window()],
            prefix_items=[_prefix_item("B1")],
            config=cfg,
            metrics_writer=metrics_writer,
            parent_label="parent_test",
        )

    assert len(items) == 1
    assert ok_status is True
