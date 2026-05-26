"""Tests for truncation chaos in apim_mimic.

The mimic probabilistically overrides max_completion_tokens to force the
upstream Foundry to return finish_reason=length. This simulates corp gpt-5.x's
dice-roll truncation, which is the chaos mode Layer 2 (token-budget escalation)
is designed to survive.
"""
from __future__ import annotations

import random

from apim_mimic import maybe_inject_truncation


def test_truncation_rate_zero_never_overrides():
    """rate=0.0 → request body is never mutated."""
    rng = random.Random(42)
    for _ in range(20):
        body = {"max_completion_tokens": 4096, "model": "x"}
        result = maybe_inject_truncation(
            body, truncation_rate=0.0, forced_budget=256, rng=rng,
        )
        assert result["injected"] is False
        assert body["max_completion_tokens"] == 4096


def test_truncation_rate_one_always_overrides():
    """rate=1.0 → every call gets budget overridden to forced_budget."""
    rng = random.Random(42)
    for _ in range(20):
        body = {"max_completion_tokens": 4096, "model": "x"}
        result = maybe_inject_truncation(
            body, truncation_rate=1.0, forced_budget=256, rng=rng,
        )
        assert result["injected"] is True
        assert result["original_budget"] == 4096
        assert result["forced_budget"] == 256
        assert body["max_completion_tokens"] == 256


def test_truncation_rate_50_percent_with_seed_reproducible():
    """rate=0.5 with a fixed seed produces a deterministic injection pattern."""
    rng_a = random.Random(42)
    rng_b = random.Random(42)

    pattern_a = []
    pattern_b = []
    for _ in range(30):
        body_a = {"max_completion_tokens": 4096}
        body_b = {"max_completion_tokens": 4096}
        result_a = maybe_inject_truncation(
            body_a, truncation_rate=0.5, forced_budget=256, rng=rng_a,
        )
        result_b = maybe_inject_truncation(
            body_b, truncation_rate=0.5, forced_budget=256, rng=rng_b,
        )
        pattern_a.append(result_a["injected"])
        pattern_b.append(result_b["injected"])

    assert pattern_a == pattern_b, "Same seed should produce identical injection pattern"
    # At rate=0.5 over 30 trials, expect ~15 injections (binomial; range 9-21 is safe)
    hits = sum(pattern_a)
    assert 8 <= hits <= 22, f"Expected ~15 hits at rate=0.5, got {hits}"


def test_truncation_preserves_other_body_fields():
    """Only max_completion_tokens is mutated; other fields untouched."""
    rng = random.Random(42)
    body = {
        "max_completion_tokens": 4096,
        "model": "gpt-5-4",
        "messages": [{"role": "user", "content": "test"}],
        "tools": [{"type": "function"}],
    }
    maybe_inject_truncation(
        body, truncation_rate=1.0, forced_budget=256, rng=rng,
    )
    assert body["model"] == "gpt-5-4"
    assert body["messages"] == [{"role": "user", "content": "test"}]
    assert body["tools"] == [{"type": "function"}]


def test_truncation_no_budget_in_body_skipped():
    """If client didn't pass max_completion_tokens at all, no injection happens."""
    rng = random.Random(42)
    body = {"model": "gpt-5-4", "messages": []}  # no max_completion_tokens
    result = maybe_inject_truncation(
        body, truncation_rate=1.0, forced_budget=256, rng=rng,
    )
    assert result["injected"] is False
    assert "max_completion_tokens" not in body


def test_forced_budget_below_client_budget_only():
    """If forced_budget >= client budget, no injection (no point — wouldn't truncate)."""
    rng = random.Random(42)
    body = {"max_completion_tokens": 128}
    result = maybe_inject_truncation(
        body, truncation_rate=1.0, forced_budget=256, rng=rng,
    )
    assert result["injected"] is False
    assert body["max_completion_tokens"] == 128


def test_returns_diagnostic_dict():
    """Function returns a dict with diagnostic fields suitable for response headers."""
    rng = random.Random(42)
    body = {"max_completion_tokens": 4096}
    result = maybe_inject_truncation(
        body, truncation_rate=1.0, forced_budget=256, rng=rng,
    )
    assert isinstance(result, dict)
    assert "injected" in result
    assert "original_budget" in result
    assert "forced_budget" in result
