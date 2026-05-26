"""Tests for invoke_with_token_escalation (Layer 2 — output-shape resilience).

The primitive escalates max_completion_tokens on finish_reason=length, retrying
the same prompt at progressively higher budgets until success or exhaustion.

Independent of Layer 1 (tenacity / network resilience), which handles transient
HTTP errors. Layer 2 sits ABOVE Layer 1 — each budget attempt may itself
trigger tenacity retries via resilient_invoke.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import corp_diag_lib as L


def _fake_response(content: str = "{}", finish_reason: str = "stop"):
    """Build a fake AIMessage-shaped result with .response_metadata."""
    msg = MagicMock()
    msg.content = content
    msg.response_metadata = {"finish_reason": finish_reason}
    return msg


def _make_invokable_factory(responses: list[tuple[str, str]]):
    """Build an invokable_factory that returns canned responses in order.

    Each factory invocation creates a fresh invokable bound to one budget.
    The shared call counter ensures successive escalation attempts get the
    next response in the list — simulating "each retry talks to the same LLM".
    """
    budgets_seen: list[int] = []
    call_count = [0]

    def factory(budget: int):
        budgets_seen.append(budget)

        class _Invokable:
            def invoke(self_inner, payload):
                idx = call_count[0]
                call_count[0] += 1
                if idx >= len(responses):
                    raise AssertionError(
                        f"Test ran out of canned responses (expected ≤{len(responses)}, got call {idx + 1})"
                    )
                content, finish_reason = responses[idx]
                return _fake_response(content, finish_reason)
        return _Invokable()

    return factory, budgets_seen, call_count


def _is_truncated_default(result) -> bool:
    """The standard truncation check used by callers."""
    return result.response_metadata.get("finish_reason") == "length"


def _config():
    """Minimal config for resilient_invoke compatibility."""
    cfg = L.load_config()
    cfg.llm.max_retries = 1  # don't retry transients in tests; keep them clean
    return cfg


# ============================================================================
# Section A — escalation behavior
# ============================================================================


def test_success_on_first_attempt_returns_immediately():
    """No escalation when the first call returns ok."""
    factory, budgets_seen, call_count = _make_invokable_factory([
        ("ok-result", "stop"),
    ])
    journey: list[int] = []

    result, status = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=_is_truncated_default,
        initial_max_tokens=1024,
        escalation_factor=2.0,
        max_attempts=4,
        config=_config(),
        context="test",
        budget_journey_out=journey,
    )

    assert status == "ok"
    assert result.content == "ok-result"
    assert journey == [1024]
    assert budgets_seen == [1024]
    assert call_count[0] == 1


def test_truncated_then_success_records_two_budgets():
    """One truncation → escalate → success on second attempt."""
    factory, budgets_seen, call_count = _make_invokable_factory([
        ("partial", "length"),
        ("complete", "stop"),
    ])
    journey: list[int] = []

    result, status = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=_is_truncated_default,
        initial_max_tokens=1024,
        escalation_factor=2.0,
        max_attempts=4,
        config=_config(),
        context="test",
        budget_journey_out=journey,
    )

    assert status == "ok"
    assert result.content == "complete"
    assert journey == [1024, 2048]
    assert budgets_seen == [1024, 2048]
    assert call_count[0] == 2


def test_all_attempts_truncated_returns_exhausted():
    """Every attempt truncates → returns the last result with 'truncation_exhausted' status."""
    factory, budgets_seen, _ = _make_invokable_factory([
        ("partial-1", "length"),
        ("partial-2", "length"),
        ("partial-3", "length"),
        ("partial-4", "length"),
    ])
    journey: list[int] = []

    result, status = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=_is_truncated_default,
        initial_max_tokens=1024,
        escalation_factor=2.0,
        max_attempts=4,
        config=_config(),
        context="test",
        budget_journey_out=journey,
    )

    assert status == "truncation_exhausted"
    assert result.content == "partial-4"
    assert journey == [1024, 2048, 4096, 8192]
    assert budgets_seen == [1024, 2048, 4096, 8192]


def test_escalation_factor_is_configurable():
    """1.5× factor produces different budget journey than 2.0×."""
    factory, budgets_seen, _ = _make_invokable_factory([
        ("partial-1", "length"),
        ("partial-2", "length"),
        ("complete", "stop"),
    ])
    journey: list[int] = []

    _, status = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=_is_truncated_default,
        initial_max_tokens=1000,
        escalation_factor=1.5,
        max_attempts=4,
        config=_config(),
        context="test",
        budget_journey_out=journey,
    )

    assert status == "ok"
    assert journey == [1000, 1500, 2250]


def test_max_attempts_caps_escalation_count():
    """Setting max_attempts=2 stops escalation early."""
    factory, _, _ = _make_invokable_factory([
        ("p1", "length"),
        ("p2", "length"),
    ])
    journey: list[int] = []

    result, status = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=_is_truncated_default,
        initial_max_tokens=1024,
        escalation_factor=2.0,
        max_attempts=2,
        config=_config(),
        context="test",
        budget_journey_out=journey,
    )

    assert status == "truncation_exhausted"
    assert journey == [1024, 2048]


def test_callable_is_truncated_is_polymorphic():
    """The truncation check is a caller-provided callable, not hardcoded to finish_reason."""
    factory, _, _ = _make_invokable_factory([
        ("partial", "stop"),  # finish_reason=stop but content marks it as bad
        ("complete", "stop"),
    ])
    journey: list[int] = []

    def custom_check(result):
        return result.content == "partial"

    _, status = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=custom_check,
        initial_max_tokens=1024,
        escalation_factor=2.0,
        max_attempts=4,
        config=_config(),
        context="test",
        budget_journey_out=journey,
    )

    assert status == "ok"
    assert journey == [1024, 2048]


def test_attempts_list_threaded_through_to_resilient_invoke():
    """Each escalation level appends its CallAttempt to the shared attempts list."""
    factory, _, _ = _make_invokable_factory([
        ("partial", "length"),
        ("complete", "stop"),
    ])
    attempts: list[L.CallAttempt] = []
    journey: list[int] = []

    _, _ = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=_is_truncated_default,
        initial_max_tokens=1024,
        escalation_factor=2.0,
        max_attempts=4,
        config=_config(),
        context="test",
        attempts=attempts,
        budget_journey_out=journey,
    )

    # Both successful HTTP attempts should have landed in attempts.
    assert len(attempts) == 2
    assert all(a.status == "ok" for a in attempts)


def test_budget_journey_out_optional():
    """Caller can omit budget_journey_out; no crash."""
    factory, _, _ = _make_invokable_factory([
        ("ok", "stop"),
    ])

    result, status = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=_is_truncated_default,
        initial_max_tokens=1024,
        escalation_factor=2.0,
        max_attempts=4,
        config=_config(),
        context="test",
    )

    assert status == "ok"


def test_context_label_passed_through_to_resilient_invoke():
    """The context string the caller passes shows up in resilient_invoke's logs.

    We verify via behavioral signal: resilient_invoke logs include the context.
    Smoke test — just ensure no crash when context is passed.
    """
    factory, _, _ = _make_invokable_factory([("ok", "stop")])

    _, _ = L.invoke_with_token_escalation(
        invokable_factory=factory,
        payload=[],
        is_truncated=_is_truncated_default,
        initial_max_tokens=1024,
        escalation_factor=2.0,
        max_attempts=4,
        config=_config(),
        context="per_phase:execution",
    )
