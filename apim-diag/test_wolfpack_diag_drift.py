"""Stage 8.1 — Drift-protection between wolfpack/llm_resilience and apim-diag/corp_diag_lib.

The two modules are parallel mirrors of the same chaos primitives. Every fix
must be applied to both. There's no automatic propagation. These tests pin
the shared invariants so silent drift gets caught at pytest time.

If wolfpack isn't importable (running apim-diag standalone), the tests
skip — so this file is safe in any environment.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

import corp_diag_lib as D

# Try to import wolfpack from the sibling predator/ project. Skip the
# entire module if it's not there — apim-diag must remain usable on its own.
#
# Subtlety: a stale editable install (e.g., predator-refactor) may already
# have `wolfpack` in sys.modules. Force the local predator/ checkout by
# evicting any prior wolfpack imports and prepending our path.
_PREDATOR_DIR = Path(__file__).resolve().parent.parent / "predator"
if _PREDATOR_DIR.is_dir():
    # Evict any prior wolfpack module so the fresh sys.path entry wins.
    for mod_name in list(sys.modules):
        if mod_name == "wolfpack" or mod_name.startswith("wolfpack."):
            del sys.modules[mod_name]
    # Remove any stale editable-install paths that contain a `wolfpack`
    # package, so our local predator/ checkout wins.
    sys.path[:] = [
        p for p in sys.path
        if not (Path(p) / "wolfpack" / "__init__.py").is_file()
    ]
    sys.path.insert(0, str(_PREDATOR_DIR))

try:
    from wolfpack import llm_resilience as W  # noqa: E402
    # Verify we got the local checkout — guard against the stale install
    # silently returning a wolfpack that predates the chaos work.
    _w_file = Path(W.__file__).resolve()
    if _PREDATOR_DIR.is_dir() and not str(_w_file).startswith(str(_PREDATOR_DIR)):
        pytest.skip(
            f"wolfpack imported from wrong location: {_w_file} "
            f"(expected under {_PREDATOR_DIR}). Stale editable install? "
            f"Drift checks skipped.",
            allow_module_level=True,
        )
except ImportError:
    pytest.skip("wolfpack not importable; drift checks skipped",
                allow_module_level=True)


# ============================================================================
# Section A — Tuples / sets / dicts that must be byte-identical
# ============================================================================


def test_apim_headers_of_interest_identical():
    """_APIM_HEADERS_OF_INTEREST drives which response headers get captured.
    Drift here would mean wolfpack and diag disagree on what telemetry to keep.
    """
    assert tuple(D._APIM_HEADERS_OF_INTEREST) == tuple(W._APIM_HEADERS_OF_INTEREST)


def test_transient_classes_identical():
    """_TRANSIENT_CLASSES drives which error classes tenacity retries.
    Drift here would mean wolfpack and diag have different retry decisions
    for the same exception — the whole point of the diag is fidelity.
    """
    assert set(D._TRANSIENT_CLASSES) == set(W._TRANSIENT_CLASSES)


def test_exception_type_classes_identical():
    """_EXCEPTION_TYPE_CLASSES maps openai SDK + azure-identity exception
    type names (strings) to chaos classes. Both sides must agree."""
    assert dict(D._EXCEPTION_TYPE_CLASSES) == dict(W._EXCEPTION_TYPE_CLASSES), (
        f"_EXCEPTION_TYPE_CLASSES drift: "
        f"diag-only={set(D._EXCEPTION_TYPE_CLASSES) - set(W._EXCEPTION_TYPE_CLASSES)}, "
        f"wolfpack-only={set(W._EXCEPTION_TYPE_CLASSES) - set(D._EXCEPTION_TYPE_CLASSES)}"
    )


# ============================================================================
# Section B — Behavioral equivalence on classify_error
# ============================================================================


@pytest.mark.parametrize("exc_factory", [
    lambda: __import__("builtins").TimeoutError("timed out"),
    lambda: __import__("builtins").ConnectionError("conn refused"),
    lambda: __import__("builtins").ValueError("non-transient bad"),
])
def test_classify_error_agreement_on_common_exceptions(exc_factory):
    """classify_error should produce the same label for the same exception."""
    e = exc_factory()
    assert D.classify_error(e) == W.classify_error(e), (
        f"classify_error drift on {type(e).__name__}: "
        f"diag={D.classify_error(e)!r}, wolfpack={W.classify_error(e)!r}"
    )


def test_classify_error_on_openai_internal_server_error():
    """openai SDK InternalServerError must classify identically."""
    import httpx
    from openai import InternalServerError
    req = httpx.Request("POST", "http://x/chat/completions")
    resp = httpx.Response(500, request=req)
    exc = InternalServerError("Internal Server Error", response=resp, body={})
    assert D.classify_error(exc) == W.classify_error(exc)


def test_classify_error_on_azure_credential_unavailable():
    """azure-identity CredentialUnavailableError must classify identically."""
    from azure.identity import CredentialUnavailableError
    exc = CredentialUnavailableError("not configured")
    assert D.classify_error(exc) == W.classify_error(exc)


# ============================================================================
# Section C — Storage mechanism (contextvar, not thread-local)
# ============================================================================


def test_neither_uses_threading_local():
    """Stage 7.1 fix — both must use contextvars, not threading.local.
    A regression to threading.local would re-introduce the threadpool-loss bug.
    """
    d_src = inspect.getsource(D._diag_request_hook)
    w_src = inspect.getsource(W._diag_request_hook)
    assert "_thread_local" not in d_src, (
        "diag: _diag_request_hook regressed to threading.local — "
        "Stage 7.1 fix lost"
    )
    assert "_thread_local" not in w_src, (
        "wolfpack: _diag_request_hook regressed to threading.local — "
        "Stage 7.1 fix lost"
    )


def test_both_use_contextvar_for_apim_capture():
    """Both must use the contextvar-with-mutable-box pattern."""
    d_src = inspect.getsource(D._diag_request_hook)
    w_src = inspect.getsource(W._diag_request_hook)
    assert "apim_capture_var" in d_src
    assert "apim_capture_var" in w_src


# ============================================================================
# Section D — Layer 2 primitive outer signature
# ============================================================================


def test_invoke_with_token_escalation_has_compatible_outer_signature():
    """Both implementations must expose the same caller-facing parameters.
    Internal kwargs (metric, emit_metric) may differ between sides since
    wolfpack's resilient_invoke takes those and diag's doesn't.
    """
    d_sig = inspect.signature(D.invoke_with_token_escalation)
    w_sig = inspect.signature(W.invoke_with_token_escalation)

    REQUIRED = {
        "invokable_factory",
        "payload",
        "is_truncated",
        "initial_max_tokens",
        "escalation_factor",
        "max_attempts",
        "context",
        "budget_journey_out",
    }
    d_params = set(d_sig.parameters)
    w_params = set(w_sig.parameters)
    assert REQUIRED.issubset(d_params), (
        f"diag invoke_with_token_escalation missing: {REQUIRED - d_params}"
    )
    assert REQUIRED.issubset(w_params), (
        f"wolfpack invoke_with_token_escalation missing: {REQUIRED - w_params}"
    )


# ============================================================================
# Section E — Hook + state functions have matching shape
# ============================================================================


def test_take_last_apim_capture_returns_same_field_keys():
    """The dict returned must have identical keys so callers can use the
    same **apim splat on either side."""
    D.reset_thread_apim_state()
    W.reset_thread_apim_state()
    d_cap = D.take_last_apim_capture()
    w_cap = W.take_last_apim_capture()
    assert set(d_cap.keys()) == set(w_cap.keys())
