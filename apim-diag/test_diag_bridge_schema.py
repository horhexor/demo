"""Stage 9.2 — Parallel mirror of wolfpack's bridge schema test.

The diag inlines ChatRecipeTrailhead; both modules must accept LLM
output that omits kill_chain_phase (the bridge call's failure mode in
every Stage 8.2 run).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

# Import the diag module the same way the bundled CLI does.
_DIAG_DIR = Path(__file__).resolve().parent
if str(_DIAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DIAG_DIR))

from diag_repro_decomposer import ChatRecipeTrailhead  # noqa: E402


def test_kill_chain_phase_has_default_when_llm_omits():
    t = ChatRecipeTrailhead(
        trailhead_id="TH-BRIDGE-001",
        title="bridge",
        claim="cross-stage",
    )
    assert t.kill_chain_phase == "bridge"


def test_kill_chain_phase_still_settable_explicitly():
    t = ChatRecipeTrailhead(
        trailhead_id="TH-001",
        title="x",
        claim="y",
        kill_chain_phase="initial_access",
    )
    assert t.kill_chain_phase == "initial_access"


def test_pydantic_model_validate_without_kill_chain_phase():
    raw = {
        "trailhead_id": "TH-BRIDGE-001",
        "title": "Bridge",
        "claim": "Cross-stage bridge claim.",
    }
    t = ChatRecipeTrailhead.model_validate(raw)
    assert t.kill_chain_phase == "bridge"


def test_unknown_kill_chain_phase_still_rejected():
    with pytest.raises(ValidationError):
        ChatRecipeTrailhead(
            trailhead_id="TH-001",
            title="x",
            claim="y",
            kill_chain_phase="not_a_real_phase",  # type: ignore[arg-type]
        )
