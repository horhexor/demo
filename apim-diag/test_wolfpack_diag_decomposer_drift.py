"""Stage 10.1 — Drift-protection between wolfpack/trailheads/* and the
inlined decomposer in apim-diag/diag_repro_decomposer.py.

The diag is a single-file mirror of wolfpack's phase-aware-refined
decomposer. Schema (ChatRecipeTrailhead) + structural functions
(`dedup_candidate_primaries`) must stay in sync. This file pins the
shared invariants so silent drift gets caught at pytest time.

Mirrors the pattern of test_wolfpack_diag_drift.py (which pins the
llm_resilience primitives).
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

# Same stale-install guardrail as test_wolfpack_diag_drift.py
_PREDATOR_DIR = Path(__file__).resolve().parent.parent / "predator"
if _PREDATOR_DIR.is_dir():
    for mod_name in list(sys.modules):
        if mod_name == "wolfpack" or mod_name.startswith("wolfpack."):
            del sys.modules[mod_name]
    sys.path[:] = [
        p for p in sys.path
        if not (Path(p) / "wolfpack" / "__init__.py").is_file()
        or Path(p).resolve() == _PREDATOR_DIR.resolve()
    ]
    sys.path.insert(0, str(_PREDATOR_DIR))

# Diag-side
sys.path.insert(0, str(Path(__file__).resolve().parent))
from diag_repro_decomposer import (  # noqa: E402
    ChatRecipeTrailhead as D_Trailhead,
    dedup_candidate_primaries as D_dedup,
)

# Wolfpack-side
try:
    from wolfpack.trailheads.decomposer_chat_recipe import (  # noqa: E402
        ChatRecipeTrailhead as W_Trailhead,
    )
    from wolfpack.trailheads.decomposer_phase_aware_refined import (  # noqa: E402
        dedup_candidate_primaries as W_dedup,
    )
    _w_file = Path(W_dedup.__code__.co_filename).resolve()
    if _PREDATOR_DIR.is_dir() and not str(_w_file).startswith(str(_PREDATOR_DIR)):
        pytest.skip(
            f"wolfpack imported from wrong location: {_w_file} "
            f"(expected under {_PREDATOR_DIR}). Stale editable install? "
            f"Decomposer drift checks skipped.",
            allow_module_level=True,
        )
except ImportError:
    pytest.skip("wolfpack not importable; decomposer drift checks skipped",
                allow_module_level=True)


# ============================================================================
# Section A — ChatRecipeTrailhead schema drift (Stage 9.2 + base shape)
# ============================================================================


def test_kill_chain_phase_has_same_default():
    """Stage 9.2 fix: kill_chain_phase defaults to 'bridge' so the LLM
    can omit it in the bridge call. Both sides must agree."""
    d = D_Trailhead(trailhead_id="x", title="x", claim="x")
    w = W_Trailhead(trailhead_id="x", title="x", claim="x")
    assert d.kill_chain_phase == w.kill_chain_phase == "bridge"


def test_trailhead_required_fields_match():
    """Both schemas must require the same minimum fields for a valid
    trailhead. Drift here would mean LLM JSON valid on one side and
    invalid on the other."""
    d_fields = set(D_Trailhead.model_fields.keys())
    w_fields = set(W_Trailhead.model_fields.keys())
    # The fields that matter for downstream consumption + grading must
    # be present in both. Allow either side to ADD fields (no symmetric
    # requirement) — but the rubric-critical ones must intersect.
    RUBRIC_CRITICAL = {
        "trailhead_id", "title", "claim", "kill_chain_phase", "role",
        "false_positive_controls", "degraded_mode", "joins_windows",
        "source_grounding",
    }
    missing_d = RUBRIC_CRITICAL - d_fields
    missing_w = RUBRIC_CRITICAL - w_fields
    assert not missing_d, f"diag schema missing rubric fields: {missing_d}"
    assert not missing_w, f"wolfpack schema missing rubric fields: {missing_w}"


# ============================================================================
# Section B — dedup_candidate_primaries behavioral equivalence (Stage 10.1)
# ============================================================================


def _build_th(cls, tid: str, phase: str, claim: str,
              fp_count: int = 5) -> object:
    return cls(
        trailhead_id=tid,
        title=f"{tid}",
        claim=claim,
        kill_chain_phase=phase,
        role="primary_detection",
        false_positive_controls=[f"fp-{i}" for i in range(fp_count)],
        source_grounding="source",
        degraded_mode="degraded",
        joins_windows="recipient -> host, 30m",
        confidence=0.8,
    )


def test_dedup_signature_compatible():
    """Both dedup functions must accept the same parameters."""
    d_sig = inspect.signature(D_dedup)
    w_sig = inspect.signature(W_dedup)
    REQUIRED = {"candidates", "overlap_threshold"}
    assert REQUIRED.issubset(set(d_sig.parameters))
    assert REQUIRED.issubset(set(w_sig.parameters))


@pytest.mark.parametrize("scenario", [
    "disjoint", "all_overlap", "partial_overlap", "single", "empty",
])
def test_dedup_behavioral_equivalence(scenario):
    """For each scenario, diag's dedup and wolfpack's dedup must produce
    the same (promoted_ids, demoted_ids) result. Drift here would mean
    the diag's prediction of corp behavior diverges from wolfpack's
    actual production behavior — the whole point of the diag is fidelity.
    """
    if scenario == "disjoint":
        d_cands = [
            _build_th(D_Trailhead, "c1", "initial_access",
                      "Inbound spearphishing emails to recipients."),
            _build_th(D_Trailhead, "c2", "execution",
                      "Process injection via rundll32 from extracted paths."),
            _build_th(D_Trailhead, "c3", "command_and_control",
                      "Periodic HTTPS beaconing low payload."),
        ]
        w_cands = [
            _build_th(W_Trailhead, "c1", "initial_access",
                      "Inbound spearphishing emails to recipients."),
            _build_th(W_Trailhead, "c2", "execution",
                      "Process injection via rundll32 from extracted paths."),
            _build_th(W_Trailhead, "c3", "command_and_control",
                      "Periodic HTTPS beaconing low payload."),
        ]
    elif scenario == "all_overlap":
        s = "Hunt for inbound spearphishing emails with external links delivered to recipients."
        d_cands = [_build_th(D_Trailhead, f"c{i}", p, s, 5 - i)
                   for i, p in enumerate(["initial_access", "execution", "command_and_control"])]
        w_cands = [_build_th(W_Trailhead, f"c{i}", p, s, 5 - i)
                   for i, p in enumerate(["initial_access", "execution", "command_and_control"])]
    elif scenario == "partial_overlap":
        # c1 + c2 overlap; c3 distinct
        d_cands = [
            _build_th(D_Trailhead, "c1", "container_delivery",
                      "Disk image with shortcut and decoy in fresh user-writable path mount extracted.", 5),
            _build_th(D_Trailhead, "c2", "execution",
                      "Container shortcut launches rundll32 from extracted fresh user-writable directory decoy.", 3),
            _build_th(D_Trailhead, "c3", "command_and_control",
                      "Stable periodic HTTPS callbacks from non-browser processes.", 5),
        ]
        w_cands = [
            _build_th(W_Trailhead, "c1", "container_delivery",
                      "Disk image with shortcut and decoy in fresh user-writable path mount extracted.", 5),
            _build_th(W_Trailhead, "c2", "execution",
                      "Container shortcut launches rundll32 from extracted fresh user-writable directory decoy.", 3),
            _build_th(W_Trailhead, "c3", "command_and_control",
                      "Stable periodic HTTPS callbacks from non-browser processes.", 5),
        ]
    elif scenario == "single":
        d_cands = [_build_th(D_Trailhead, "solo", "execution", "any claim")]
        w_cands = [_build_th(W_Trailhead, "solo", "execution", "any claim")]
    else:  # empty
        d_cands = []
        w_cands = []

    d_p, d_d = D_dedup(d_cands, overlap_threshold=0.40)
    w_p, w_d = W_dedup(w_cands, overlap_threshold=0.40)

    d_promoted_ids = [t.trailhead_id for t in d_p]
    w_promoted_ids = [t.trailhead_id for t in w_p]
    d_demoted_ids = [t.trailhead_id for t in d_d]
    w_demoted_ids = [t.trailhead_id for t in w_d]

    assert d_promoted_ids == w_promoted_ids, (
        f"dedup promotion drift on {scenario}: "
        f"diag={d_promoted_ids}, wolfpack={w_promoted_ids}"
    )
    assert d_demoted_ids == w_demoted_ids, (
        f"dedup demotion drift on {scenario}: "
        f"diag={d_demoted_ids}, wolfpack={w_demoted_ids}"
    )
