"""Stage 10.1 — TDD for deterministic role demotion.

When per-phase decomposition produces 4 candidate primaries (one per
phase), some candidates may overlap substantively with stronger
candidates (e.g., container_delivery primary anchoring on the same
"fresh user-writable path + extracted container" idea as the execution
primary). The rubric's "primaries materially distinct" A-range gate
caps such portfolios at B.

Polish can't fix this — its prompt explicitly forbids role demotion.
Instead, deterministic dedup uses the existing `_claim_overlap` to
detect the same overlap an LLM grader would, and flips the loser's
role to `supporting_detection`.

This function is pure (no LLM), deterministic, and runs in microseconds.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_DIAG_DIR = Path(__file__).resolve().parent
if str(_DIAG_DIR) not in sys.path:
    sys.path.insert(0, str(_DIAG_DIR))

from diag_repro_decomposer import (  # noqa: E402
    ChatRecipeTrailhead,
    dedup_candidate_primaries,
)


def _th(tid: str, phase: str, claim: str, fp_count: int = 5,
        sources: bool = True) -> ChatRecipeTrailhead:
    """Builds a trailhead with enough fields to be score-rankable."""
    return ChatRecipeTrailhead(
        trailhead_id=tid,
        title=f"{tid} for {phase}",
        claim=claim,
        kill_chain_phase=phase,
        role="primary_detection",
        false_positive_controls=[f"fp-{i}" for i in range(fp_count)],
        source_grounding="source" if sources else "",
        degraded_mode="degraded" if sources else "",
        joins_windows="recipient -> host, 30m",
        confidence=0.8,
    )


def test_no_overlap_all_stay_primary():
    """Disjoint claims: every candidate stays primary."""
    c1 = _th("c1", "initial_access",
             "Inbound spearphishing emails with external links to recipients.")
    c2 = _th("c2", "execution",
             "Process injection via rundll32 from extracted directory paths.")
    c3 = _th("c3", "command_and_control",
             "Periodic HTTPS beaconing with low payload sizes and timing jitter.")

    promoted, demoted = dedup_candidate_primaries(
        [c1, c2, c3], overlap_threshold=0.55,
    )

    assert len(promoted) == 3
    assert len(demoted) == 0
    assert all(t.role == "primary_detection" for t in promoted)


def test_all_overlap_only_highest_score_kept():
    """When every candidate has near-identical claims, only the best
    (by _score_trailhead) survives as primary; the rest demoted."""
    same_claim = (
        "Hunt for inbound spearphishing emails with external links delivered "
        "to recipients in policy and legal cohorts followed by web access."
    )
    c1 = _th("c1", "initial_access", same_claim, fp_count=5)
    c2 = _th("c2", "execution", same_claim, fp_count=3)  # lower score
    c3 = _th("c3", "command_and_control", same_claim, fp_count=1)  # lowest

    promoted, demoted = dedup_candidate_primaries(
        [c1, c2, c3], overlap_threshold=0.55,
    )

    assert len(promoted) == 1
    assert promoted[0].trailhead_id == "c1"  # highest fp_count → highest score
    assert len(demoted) == 2
    assert all(t.role == "supporting_detection" for t in demoted)


def test_partial_overlap_only_conflicting_demoted():
    """Two candidates overlap each other but not the third — the third
    stays primary, and the conflicting pair resolves by score."""
    c_overlap_a = _th(
        "c_overlap_a", "container_delivery",
        "Disk image or archive containing shortcut and decoy in fresh "
        "user-writable extracted path with mount and extraction events.",
        fp_count=5,
    )
    c_overlap_b = _th(
        "c_overlap_b", "execution",
        "Container with shortcut launches rundll32 from extracted fresh "
        "user-writable directory containing the decoy and the shortcut.",
        fp_count=3,
    )
    c_distinct = _th(
        "c_distinct", "command_and_control",
        "Stable periodic HTTPS callbacks from non-browser processes with "
        "moderate jitter and low payload volume.",
        fp_count=5,
    )

    promoted, demoted = dedup_candidate_primaries(
        [c_overlap_a, c_overlap_b, c_distinct], overlap_threshold=0.40,
    )

    promoted_ids = {t.trailhead_id for t in promoted}
    demoted_ids = {t.trailhead_id for t in demoted}
    # The distinct one always stays.
    assert "c_distinct" in promoted_ids
    # Exactly one of the overlapping pair is demoted.
    assert ("c_overlap_a" in promoted_ids) ^ ("c_overlap_b" in promoted_ids), (
        f"expected exactly one of overlap pair promoted; got promoted={promoted_ids}"
    )
    assert len(demoted) == 1
    assert all(t.role == "supporting_detection" for t in demoted)


def test_demoted_trailheads_get_role_flipped():
    """A demoted trailhead's `role` field must change to
    `supporting_detection`. Otherwise downstream consumers can't tell."""
    same = "Identical claim text used twice for deterministic demotion."
    c1 = _th("c1", "initial_access", same, fp_count=5)
    c2 = _th("c2", "execution", same, fp_count=1)

    _, demoted = dedup_candidate_primaries([c1, c2], overlap_threshold=0.5)

    assert len(demoted) == 1
    assert demoted[0].role == "supporting_detection"


def test_empty_input_returns_empty_output():
    promoted, demoted = dedup_candidate_primaries([])
    assert promoted == []
    assert demoted == []


def test_single_candidate_always_promoted():
    only = _th("solo", "execution",
               "Any single candidate has nothing to overlap with.")
    promoted, demoted = dedup_candidate_primaries([only])
    assert promoted == [only]
    assert demoted == []


def test_promotion_order_stable_within_score_tier():
    """When scores are tied, ties should resolve deterministically
    (not depend on dict ordering or hash randomization)."""
    # Two trailheads with identical scores and identical claims
    claim = "Identical claim text and identical score."
    c1 = _th("c1", "initial_access", claim, fp_count=3)
    c2 = _th("c2", "execution", claim, fp_count=3)

    p1, d1 = dedup_candidate_primaries([c1, c2], overlap_threshold=0.5)
    p2, d2 = dedup_candidate_primaries([c1, c2], overlap_threshold=0.5)

    # Same call → same result
    assert [t.trailhead_id for t in p1] == [t.trailhead_id for t in p2]
    assert [t.trailhead_id for t in d1] == [t.trailhead_id for t in d2]
