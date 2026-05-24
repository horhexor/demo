"""diag_repro_decomposer.py — corp decomposer-phase diagnostic, thin orchestrator.

Imports everything from corp_diag_lib (auth, resilient_invoke, MetricsWriter,
CallMetric, APIM header capture, error classification, summary, logging,
config loading + source tracking, token chaos). This file owns ONLY the
decomposer-specific logic:

  - Wolfpack contract schemas (BehaviorClusterBundle etc., inlined)
  - Chat-recipe schemas (ChatRecipeTrailhead etc., inlined)
  - 10 inlined prompts (shared header, bridge, per-trailhead polish, 7 phase variants)
  - Phase discovery + canonical TTP-to-phase mapping
  - Trailhead scoring + overlap helpers
  - Three LLM call wrappers (per_phase, bridge, per_trailhead_polish)
  - Decomposer pipeline orchestration
  - CLI + main

Settings come from corp_diag_config.yaml. Run `python -m corp_diag_lib --show-config`
to inspect resolved values + sources (cli|env|yaml|default).

Pipeline mirrors `python -m wolfpack.scripts.run_trailhead_phase --decomposer
phase_aware_refined --no-portfolio-polish`. Three LLM call types:

  1. per_phase   — one call per discovered kill-chain phase (parallel)
  2. bridge      — one call producing the cross-phase bridge trailhead
  3. per_trailhead_polish — one call per draft trailhead (parallel)

portfolio_polish is intentionally skipped (`--no-portfolio-polish`).

Usage:

    python diag_repro_decomposer.py \\
        --bundle-path <path> \\
        --behaviors-path <path> \\
        --reports-dir <path> \\
        --graph-path <path> \\
        --outputs-root outputs/decomposer-runs/corp \\
        --llm-profile-name corp \\
        --decomposer phase_aware_refined --no-portfolio-polish \\
        -v
"""

from __future__ import annotations

import argparse
import contextvars
import json
import logging
import os
import re
import sys
import textwrap
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

import corp_diag_lib as lib

logger = logging.getLogger("corp_diag.decomposer")
raw_log = logging.getLogger("corp_diag.raw")
batch_log = logging.getLogger("corp_diag.batching")


# ============================================================================
# Section E — Wolfpack contract schemas (inlined from wolfpack/contracts.py)
# ============================================================================


class AnchorEvidenceRef(BaseModel):
    stable_anchor: str = Field(..., min_length=1)
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    snippet: str = Field(..., min_length=1)
    linked_ttp_ids: list[str] = Field(default_factory=list)
    source_kind: Literal["understand_section", "raw_fallback"]

    @model_validator(mode="after")
    def _validate_line_bounds(self) -> "AnchorEvidenceRef":
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class TelemetryRequirements(BaseModel):
    log_sources: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)


class _ConfidenceModel(BaseModel):
    confidence: float = Field(..., ge=0.0, le=1.0)


class AtomicBehaviorCandidate(_ConfidenceModel):
    behavior_id: str = Field(..., pattern=r"^B[1-9]\d*$")
    claim: str = Field(..., min_length=1)
    evidence_refs: list[AnchorEvidenceRef] = Field(default_factory=list)
    observables: list[str] = Field(default_factory=list)
    telemetry_requirements: TelemetryRequirements
    source_agent: str = Field(..., min_length=1)


class BehaviorCluster(_ConfidenceModel):
    behavior_cluster_id: str = Field(..., pattern=r"^BC[1-9]\d*(-[a-z0-9_]+)?$")
    member_behavior_ids: list[str] = Field(default_factory=list)
    claim: str = Field(..., min_length=1)
    evidence_refs: list[AnchorEvidenceRef] = Field(default_factory=list)
    observables: list[str] = Field(default_factory=list)
    candidate_query_intents: list[str] = Field(default_factory=list)

    @field_validator("member_behavior_ids")
    @classmethod
    def _validate_member_ids(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.startswith("B"):
                raise ValueError("member_behavior_ids entries must start with 'B'")
        return value


class ExploratoryBehaviorCluster(BehaviorCluster):
    exploratory_reason_codes: list[str] = Field(default_factory=list)
    source_adjudication_status: Literal["unsupported", "partially_grounded"]
    promotion_candidate: bool = False


class AdjudicationResult(BaseModel):
    subject_id: str = Field(..., pattern=r"^BC[1-9]\d*(-[a-z0-9_]+)?$")
    status: Literal["grounded", "partially_grounded", "unsupported"]
    reasons: list[str] = Field(default_factory=list)
    validated_anchor_refs: list[str] = Field(default_factory=list)
    dropped_evidence_refs: list[str] = Field(default_factory=list)
    retention_decision: Literal[
        "retain_grounded", "retain_partial", "route_exploratory", "drop_invalid",
    ]


class BehaviorClusterBundle(BaseModel):
    contract_version: str = "1.0"
    report_id: str = Field(..., min_length=1)
    run_id: str = Field(..., min_length=1)
    run_mode: Literal["multi_agent_primary", "single_agent_control", "fallback_raw"]
    behavior_clusters_candidate: list[BehaviorCluster] = Field(default_factory=list)
    adjudication: list[AdjudicationResult] = Field(default_factory=list)
    behavior_clusters_grounded: list[BehaviorCluster] = Field(default_factory=list)
    behavior_clusters_partially_grounded: list[BehaviorCluster] = Field(default_factory=list)
    behavior_clusters_unsupported: list[BehaviorCluster] = Field(default_factory=list)
    behavior_clusters_exploratory: list[ExploratoryBehaviorCluster] = Field(default_factory=list)
    unsupported_reasons_rollup: dict[str, int] = Field(default_factory=dict)
    grounding_coverage_stats: dict = Field(default_factory=dict)
    processed_anchor_ids: list[str] = Field(default_factory=list)
    unprocessed_anchor_ids: list[str] = Field(default_factory=list)


# ============================================================================
# Section F — Chat-recipe schemas (inlined from decomposer_chat_recipe.py)
# ============================================================================


def _coerce_str_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        if any(sep in v for sep in (",", ";", "|")):
            return [p.strip() for p in re.split(r"[,;|]", v) if p.strip()]
        return [v.strip()] if v.strip() else []
    return [str(v)]


def _coerce_str_str_list_dict(v: Any) -> dict[str, list[str]]:
    if v is None:
        return {}
    if isinstance(v, list):
        return {"unspecified": _coerce_str_list(v)}
    if isinstance(v, dict):
        return {str(k): _coerce_str_list(val) for k, val in v.items()}
    return {"unspecified": _coerce_str_list(v)}


_ChatRecipeRole = Literal["primary_detection", "supporting_detection", "ioc_lookup", "bridge"]
_ChatRecipeKillChainPhase = Literal[
    "initial_access", "delivery", "container_delivery",
    "execution", "defense_evasion", "persistence",
    "privilege_escalation", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact", "bridge",
]


class _ChatValidationCriteria(BaseModel):
    positive_conditions: list[str] = Field(default_factory=list)
    negative_conditions: list[str] = Field(default_factory=list)


class _ChatWikiEvidenceRef(BaseModel):
    wiki_slug: str
    snippet: str = ""


class ChatRecipeTrailhead(BaseModel):
    trailhead_id: str
    title: str
    claim: str
    kill_chain_phase: _ChatRecipeKillChainPhase
    source_technique_ids: list[str] = Field(default_factory=list)
    expected_signals: list[str] = Field(default_factory=list)
    observables: list[str] = Field(default_factory=list)
    required_log_sources: list[str] = Field(default_factory=list)
    required_fields: dict[str, list[str]] = Field(default_factory=dict)
    detection_method: str = "correlation"
    validation_criteria: _ChatValidationCriteria = Field(default_factory=_ChatValidationCriteria)
    confidence: float = Field(0.7, ge=0.0, le=1.0)
    role: _ChatRecipeRole = "primary_detection"
    wiki_evidence_refs: list[_ChatWikiEvidenceRef] = Field(default_factory=list)
    joins_windows: str = ""
    degraded_mode: str = ""
    false_positive_controls: list[str] = Field(default_factory=list)
    enhanced_telemetry: list[str] = Field(default_factory=list)
    tunable_heuristics: list[str] = Field(default_factory=list)
    source_grounding: str = ""

    @field_validator(
        "source_technique_ids", "expected_signals", "observables",
        "required_log_sources", "false_positive_controls",
        "enhanced_telemetry", "tunable_heuristics",
        mode="before",
    )
    @classmethod
    def _coerce_lists(cls, v: Any) -> list[str]:
        return _coerce_str_list(v)

    @field_validator("required_fields", mode="before")
    @classmethod
    def _coerce_required_fields(cls, v: Any) -> dict[str, list[str]]:
        return _coerce_str_str_list_dict(v)


class ChatRecipePortfolio(BaseModel):
    campaign_slug: str = ""
    trailheads: list[ChatRecipeTrailhead] = Field(default_factory=list)
    portfolio_notes: str = ""


class ChatRecipeGeneratorOutput(BaseModel):
    portfolio: ChatRecipePortfolio
    self_grade: dict | None = None


# ============================================================================
# Section G — Inlined prompts (10 prompts from phase_aware_refined/)
# (portfolio_polish + portfolio_polish_aplus omitted — --no-portfolio-polish)
# ============================================================================


PROMPT_SHARED_HEADER = """You are a senior threat-hunt analyst building the **{{PHASE_NAME}}** slice of a multi-phase hunt portfolio. Other phases are being handled in parallel by your peers; the cross-phase bridge will be assembled separately.

Your job for this phase is:

- **Exactly 1 primary_detection trailhead** that captures the durable hunt logic for THIS phase, AND
- **Optionally 1-2 supporting_detection trailheads** that add genuinely distinct angles within this phase (different angle, different telemetry, different cohort, different prerequisite chain).

Take your time. Reason carefully. The portfolio is scored against a published rubric — A-range portfolios pass all five A-range gates:

1. Source fidelity ≥ 8/10 (claims trace back to the report; no invented behaviors).
2. No central trailhead unsupported by the source.
3. The campaign's main durable cross-phase bridge is preserved.
4. IOC-only content is treated as enrichment, not core hunting logic.
5. Primary trailheads are materially distinct from each other.

# What "high-scoring" looks like in this rubric (phase-agnostic principles)

Apply ALL of these as you write the claim:

- **Behavior over artifact.** The claim's core hunt logic must live in *procedure / lineage / cadence / timing / sequence / provenance* — things the adversary cannot trivially rotate. Names of system primitives the report describes (e.g., LOLBAS binaries the report mentions, persistence primitives the report mentions, analyst-vocabulary terms the report uses) DO belong in claims because they're stable OS-level vocabulary. Adversary-controlled artifacts (domains, hashes, decoy filenames, sender addresses, malware family names) do NOT belong in claims — they're enrichment.
- **Composition pattern.** Strong primaries combine 2-3 *contextual* signals (e.g., "primitive X + lineage Y + provenance Z"). Single-signal claims tend to be either too narrow (brittle to rotation) or too broad (noisy).
- **Realistic telemetry.** Specify the *primary* telemetry source and a *fallback* path for when it's missing. Common fallback shapes: "if process-attributed proxy is unavailable, fall back to host-level cadence analytics + endpoint lineage pivot via image-load telemetry"; "if click telemetry is missing, fall back to recipient → host correlation."
- **Explicit FP controls.** Every primary needs 3-5 specific suppressions: vendor-service allowlists, baseline novelty constraints, signed-binary exclusions, partner-sender allowlists, etc.
- **Operationalizable.** State the entities, the join key, the time window, and the prioritization rule. A hunter should be able to translate the claim into a Splunk/Kusto query without inventing missing entities.
- **Sharp not brittle.** Add specificity through *context combinations* (lineage + path provenance + cadence), not through exact strings (subjects, URIs, hashes).

# Phase-boundary discipline

Stay strictly within **{{PHASE_NAME}}**:

- Do NOT include claim text whose center of gravity is in another phase.
- It's fine — and often required — to mention an adjacent phase as a *lineage / context cue* ("after recent user interaction with a delivered file", "on hosts already flagged by earlier-phase signals"), but the trailhead's core hunt logic must live in this phase.
- If you find yourself writing a trailhead whose primary anchor is in another phase, **stop and skip it** — the other phase's analyst will produce it.

# Per-trailhead structure (write as markdown)

```
## TH-{role}-{nnn}: {title under 80 chars}

**Role:** primary_detection | supporting_detection

**Kill chain phase:** {{PHASE_NAME}}

**Source technique IDs:** comma-separated MITRE IDs the report mentions (e.g. T1566.002, T1218.011)

**Claim** (200-350 chars, hunt-hypothesis level prose, behavior-first):

[Hunt hypothesis. No artifact / domain / hash / vendor / family names in claim text. End primaries with: "Treat [X] as enrichment rather than required match conditions."]

**Joins / window** (entity → entity → entity + time window, under 60 chars):

**Required log sources** (1-2 generic categories combined with OR; no vendor names):

**Expected signals** (behavioral signals — at least 2, not IOCs):

**Validation criteria:**

- Positive (what confirms): [...]
- Negative (what disconfirms — at least 1): [...]

**False positive controls** (3-5 explicit suppressions):

**Degraded mode** (REQUIRED for primaries — explicit fallback path when ideal telemetry is missing):

**Enhanced telemetry** (richer signals — enrichment only):

**Tunable heuristics** (adjustable thresholds — enrichment only):

**Source grounding** (1-3 sentences quoting or paraphrasing the report, tying the claim to actual source content):

> [...]

**Confidence:** 0.5-0.95 float
```

If THIS phase has insufficient operational content in the report to support even one strong trailhead, return an empty trailheads list. This is acceptable — better to skip than fabricate.

Set `self_grade` to `null`. Do not include `portfolio_notes`.
"""


PROMPT_BRIDGE_BUILDER = """You are a senior threat-hunt analyst building the **cross-phase bridge trailhead** for a campaign's hunt portfolio. Other analysts have produced the per-phase primary trailheads (one per kill-chain phase); your job is to write the single bridge trailhead that operationalizes how those phases connect for a hunter.

Take your time. Reason carefully. The bridge is the single most important trailhead in the portfolio — it turns isolated stage trailheads into a campaign-aware hunt workflow. An A-range portfolio MUST preserve the bridge with explicit entity-resolution joins, a time window, a scored-overlap analytic, and a degraded mode.

# What you have

## Per-phase primary trailheads (these define the chain you must bridge)

{{PER_PHASE_PRIMARIES}}

## Campaign graph: stage-to-stage edges observed in THIS campaign

{{GRAPH_PHASE_EDGES}}

## Brief campaign context

{{CAMPAIGN_BRIEF}}

# What to produce

Produce exactly ONE trailhead, role = `bridge`. No primary or supporting trailheads.

The bridge must:

1. **Operationalize the scored-overlap analytic with N stages**, where **N equals the count of per-phase primaries provided above**. Do not merge two primaries into one stage. Do not invent stages without a corresponding primary. For each of the N primaries, the bridge claim must contain one corresponding stage signal. Promote cases with evidence from at least 2 of N stages; highest priority when all N align; degrade gracefully when one stage's telemetry is missing.
2. **Specify explicit entity-resolution joins** between adjacent phases (e.g., `recipient → user → device`, `same host and process`, `cross-host via known credential`). Vague joins like "same user" or "related activity" lose bridge-integrity points.
3. **Specify a time window** for the entire chain (and sub-windows where the report justifies them). Use the windows the report describes; do not invent values. Generic shape examples (substitute the report's actual numbers): "stage-1 → stage-2 within `<short minutes>`; stage-2 → stage-3 within `<minutes-to-hours>`; stage-3 → stage-4 sustained over `<hours-to-days>`."
4. **Include an explicit degraded mode** that names each of the N stages and says exactly what to do when that stage's telemetry is missing (one fallback per stage).
5. **Treat domains, hashes, filenames, and other IOCs as enrichment only**.
6. **Ground in the report's own correlation guidance** where the report provides one. If the report names a specific join window (e.g., a 30-minute click-to-execution rule), use that number rather than inventing one.

# Per-trailhead structure (write as markdown)

```
## TH-BRIDGE-001: {title under 80 chars}

**Role:** bridge

**Kill chain phase:** bridge

**Source technique IDs:** comma-separated MITRE IDs from across the phases (at least 2, ideally one per covered phase)

**Claim** (250-400 chars, prose specifying the N-stage scored-overlap analytic — name each stage's signal):

[Explicit text: "Score [entities] by overlap across N behaviors: (1) <signal from primary 1>, (2) <signal from primary 2>, ..., (N) <signal from primary N>. Promote cases with evidence from at least 2 of N stages; highest priority when all N align. Degrade gracefully when one stage's telemetry is missing. Treat domains, hashes, filenames, and infrastructure indicators as enrichment rather than required match conditions."]

**Joins / window** (entity-resolution chain across phases + time window, under 70 chars):

**Required log sources** (one per stage, combined with OR; no vendor names):

**Expected signals** (cross-stage):

**Validation criteria:**

- Positive (what confirms full chain): [...]
- Negative (what disconfirms — at least 2): [...]

**False positive controls** (5+ specific suppressions — bridges need more because they fire on overlap):

- [allowlist enterprise update / release flows that mimic the upstream stage]
- [allowlist approved newsletter / partner / signed-update senders at the upstream stage]
- [allowlist EDR / management / patching agents at the endpoint stage]
- [require minimum repetition count before scoring a cadence pattern at the network stage]
- [require novelty: first-seen relationship for at least one entity pair to reduce baseline traffic]

**Degraded mode** (REQUIRED — one explicit fallback per stage):

[e.g. "If stage-1 telemetry is missing: anchor on the remaining stages' overlap with reduced confidence. If stage-2 attribution is missing: fall back to stage-1 + stage-3 with documented confidence penalty. ..."]

**Enhanced telemetry** (optional richer signals — enrichment only):

**Tunable heuristics** (specific thresholds — enrichment only):

**Source grounding** (1-3 sentences quoting or paraphrasing the report's own recommended correlation workflow):

> [...]

**Confidence:** 0.80-0.95 float (bridges should be high-confidence when properly grounded)
```

# Critical rules

- The claim MUST contain the scored-overlap phrase ("at least 2 of N stages" or equivalent). Without it the bridge fails the rubric's bridge-integrity check.
- The joins/window MUST specify entity-resolution explicitly (e.g., "recipient → user → device" or "same host and process").
- The required log sources MUST have one entry per stage.
- The degraded mode MUST address what to do when each stage's telemetry is independently missing.
- Source fidelity: use the report's own correlation guidance where possible.
- Name explicit system primitives and analyst-vocabulary terms when the report describes them (e.g., LOLBAS binaries by name, "beaconing"/"callback"/"tasking" instead of paraphrases). These are stable OS-level / analyst terms, not adversary IOCs.

# Output format

Produce a `GeneratorOutput` JSON containing exactly ONE trailhead. Do not include `portfolio_notes`. Set `self_grade` to `null`.
"""


PROMPT_PER_TRAILHEAD_POLISH = """You are reviewing a SINGLE threat-hunt trailhead against the rubric's A+ criteria and emitting a tightened version. This is a per-trailhead polish — you cannot see the rest of the portfolio. Focus on the fields the rubric grades for this specific trailhead's role.

# What you have

## The trailhead to review and revise

{{TRAILHEAD_BLOCK}}

## Source threat reports (the only acceptable grounding for revisions)

{{THREAT_REPORTS}}

# A+ checklist (apply the section that matches this trailhead's role)

## If the trailhead's role is `primary_detection`

1. **Claim contains the composition pattern explicitly.** 2-3 contextual signals named in one sentence, in the shape `primitive/vector + lineage-or-context cue + cadence-or-provenance constraint`. If the claim has only one signal anchoring it, look in the report for a second contextual signal and add it.
2. **Claim contains an explicit time-window or cadence-stability cue** *where the report supports one*. Use the SPECIFIC values the report describes (do NOT invent values; if the report has no window, keep the claim window-agnostic). Replace vague phrases like "shortly after" or "later" with the report's stated window.
3. **Claim ends with the IOC-as-enrichment sentence**: "Treat [specific items the report names] as enrichment rather than required match conditions." Name the actual short-lived artifacts the report mentions (sender addresses, hashes, filenames, hosting URLs, decoy titles, family/tool names) — not a generic placeholder.
4. **`validation_criteria.positive_conditions` enumerates the full state required to confirm**, not a paraphrase of the claim.
5. **`false_positive_controls` field is populated** with 4-5 specific named suppressions (allowlist names, baseline patterns, signed-binary exclusions). If FP content currently lives only in `validation_criteria.negative_conditions`, move/duplicate it to `false_positive_controls`. Suppressions must be specific — "exclude X if benign" is too vague.
6. **`degraded_mode` is one full fallback path** — names the specific fallback telemetry source and the analytic adjustment when the primary source is missing. Not a generic phrase.
7. **`source_grounding` quotes or paraphrases the specific report section(s)** supporting this trailhead.

## If the trailhead's role is `bridge`

1. **Each of the N stage signals in the claim references its corresponding primary's anchor** (so a reviewer can trace which primary contributes which stage signal). Use the primary IDs (TH-P-001 etc.) when the claim says "stage 1 / stage 2 / ...".
2. **Sub-windows for each stage transition** must be present in the claim text (not just metadata). E.g., "stage-1 → stage-2 within `<report's stated window>`; stage-3 → stage-4 sustained over `<report's stated window>`." Use the report's stated values.
3. **Entity-resolution joins in the claim** use explicit arrows or "the same X" cues (e.g., `recipient → user → device`, "the same host and process lineage").
4. **`validation_criteria` includes a multi-stage degraded path** that names each of the N stages and what to do when that stage's telemetry is independently missing.
5. **`false_positive_controls` field is populated** with 5+ specific named suppressions (bridges fire on overlap and need more).
6. **The scored-overlap phrase is in the claim**: "Promote cases with evidence from at least 2 of N stages; highest priority when all N align" or equivalent.
7. **Sub-windows and stage signals all trace back to specific report content** (cite via `source_grounding`).

## If the trailhead's role is `supporting_detection`

1. **If this is a "gated" supporting** (the claim says it gates on another trailhead's signal), **the gating primary/bridge ID is named explicitly in the claim text** (e.g., "On hosts already flagged by TH-P-003 or TH-P-005..."). The gate appearing only in metadata loses portfolio-value points.
2. **Claim describes a distinct angle**, not a wording variant of another trailhead in the portfolio. (You can't see the rest of the portfolio — but if the claim feels like it could be a rewording of a generic primary, sharpen it toward a genuinely different angle: different telemetry, different cohort, different prerequisite chain, different time scale, etc.)
3. **`source_grounding`** ties to the specific report content the supporting angle is grounded in.
4. **`false_positive_controls`** field is populated.

## Universal (applies to every role)

- No domain, hash, filename, sender address, malware family name, or vendor name appears in the **claim text**. They belong in `enhanced_telemetry`, `tunable_heuristics`, or the IOC-as-enrichment trailing sentence.
- No invented procedures, primitives, or TTPs the report doesn't describe.
- Preserve the trailhead's role, kill_chain_phase, and trailhead_id.

# How to revise

For each checklist item, decide:
- If the trailhead already passes the item: leave that field unchanged.
- If the item fails: revise *only* the relevant field(s).

Do NOT introduce new behaviors the report doesn't describe. Do NOT change the trailhead's role.

If the trailhead is already strong on every item, return it unchanged.

# Output

Produce a `GeneratorOutput` JSON containing exactly ONE trailhead (the revised version of the input trailhead). Preserve the input's `trailhead_id`. Do not include `portfolio_notes`. Set `self_grade` to `null`.
"""


PROMPT_PHASE_DEFAULT = """# What "good" looks like for this phase (generic guidance)

This phase doesn't have a phase-specific addendum in the prompt library — fall back to the phase-agnostic principles from the shared header. Particularly important:

- Build the claim around 2-3 contextual signals (the *composition pattern*), not a single brittle anchor.
- Name explicit OS-level primitives and analyst-vocabulary terms the report describes; abstract away adversary-controlled artifacts.
- Specify primary telemetry + a degraded-mode fallback.
- Provide 3-5 explicit FP controls.
- Stay within the phase boundary; mention adjacent phases only as lineage cues.

If the report has no operational content for this phase, return an empty trailheads list — do not fabricate.
"""


PROMPT_PHASE_INITIAL_ACCESS = """# What "good" looks like for **initial_access** trailheads

The strongest IA primaries name the *delivery procedure* + *cohort/novelty discriminator* + *post-delivery action that ties to endpoint or web telemetry*. Adversary infrastructure (sender domains, exact subjects, link URLs) belongs in enrichment, not the claim.

## Phase-specific patterns the rubric rewards

- **Composition pattern**: `vector identity + cohort/novelty discriminator + downstream confirmation signal`. The pattern is shape-agnostic — fill it in from whichever IA vector the report describes. Examples across different IA types (not all of these will apply to any one campaign):
  - *Phishing-led IA*: delivery shape (attachment vs link, attachment file-type, body-only) + sender/recipient novelty for the recipient cohort + post-delivery user action (click, attachment open) within a short window.
  - *Exploit-driven IA*: vulnerable surface identity (a public-facing application, edge VPN, or remote service) + first-seen / off-baseline source IP or geography + post-exploit observable (web-shell write, shell process spawn, anomalous outbound from the target host).
  - *Valid-account abuse IA*: account-context identity (service principal, integration, OAuth grant) + novelty of the grantor / scope / source location + post-authentication anomalous API or resource access.
  - *Supply-chain IA*: distribution-channel identity (signed updater, package registry, vendor distribution) + signing-or-source anomaly + post-install anomalous endpoint behavior.
- **Behavioral durability**: vector-shape and novelty characteristics that survive infrastructure rotation. The specific dimensions vary by vector — phishing leans on sender/recipient novelty and delivery shape; exploit-driven IA leans on vulnerable-surface enumeration and source novelty; valid-account abuse leans on grant novelty and post-auth behavior shape. Use whichever applies in this report.
- **Avoid IOC anchoring**: do NOT lock the claim to specific subjects, sender addresses, URL paths, attachment names, exact CVE IDs, or specific account names. Those rotate or are campaign-specific.

## Phase-specific telemetry

- **Primary**: email gateway / message-trace logs (delivery side); proxy / web gateway logs (click side).
- **Degraded-mode fallback**: when click telemetry is missing, fall back to "delivered to recipient" + recipient-to-host correlation via endpoint web-access logs. When sender-side fields are sparse, lean on cohort-novelty + delivery-shape features instead.

## Phase-specific FP controls (suggest at least 3, pick what applies)

- Allowlist approved newsletter / notification / billing / partner senders.
- Allowlist legitimate enterprise SaaS that uses link-only delivery (calendar invites, document-share notifications, password resets).
- Require novelty: first-seen sender ↔ recipient pair, OR first-seen sending domain for that recipient cohort.
- Exclude messages bearing valid DKIM/SPF/DMARC from known partner domains.
- Exclude bulk-marketing platforms with documented sender reputation.

## When a supporting is justified

Produce a supporting only if you have a meaningfully different angle (not a wording variant):
- A **novelty / cohort-clustering** supporting that adds campaign-level wave detection (vs the primary's per-message logic).
- A **redirect-chain shape** supporting that adds web-pivot enrichment when click telemetry is rich.
- A **sender-authentication-failure** supporting that adds an orthogonal signal.

Skip the supporting if you only have a wording-variant idea.
"""


PROMPT_PHASE_DELIVERY = """# What "good" looks like for **delivery** / **container_delivery** trailheads

The strongest delivery primaries name the *delivery container type* + *user-handling primitive* + *inner-content shape* that gates downstream execution. Container filenames and decoy document titles are enrichment, not the claim.

## Phase-specific patterns the rubric rewards

- **Composition pattern**: `container vector + handling primitive + inner-content co-presence`. Fill in the specifics from whichever container vector the report describes. Examples across different delivery-container types (not all will apply to any one campaign):
  - *OneNote-as-container delivery*: `.one` container + render-to-screen + embedded HTA / script / linked-payload icon.
  - *HTML-smuggling delivery*: browser-rendered HTML page + in-browser blob decoding + drop-to-disk into Downloads.
  - *MSI/installer delivery*: signed-or-unsigned MSI + msiexec child-spawn + cabinet-extracted secondary payload into Temp / ProgramData.
  - *Container-image delivery (registry pull)*: image-pull from a container registry + container-runtime spawn + tooling executed inside the container with host-mount escape.
- **Behavioral durability**: container handling (mount, extract, render, install, pull) + inner-content co-residency patterns + freshness or first-seen-source provenance of the staging path. These survive when the adversary rotates filenames, themes, and hosting URLs.
- **Avoid IOC anchoring**: do NOT name specific container filenames, decoy document titles, or hosting URLs in the claim.

## Phase-specific telemetry

- **Primary**: endpoint file-creation / file-modification logs, mount/extract events, image-mount events.
- **Degraded-mode fallback**: when file-system telemetry is sparse, fall back to process lineage that begins from a freshly-created path or from `explorer.exe` opening content in a non-standard directory; use download-source attribution from web/proxy logs as an upstream anchor.

## Phase-specific FP controls (suggest at least 3, pick what applies)

- Allowlist enterprise software installers and update packages that legitimately use compressed containers.
- Allowlist version-control / collaboration tools that routinely extract archives into per-user paths.
- Require freshness: container path is newly created (within hours), not an existing well-known directory.
- Exclude containers extracted from signed enterprise software-distribution platforms.

## When a supporting is justified

Produce a supporting only if it's a meaningfully different angle:
- A **provenance / source-novelty** supporting that adds "first-seen download path / first-seen external source" enrichment.
- An **inner-content co-residency** supporting that detects the LNK+decoy pair pattern as a standalone weak signal (useful when execution telemetry is lagging).

Skip the supporting if you only have a wording-variant idea.
"""


PROMPT_PHASE_EXECUTION = """# What "good" looks like for **execution** trailheads

The strongest execution primaries name the *launch primitive* + *parent process lineage* + *path-provenance / context*. Process command-line strings are sometimes useful; exact paths and hashes are enrichment, not the claim.

## Phase-specific patterns the rubric rewards

- **Composition pattern**: `launch primitive + parent-lineage cue + path-provenance constraint`. Fill in the specifics from whichever launch primitive the report describes. Examples across different execution primitives (not all will apply to any one campaign):
  - *LOLBAS abuse*: a system-provided binary the report names invoked with non-standard arguments from a non-standard parent (e.g., `wmic process call create` spawned by a service-account interactive shell, or `certutil -urlcache` spawned outside an admin maintenance window).
  - *Macro / interpreter abuse*: an Office product spawning a script interpreter the report names (e.g., `winword.exe` parent of `powershell.exe`) with the interpreter loading content from a network or temp path.
  - *Vulnerability exploitation*: a service process (e.g., a web server, mail server, edge VPN) suddenly parenting a shell/scripting interpreter that wasn't part of its baseline child set.
  - *Service / scheduled-task triggered*: a Windows service or scheduled-task action launching from a non-standard path or under a non-standard identity, with no corresponding installer-signed lineage.
- **Behavioral durability**: process lineage, parent-child relationships, "freshly-created path" provenance, launch-primitive identity (the OS binary the adversary cannot rename). These survive when filenames, hashes, and exact command-lines rotate.
- **Stable OS primitive names belong in the claim** when the report names them. LOLBAS-family binaries (`certutil`, `bitsadmin`, `schtasks`, `wmic`, `mshta`, `regsvr32`, `rundll32`, `msbuild`, `installutil`, `cmstp`, `vssadmin`, `wevtutil`, named drivers), script interpreters (`powershell`, `cmd`, `cscript`, `wscript`), and analyst vocabulary ("signed-binary proxy execution", "interpreter abuse", "DLL search-order hijack") are stable OS-level terminology the hunter expects in a query. Use whichever the report describes — do not abstract them to "trusted utility" or "signed binary."
- **Avoid IOC anchoring**: do NOT lock the claim to specific DLL filenames, exact command-line strings, or hashes.

## Phase-specific telemetry

- **Primary**: endpoint process-creation logs with parent-child lineage + command line; image-load logs when available.
- **Degraded-mode fallback**: when image-load telemetry is missing, fall back to process-creation with parent process + working-directory provenance + recent-extraction context as a proxy for path-of-load.

## Phase-specific FP controls (suggest at least 3, pick what applies)

- Allowlist signed-installer flows that legitimately invoke LOLBAS-style binaries (control-panel utilities, MSI installer pipelines, signed updater chains, etc.).
- Allowlist signed enterprise-software update / patching agents and their child invocations.
- Allowlist Microsoft-Office macro pipelines whose normal lineage is well-known.
- Allowlist help-system / repair-tool invocations of system binaries (e.g., `mshta` opening `.chm`).
- Exclude built-in OS administrative scripts in known maintenance windows.

## When a supporting is justified — including the gated-post-foothold pattern

Two distinct supporting angles are common for the execution phase:

1. **Tradecraft variant within execution**: a different launch primitive the report mentions (e.g., interpreter-based execution vs binary-proxy execution), OR an interactively-invoked variant vs a service-spawned variant.
2. **Post-foothold tradecraft as a gated supporting**: if the report describes any *post-foothold* tradecraft within this same phase or chained to it (process injection, in-memory module mapping, host-process migration to another binary, lateral movement of the execution context, scheduled-task persistence created from the foothold, credential collection from the foothold), produce a supporting that **gates on the primary having already fired** — e.g., "On hosts where [primary] fired, look for [post-foothold signal]." This is one of the highest-value supporting patterns the rubric rewards because it preserves the campaign's downstream behavior.

Use the post-foothold gated-supporting pattern whenever the report supports it.
"""


PROMPT_PHASE_DEFENSE_EVASION = """# What "good" looks like for **defense_evasion** trailheads

The strongest defense_evasion primaries name the *evasion mechanic* + *target host/process context* + *gating prerequisite*. Generic obfuscation cues are weak; concrete mechanics tied to lineage are strong.

## Phase-specific patterns the rubric rewards

- **Composition pattern**: `evasion primitive + target host/process context + gating prerequisite` (e.g., "in-memory module loading into a child process whose parent lineage matches a recent suspicious execution chain").
- **Behavioral durability**: the evasion *mechanic* (injection, hollowing, masquerading, reflective loading, in-memory module mapping, debug-blocking) survives even when payloads, families, and infrastructure rotate.
- **Stable analyst vocabulary belongs in the claim** when the report describes the mechanic: "process injection", "process hollowing", "reflective code loading", "DLL search-order hijack", "DLL sideloading", "AppDomainManager injection", "named-pipe impersonation", "PPID spoofing", "image-file-execution-options redirect".
- **Avoid IOC anchoring**: do NOT lock to specific malware family names, payload hashes, or exact injection target process names — the technique is the durable signal.

## Phase-specific telemetry

- **Primary**: endpoint process-access logs, memory-operation telemetry (CreateRemoteThread, WriteProcessMemory, NtMapViewOfSection), kernel-callback events.
- **Degraded-mode fallback**: when memory-operation telemetry is sparse, fall back to suspicious-parent-child lineage + image-load patterns + handle-open relationships as a proxy.

## Phase-specific FP controls (suggest at least 3)

- Allowlist EDR / AV / DLP / monitoring vendor processes whose normal behavior includes injection / hollowing for inspection.
- Allowlist Microsoft-Office and other applications that perform legitimate cross-process operations.
- Allowlist debugging-tool usage in known engineering / IR contexts.
- Exclude code-signed / Microsoft-signed processes performing built-in cross-process operations.

## When a supporting is justified

This phase often produces ONE strong primary plus an optional supporting:

- A **gated-execution-chain** supporting: on hosts already flagged by execution-phase trailheads, look for evasion-mechanic indicators as a confirmatory signal. This frames the evasion as a downstream confirmation rather than a standalone hunt.
- An **enrichment-shape** supporting: detect ancillary tradecraft (memory-region characteristics, image-load anomalies) that confirms the evasion mechanic when the primary's main telemetry is incomplete.

Skip the supporting if no genuinely different angle exists.
"""


PROMPT_PHASE_PERSISTENCE = """# What "good" looks like for **persistence** trailheads

The strongest persistence primaries name the *persistence primitive* + *artifact location* + *trigger-time discriminator*. Specific scheduled-task names or registry-value names are enrichment, not the claim.

## Phase-specific patterns the rubric rewards

- **Composition pattern**: `persistence primitive + artifact location/path constraint + trigger discriminator` (e.g., "scheduled task created with a logon-trigger from a non-admin context where the action references a user-writable executable path").
- **Behavioral durability**: persistence primitive identity (scheduled task vs service vs run-key vs WMI subscription vs COM hijack) and the location/path-provenance discriminator. These survive even when artifact names rotate.
- **Stable analyst vocabulary belongs in the claim**: "scheduled task", "service install", "registry run key", "WMI subscription", "COM hijack", "image-file-execution-options hijack", "DLL search-order persistence", "AppInit DLL", "logon script", "winlogon notify package".
- **Avoid IOC anchoring**: do NOT name specific task names, service names, registry values, or executable filenames.

## Phase-specific telemetry

- **Primary**: native Windows event logs (Task Scheduler, Service Control Manager, Registry, WMI), Sysmon-equivalent registry / WMI / file-create events.
- **Degraded-mode fallback**: when registry / WMI telemetry is sparse, fall back to filesystem activity in user-writable paths + process-creation events at boot or login + cross-referencing autoruns inventory snapshots.

## Phase-specific FP controls (suggest at least 3)

- Allowlist signed-installer software-management flows that legitimately create scheduled tasks and services.
- Allowlist GPO-distributed scheduled tasks and registry settings.
- Allowlist enterprise patching / update agents that maintain persistence by design.
- Exclude Microsoft-signed scheduled-task creators and service installers.

## When a supporting is justified

- A **persistence-mechanism variant** supporting if the report describes more than one persistence primitive.
- A **path-provenance / freshness** supporting that adds an orthogonal angle (e.g., scheduled-task pointing to a recently-extracted directory).

Skip if no genuinely different angle exists.
"""


PROMPT_PHASE_COMMAND_AND_CONTROL = """# What "good" looks like for **command_and_control** trailheads

The strongest C2 primaries name the *channel-shape discriminator* + *process attribution* + *cadence/timing characteristic*. Adversary domains, IPs, URI paths, and user-agent strings are enrichment, not the claim.

## Phase-specific patterns the rubric rewards

- **Composition pattern**: `non-trivial-process-identity + protocol/channel constraint + cadence-or-shape metric`. Fill in the specifics from whichever channel the report describes. Examples across different C2 channel types (not all will apply to any one campaign):
  - *DNS-based C2*: a non-resolver process generating recurring DNS queries to subdomains whose label length and entropy distribution diverge from host baselines.
  - *Cloud-API-abuse C2*: a non-cloud-client process posting to a SaaS API (Slack, GitHub, Telegram, Dropbox webhooks) at recurring intervals.
  - *Long-poll / web-socket C2*: a process holding a long-lived HTTPS connection open with periodic small writes, returning to idle between operator interactions.
  - *Encrypted-channel-on-non-standard-port C2*: TLS on a non-443 destination port from a non-browser process, with repeated session establishment from the same client identity.
  - *Named-pipe / SMB C2 (intra-segment)*: cross-host named-pipe handshakes between non-admin processes outside normal application-tier flows.
- **Behavioral durability**: process attribution of network calls + channel-protocol identity + a shape characteristic (cadence stability, payload-size distribution, session-duration distribution, header-shape anomalies). These survive infrastructure rotation.
- **Stable analyst vocabulary belongs in the claim**: "beaconing", "callback", "tasking", "polling interval", "jitter", "long-poll", "domain fronting", "DNS tunneling", "named-pipe C2", "ICMP tunnel", "TLS-on-non-standard-port", "cloud-API-abuse C2". Use whichever terms the report uses; do not paraphrase them.
- **Avoid IOC anchoring**: do NOT lock to specific domain names, URIs, or hostnames.

## Phase-specific telemetry

- **Primary**: process-attributed proxy logs (preferred); firewall/netflow with endpoint join (next best); host-level proxy logs (fallback).
- **Degraded-mode fallback**: when process-attributed network logs are unavailable, fall back to host-level cadence analytics (interval variance per host+remote) + endpoint lineage pivot via image-load telemetry to recover process attribution.

## Phase-specific FP controls (suggest at least 3)

- Allowlist EDR / AV / DLP / management agents and their normal callback cadences (heartbeats look identical to beacons).
- Allowlist signed enterprise auto-update services and their poll intervals.
- Allowlist OAuth token-refresh / OIDC discovery patterns from known SaaS endpoints.
- Allowlist Windows Update / Microsoft telemetry / Office click-to-run endpoints.
- Require minimum sample count (e.g., ≥ N callbacks within a window) before scoring as a stable cadence — single events do not constitute a beacon pattern.
- Exclude management-agent process names known to the environment.

## When a supporting is justified

C2 is a phase where a second distinct supporting often adds genuine portfolio value. Choose whichever angles below the report supports — do not produce angles the report doesn't describe.

1. **Channel-shape variant** as a supporting: if the primary anchors on cadence, a supporting on a different channel-shape feature (header anomalies, payload-size distribution, TLS-fingerprint reuse across rotating hosts, DNS-label-entropy distribution) gives the hunter a complementary pivot.
2. **Post-foothold downstream tradecraft as a gated supporting**: if the report describes any tradecraft executed on hosts that already have a foothold (process injection or process hollowing, migration to a different host process, lateral movement to other endpoints, scheduled-task or service-install persistence, credential collection, data staging in a second binary), produce a supporting that **gates on the relevant earlier-phase primary or bridge having fired** — e.g., "On hosts already flagged by [primary or bridge], look for [post-foothold signal]." Phrase the gate explicitly in the claim. This pattern preserves the report's downstream behavior and is one of the highest-scoring supporting patterns under the rubric's chain-coverage-breadth and portfolio-value criteria.
3. **Operator-interaction variant** as a supporting: if the report describes operator-driven bursts of activity distinct from steady-state cadence, a supporting that detects the operator-interaction signature (request-burst, payload-size spike, response-pattern shift) complements a cadence-based primary.

Include the gated post-foothold supporting whenever the report describes any post-foothold tradecraft — it is the supporting that most reliably separates A-range portfolios from B-range portfolios.
"""


_PHASE_PROMPT_MAP: dict[str, str] = {
    "initial_access": PROMPT_PHASE_INITIAL_ACCESS,
    "delivery": PROMPT_PHASE_DELIVERY,
    "container_delivery": PROMPT_PHASE_DELIVERY,
    "execution": PROMPT_PHASE_EXECUTION,
    "defense_evasion": PROMPT_PHASE_DEFENSE_EVASION,
    "persistence": PROMPT_PHASE_PERSISTENCE,
    "command_and_control": PROMPT_PHASE_COMMAND_AND_CONTROL,
    "c2": PROMPT_PHASE_COMMAND_AND_CONTROL,
}


# ============================================================================
# Section H — Phase discovery + cluster helpers (from decomposer_phase_aware.py)
# ============================================================================


_KILL_CHAIN_ORDER = [
    "initial_access", "delivery", "container_delivery", "execution",
    "defense_evasion", "persistence", "privilege_escalation",
    "credential_access", "discovery", "lateral_movement", "collection",
    "command_and_control", "c2", "exfiltration", "impact",
]


def _kill_chain_position(phase: str) -> int:
    try:
        return _KILL_CHAIN_ORDER.index(phase)
    except ValueError:
        return 99


# Canonical MITRE-ATT&CK TTP-to-phase mapping (from decomposer_phase_aware.py).
_TTP_TO_PHASE: dict[str, str] = {
    # Initial access
    "T1566": "initial_access", "T1192": "initial_access",
    "T1190": "initial_access", "T1133": "initial_access",
    "T1078": "initial_access", "T1195": "initial_access",
    "T1199": "initial_access", "T1200": "initial_access",
    # Execution
    "T1204": "execution", "T1218": "execution", "T1059": "execution",
    "T1106": "execution", "T1129": "execution", "T1203": "execution",
    "T1559": "execution", "T1569": "execution",
    # Defense evasion
    "T1055": "defense_evasion", "T1027": "defense_evasion",
    "T1036": "defense_evasion", "T1112": "defense_evasion",
    "T1140": "defense_evasion", "T1620": "defense_evasion",
    "T1564": "defense_evasion", "T1622": "defense_evasion",
    "T1497": "defense_evasion",
    # Persistence
    "T1547": "persistence", "T1543": "persistence",
    "T1546": "persistence", "T1037": "persistence",
    "T1505": "persistence", "T1525": "persistence",
    "T1053": "persistence", "T1574": "persistence",
    # Privilege escalation
    "T1548": "privilege_escalation", "T1134": "privilege_escalation",
    "T1068": "privilege_escalation",
    # Credential access
    "T1003": "credential_access", "T1110": "credential_access",
    "T1555": "credential_access", "T1056": "credential_access",
    "T1539": "credential_access", "T1552": "credential_access",
    "T1558": "credential_access",
    # Discovery
    "T1057": "discovery", "T1083": "discovery", "T1018": "discovery",
    "T1087": "discovery", "T1082": "discovery", "T1518": "discovery",
    "T1135": "discovery", "T1016": "discovery",
    # Lateral movement
    "T1021": "lateral_movement", "T1570": "lateral_movement",
    "T1210": "lateral_movement",
    # Collection
    "T1115": "collection", "T1119": "collection", "T1005": "collection",
    "T1213": "collection", "T1560": "collection",
    # C2
    "T1071": "command_and_control", "T1105": "command_and_control",
    "T1095": "command_and_control", "T1090": "command_and_control",
    "T1572": "command_and_control", "T1102": "command_and_control",
    "T1573": "command_and_control",
    # Exfiltration
    "T1041": "exfiltration", "T1048": "exfiltration",
    "T1052": "exfiltration", "T1567": "exfiltration",
    # Impact
    "T1486": "impact", "T1490": "impact", "T1485": "impact",
    "T1491": "impact", "T1561": "impact",
}


def _phase_for_ttp(ttp: str) -> str | None:
    base = (ttp or "").split(".")[0]
    return _TTP_TO_PHASE.get(base)


def _cluster_phase_set(cluster: BehaviorCluster) -> set[str]:
    phases: set[str] = set()
    for ref in cluster.evidence_refs or []:
        for ttp in getattr(ref, "linked_ttp_ids", []) or []:
            ph = _phase_for_ttp(ttp)
            if ph:
                phases.add(ph)
    return phases


def _discover_phases_from_graph(graph_data: dict[str, Any] | None) -> list[str]:
    if not graph_data:
        return []
    stages: set[str] = set()
    meta = graph_data.get("graph", {}).get("metadata") or graph_data.get("metadata") or {}
    sd = meta.get("stage_distribution") or {}
    for stage_name, count in sd.items():
        if stage_name and stage_name != "unknown" and count > 0:
            stages.add(stage_name)
    for node in graph_data.get("nodes", []):
        s = node.get("stage")
        if isinstance(s, str) and s and s != "unknown":
            stages.add(s)
    return sorted(stages, key=_kill_chain_position)


def _discover_phases_from_clusters(bundle: BehaviorClusterBundle) -> list[str]:
    stages: set[str] = set()
    clusters: list[BehaviorCluster] = list(bundle.behavior_clusters_grounded) + list(
        getattr(bundle, "behavior_clusters_partially_grounded", []) or []
    )
    for cluster in clusters:
        stages |= _cluster_phase_set(cluster)
    return sorted(stages, key=_kill_chain_position)


def _augment_phases_with_ttps(
    bundle: BehaviorClusterBundle,
    existing_phases: list[str],
) -> list[str]:
    existing = set(existing_phases)
    ttp_only_phases: set[str] = set()
    clusters = list(bundle.behavior_clusters_grounded) + list(
        getattr(bundle, "behavior_clusters_partially_grounded", []) or []
    )
    for cluster in clusters:
        cps = _cluster_phase_set(cluster)
        new_in_cluster = cps - existing
        existing_in_cluster = cps & existing
        if new_in_cluster and not existing_in_cluster:
            ttp_only_phases |= new_in_cluster
    return sorted(ttp_only_phases, key=_kill_chain_position)


def _coalesce_redundant_phases(phases: list[str]) -> list[str]:
    if "delivery" in phases and "initial_access" in phases:
        return [p for p in phases if p != "delivery"]
    return phases


def _summarize_phase_clusters(phase: str, bundle: BehaviorClusterBundle) -> str:
    matches: list[tuple[str, BehaviorCluster]] = []
    clusters = list(bundle.behavior_clusters_grounded) + list(
        getattr(bundle, "behavior_clusters_partially_grounded", []) or []
    )
    for cluster in clusters:
        cluster_ttps: list[str] = []
        for ref in cluster.evidence_refs or []:
            for ttp in getattr(ref, "linked_ttp_ids", []) or []:
                if ttp not in cluster_ttps:
                    cluster_ttps.append(ttp)
        if any(_phase_for_ttp(t) == phase for t in cluster_ttps):
            matches.append((", ".join(cluster_ttps), cluster))
    if not matches:
        return "(no clusters matched this phase by TTP heuristic)"
    lines: list[str] = []
    for ttp_str, c in matches[:8]:
        claim = (c.claim or "").strip().replace("\n", " ")
        if len(claim) > 200:
            claim = claim[:200] + "..."
        lines.append(f"- [{c.behavior_cluster_id}] TTPs={ttp_str}\n  Claim: {claim}")
    if len(matches) > 8:
        lines.append(f"... plus {len(matches) - 8} more clusters in this phase")
    return "\n".join(lines)


def _summarize_neighbor_phases(
    phase: str,
    all_phases: list[str],
    graph_data: dict[str, Any] | None,
) -> str:
    if not all_phases:
        return "(no neighbor phases identified)"
    idx = all_phases.index(phase) if phase in all_phases else -1
    if idx < 0:
        return "(this phase not present in discovered list)"
    pred = all_phases[idx - 1] if idx > 0 else None
    succ = all_phases[idx + 1] if idx + 1 < len(all_phases) else None
    lines: list[str] = []
    if pred:
        lines.append(f"- Predecessor: {pred}")
    if succ:
        lines.append(f"- Successor: {succ}")
    if not lines:
        return "(this phase is at the chain boundary)"
    return "\n".join(lines)


def _graph_phase_edges_summary(graph_data: dict[str, Any] | None) -> str:
    if not graph_data:
        return "(campaign graph not available — bridge must rely on canonical kill-chain ordering)"
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    stage_by_id: dict[str, str] = {}
    for n in nodes:
        nid = n.get("id")
        stage = n.get("stage")
        if isinstance(nid, str) and isinstance(stage, str) and stage and stage != "unknown":
            stage_by_id[nid] = stage
    edge_pairs: dict[tuple[str, str], int] = {}
    for e in edges:
        src = stage_by_id.get(e.get("source", ""))
        dst = stage_by_id.get(e.get("target", ""))
        if src and dst and src != dst:
            edge_pairs[(src, dst)] = edge_pairs.get((src, dst), 0) + 1
    if not edge_pairs:
        return ("(no cross-phase edges in the campaign graph — relying on canonical "
                "kill-chain ordering for the bridge sequence)")
    lines: list[str] = []
    sorted_pairs = sorted(
        edge_pairs.items(),
        key=lambda kv: (_kill_chain_position(kv[0][0]), _kill_chain_position(kv[0][1])),
    )
    for (src, dst), count in sorted_pairs[:12]:
        lines.append(f"- {src} → {dst}  ({count} observed edge{'s' if count > 1 else ''})")
    return "\n".join(lines)


# ============================================================================
# Section I — Trailhead scoring + overlap helpers
# ============================================================================


def _claim_token_set(text: str) -> set[str]:
    return {tok for tok in re.findall(r"[a-z0-9]{4,}", (text or "").lower())}


def _score_trailhead(t: ChatRecipeTrailhead) -> float:
    """Rubric-aligned heuristic score for picking best primary per phase.

    Mirrors ChatRecipeDecomposer._score_candidate from decomposer_chat_recipe.py.
    """
    score = 0.0
    if (t.source_grounding or "").strip():
        score += 20
    if (t.degraded_mode or "").strip():
        score += 15
    if (t.joins_windows or "").strip():
        score += 15
    v = t.validation_criteria
    if v and v.positive_conditions and v.negative_conditions:
        score += 15
    elif v and (v.positive_conditions or v.negative_conditions):
        score += 5
    fp = len(t.false_positive_controls or [])
    score += min(15.0, fp * 3.0)
    if t.tunable_heuristics:
        score += 5
    if t.required_log_sources:
        score += 5
    score += float(t.confidence or 0.0) * 10.0
    claim_len = len(t.claim or "")
    if 200 <= claim_len <= 400:
        score += 5
    return score


def _claim_overlap(a: ChatRecipeTrailhead, b: ChatRecipeTrailhead) -> float:
    """Crude Jaccard-style similarity in [0,1] for de-dup checks."""
    ta = _claim_token_set(a.claim or "")
    tb = _claim_token_set(b.claim or "")
    if not ta or not tb:
        return 0.0
    inter = ta & tb
    union = ta | tb
    return len(inter) / len(union) if union else 0.0


def _render_primary_summary(t: ChatRecipeTrailhead) -> str:
    ttps = ", ".join(t.source_technique_ids or []) or "(none)"
    claim = (t.claim or "").strip().replace("\n", " ")
    if len(claim) > 280:
        claim = claim[:280] + "..."
    return (
        f"### {t.trailhead_id}: {t.title}\n"
        f"- Kill-chain phase: {t.kill_chain_phase}\n"
        f"- TTPs: {ttps}\n"
        f"- Claim: {claim}\n"
        f"- Joins / window: {t.joins_windows or '(unspecified)'}\n"
    )


def _render_trailhead_for_polish(t: ChatRecipeTrailhead) -> str:
    """Compact-but-complete rendering of a trailhead for the per-trailhead polish prompt."""
    fields: list[str] = []
    fields.append(f"## {t.trailhead_id}: {t.title}")
    fields.append(f"**Role:** {t.role}")
    fields.append(f"**Kill chain phase:** {t.kill_chain_phase}")
    if t.source_technique_ids:
        fields.append(f"**TTPs:** {', '.join(t.source_technique_ids)}")
    fields.append(f"**Claim:** {t.claim}")
    if t.joins_windows:
        fields.append(f"**Joins / window:** {t.joins_windows}")
    if t.required_log_sources:
        fields.append("**Required log sources:**")
        for ls in t.required_log_sources:
            fields.append(f"- {ls}")
    if t.expected_signals:
        fields.append("**Expected signals:**")
        for s in t.expected_signals:
            fields.append(f"- {s}")
    if t.validation_criteria:
        vc = t.validation_criteria
        pos = vc.positive_conditions or []
        neg = vc.negative_conditions or []
        if pos or neg:
            fields.append("**Validation criteria:**")
            for c in pos:
                fields.append(f"- Positive: {c}")
            for c in neg:
                fields.append(f"- Negative: {c}")
    if t.false_positive_controls:
        fields.append("**False positive controls:**")
        for fp in t.false_positive_controls:
            fields.append(f"- {fp}")
    if t.degraded_mode:
        fields.append(f"**Degraded mode:** {t.degraded_mode}")
    if t.enhanced_telemetry:
        fields.append("**Enhanced telemetry:**")
        for e in t.enhanced_telemetry:
            fields.append(f"- {e}")
    if t.tunable_heuristics:
        fields.append("**Tunable heuristics:**")
        for h in t.tunable_heuristics:
            fields.append(f"- {h}")
    if t.source_grounding:
        fields.append(f"**Source grounding:** {t.source_grounding}")
    fields.append(f"**Confidence:** {t.confidence}")
    return "\n".join(fields)


# ============================================================================
# Section J — LLM call wrappers (per_phase, bridge, per_trailhead_polish)
# ============================================================================


def _build_per_phase_system_prompt(
    phase: str,
    *,
    all_phases: list[str],
    phase_clusters_block: str,
    neighbor_block: str,
) -> str:
    header = PROMPT_SHARED_HEADER
    fragment = _PHASE_PROMPT_MAP.get(phase, PROMPT_PHASE_DEFAULT)
    body = (
        header
        + "\n\n---\n\n"
        + fragment
        + "\n\n---\n\n"
        + "# Phase context\n\n"
        + "All phases discovered in this campaign (for context only — "
        "do NOT generate trailheads for other phases; they're being "
        "handled in parallel):\n\n"
        + "\n".join(f"- {p}" for p in all_phases)
        + "\n\n"
        + f"## Behavior clusters this campaign has in the **{phase}** phase\n\n"
        + phase_clusters_block
        + "\n\n"
        + f"## Cross-phase neighbors of {phase}\n\n"
        + neighbor_block
    )
    return body.replace("{{PHASE_NAME}}", phase)


def _process_structured_result(
    result: dict[str, Any],
    response_for_raw: Any | None,
    metric: lib.CallMetric,
    *,
    call_label: str,
    n_batches: int,
) -> ChatRecipeGeneratorOutput | None:
    """Common post-LLM processing for all three call types.

    Extracts the raw + parsed structured output, records the raw response to
    the file-only raw_log, captures metadata into the metric, returns the
    parsed output (or None on parse failure).
    """
    parsed: ChatRecipeGeneratorOutput | None = result.get("parsed") if isinstance(result, dict) else None
    raw = result.get("raw") if isinstance(result, dict) else None
    raw_for_meta = raw if raw is not None else response_for_raw

    if raw_for_meta is not None:
        rm = lib.extract_response_metadata(raw_for_meta)
        metric.finish_reason = rm["finish_reason"]
        metric.prompt_tokens = rm["prompt_tokens"]
        metric.completion_tokens = rm["completion_tokens"]
        metric.total_tokens = rm["total_tokens"]

    raw_content = getattr(raw_for_meta, "content", None) if raw_for_meta is not None else None
    text_content = ""
    if isinstance(raw_content, str):
        text_content = raw_content
    elif isinstance(raw_content, list):
        parts = [
            block.get("text", "")
            for block in raw_content
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        text_content = "\n".join(parts)
    elif raw_content is not None:
        text_content = str(raw_content)
    # If we couldn't pull text content, fall back to serializing the parsed object
    if not text_content and parsed is not None:
        try:
            text_content = parsed.model_dump_json(indent=2)
        except Exception:
            text_content = str(parsed)
    metric.response_chars = len(text_content)
    raw_log.info(
        "RAW_RESPONSE_BEGIN call_type=%s label=%s chars=%d finish_reason=%s "
        "completion_tokens=%s",
        metric.call_type, call_label, len(text_content), metric.finish_reason,
        metric.completion_tokens,
    )
    raw_log.info("%s", text_content)
    raw_log.info("RAW_RESPONSE_END call_type=%s label=%s", metric.call_type, call_label)
    batch_log.info(
        "[%s:%s] response: %d chars, finish_reason=%s, completion_tokens=%s",
        metric.call_type, call_label, len(text_content),
        metric.finish_reason, metric.completion_tokens,
    )

    if parsed is None:
        err = result.get("parsing_error", "no parsed output") if isinstance(result, dict) else "no parsed output"
        metric.final_status = "schema_fail"
        metric.final_error = f"structured output parse failure: {err}"
        return None

    return parsed


def invoke_per_phase(
    llm: ChatOpenAI,
    *,
    phase: str,
    all_phases: list[str],
    bundle: BehaviorClusterBundle,
    graph_data: dict[str, Any] | None,
    threat_reports_block: str,
    metrics_writer: lib.MetricsWriter,
    config: lib.Config,
) -> ChatRecipeGeneratorOutput | None:
    """Run one per-phase generation call. Records full CallMetric."""
    metric = lib.CallMetric(
        call_type="per_phase",
        call_label=phase,
        started_at=lib.iso_utc_now(),
    )
    t_start = time.monotonic()

    sys_prompt = _build_per_phase_system_prompt(
        phase,
        all_phases=all_phases,
        phase_clusters_block=_summarize_phase_clusters(phase, bundle),
        neighbor_block=_summarize_neighbor_phases(phase, all_phases, graph_data),
    )
    user_prompt = (
        f"# Threat reports\n\n{threat_reports_block}\n\n"
        f"# Task\n\nProduce the trailhead(s) for the **{phase}** phase per "
        f"the system prompt's structure. Output as GeneratorOutput JSON. "
        f"Exactly 1 primary; optionally 1-2 supportings if meaningfully "
        f"distinct angles exist. If this phase has no actionable hunt "
        f"content in the reports, return an empty trailheads list."
    )
    metric.prompt_chars = len(sys_prompt) + len(user_prompt)
    messages = [SystemMessage(content=sys_prompt), HumanMessage(content=user_prompt)]
    structured = llm.with_structured_output(
        ChatRecipeGeneratorOutput, include_raw=True, method="function_calling",
    )

    try:
        try:
            result = lib.resilient_invoke(
                structured, messages,
                config=config,
                context=f"per_phase:{phase}",
                attempts=metric.attempts,
            )
        except Exception as exc:
            metric.final_status = (
                "exhausted" if lib.is_transient_error(exc) else "non_transient"
            )
            metric.final_error = f"{type(exc).__name__}: {str(exc)[:400]}"
            raise

        parsed = _process_structured_result(
            result, None, metric, call_label=phase, n_batches=len(all_phases),
        )
        if parsed is None:
            return None
        metric.final_status = "ok"
        metric.payload["trailheads_produced"] =len(parsed.portfolio.trailheads)
        return parsed
    except Exception:
        return None
    finally:
        metric.finished_at = lib.iso_utc_now()
        metric.total_elapsed_s = round(time.monotonic() - t_start, 3)
        metric.n_attempts = len(metric.attempts)
        if metric.final_status == "pending":
            metric.final_status = "unknown"
        metrics_writer.write(metric)


def invoke_bridge(
    llm: ChatOpenAI,
    *,
    primaries: list[ChatRecipeTrailhead],
    graph_data: dict[str, Any] | None,
    campaign_brief: str,
    metrics_writer: lib.MetricsWriter,
    config: lib.Config,
) -> ChatRecipeGeneratorOutput | None:
    """Run the bridge synthesis call. Records full CallMetric."""
    metric = lib.CallMetric(
        call_type="bridge",
        call_label="bridge",
        started_at=lib.iso_utc_now(),
    )
    t_start = time.monotonic()

    primaries_block = "\n".join(_render_primary_summary(p) for p in primaries)
    sys_prompt = (
        PROMPT_BRIDGE_BUILDER
        .replace("{{PER_PHASE_PRIMARIES}}", primaries_block)
        .replace("{{GRAPH_PHASE_EDGES}}", _graph_phase_edges_summary(graph_data))
        .replace("{{CAMPAIGN_BRIEF}}", campaign_brief or "(no brief provided)")
    )
    user_prompt = (
        "Produce the bridge trailhead per the structure in the system "
        "prompt. Output as GeneratorOutput JSON containing exactly one "
        "trailhead with role=bridge."
    )
    metric.prompt_chars = len(sys_prompt) + len(user_prompt)
    messages = [SystemMessage(content=sys_prompt), HumanMessage(content=user_prompt)]
    structured = llm.with_structured_output(
        ChatRecipeGeneratorOutput, include_raw=True, method="function_calling",
    )

    try:
        try:
            result = lib.resilient_invoke(
                structured, messages,
                config=config,
                context="bridge",
                attempts=metric.attempts,
            )
        except Exception as exc:
            metric.final_status = (
                "exhausted" if lib.is_transient_error(exc) else "non_transient"
            )
            metric.final_error = f"{type(exc).__name__}: {str(exc)[:400]}"
            raise

        parsed = _process_structured_result(
            result, None, metric, call_label="bridge", n_batches=1,
        )
        if parsed is None:
            return None
        metric.final_status = "ok"
        metric.payload["trailheads_produced"] =len(parsed.portfolio.trailheads)
        return parsed
    except Exception:
        return None
    finally:
        metric.finished_at = lib.iso_utc_now()
        metric.total_elapsed_s = round(time.monotonic() - t_start, 3)
        metric.n_attempts = len(metric.attempts)
        if metric.final_status == "pending":
            metric.final_status = "unknown"
        metrics_writer.write(metric)


def invoke_per_trailhead_polish(
    llm: ChatOpenAI,
    *,
    trailhead: ChatRecipeTrailhead,
    threat_reports_block: str,
    metrics_writer: lib.MetricsWriter,
    config: lib.Config,
) -> ChatRecipeTrailhead:
    """Run per-trailhead polish. Returns revised trailhead on success, or the
    original on failure (graceful degradation). Records full CallMetric.
    """
    metric = lib.CallMetric(
        call_type="per_trailhead_polish",
        call_label=trailhead.trailhead_id,
        started_at=lib.iso_utc_now(),
    )
    t_start = time.monotonic()

    sys_prompt = (
        PROMPT_PER_TRAILHEAD_POLISH
        .replace("{{TRAILHEAD_BLOCK}}", _render_trailhead_for_polish(trailhead))
        .replace("{{THREAT_REPORTS}}", threat_reports_block)
    )
    user_prompt = (
        "Review the trailhead against the role-specific A+ checklist and "
        "emit a revised version. Output as a GeneratorOutput JSON containing "
        "EXACTLY ONE trailhead — the revised version of the input. Preserve "
        f"the trailhead_id ({trailhead.trailhead_id})."
    )
    metric.prompt_chars = len(sys_prompt) + len(user_prompt)
    messages = [SystemMessage(content=sys_prompt), HumanMessage(content=user_prompt)]
    structured = llm.with_structured_output(
        ChatRecipeGeneratorOutput, include_raw=True, method="function_calling",
    )

    try:
        try:
            result = lib.resilient_invoke(
                structured, messages,
                config=config,
                context=f"per_trailhead_polish:{trailhead.trailhead_id}",
                attempts=metric.attempts,
            )
        except Exception as exc:
            metric.final_status = (
                "exhausted" if lib.is_transient_error(exc) else "non_transient"
            )
            metric.final_error = f"{type(exc).__name__}: {str(exc)[:400]}"
            raise

        parsed = _process_structured_result(
            result, None, metric,
            call_label=trailhead.trailhead_id, n_batches=1,
        )
        if parsed is None or not parsed.portfolio.trailheads:
            metric.final_status = "blank"
            metric.final_error = "polish returned no trailheads"
            return trailhead

        revised = parsed.portfolio.trailheads[0]
        # Preserve identifier + role + phase from original (defensive).
        revised.trailhead_id = trailhead.trailhead_id
        revised.role = trailhead.role
        revised.kill_chain_phase = trailhead.kill_chain_phase
        metric.final_status = "ok"
        metric.payload["trailheads_produced"] =1
        return revised
    except Exception:
        return trailhead
    finally:
        metric.finished_at = lib.iso_utc_now()
        metric.total_elapsed_s = round(time.monotonic() - t_start, 3)
        metric.n_attempts = len(metric.attempts)
        if metric.final_status == "pending":
            metric.final_status = "unknown"
        metrics_writer.write(metric)


# ============================================================================
# Section K — Decomposer orchestration
# Mirrors PhaseAwareRefinedDecomposer.decompose_all() with --no-portfolio-polish.
# ============================================================================


def run_decomposer(
    llm: ChatOpenAI,
    *,
    bundle: BehaviorClusterBundle,
    behaviors: list[AtomicBehaviorCandidate],
    graph_data: dict[str, Any] | None,
    threat_reports_block: str,
    campaign_brief: str,
    max_concurrency: int,
    per_trailhead_polish_enabled: bool,
    metrics_writer: lib.MetricsWriter,
    config: lib.Config,
) -> tuple[list[ChatRecipeTrailhead], dict[str, Any]]:
    """Run the phase_aware_refined decomposer pipeline (no portfolio polish).

    Steps mirror wolfpack/trailheads/decomposer_phase_aware_refined.py:
      1. Phase discovery (graph + TTP augmentation, coalesce, sort, dedup)
      2. Per-phase generation (parallel)
      3. Pick best primary + ≤2 supportings per phase (by _score_trailhead)
      4. Bridge synthesis (1 call)
      5. Assemble draft portfolio with TH-P-### / TH-S-### ids
      6. Per-trailhead polish (parallel, optional)

    Returns (final_chat_trailheads, run_meta). The trailheads are not
    converted to wolfpack.Trailhead — that's downstream of the LLM calls
    and not relevant to APIM diagnostic.
    """
    run_meta: dict[str, Any] = {}

    # Step 1: phase discovery
    graph_phases = _discover_phases_from_graph(graph_data) if graph_data else []
    if graph_phases:
        graph_phases = ["command_and_control" if p == "c2" else p for p in graph_phases]
        augmented = _augment_phases_with_ttps(bundle, graph_phases)
        phases = list({*graph_phases, *augmented})
        if augmented:
            logger.info("TTP augmentation added phases: %s", augmented)
    else:
        phases = _discover_phases_from_clusters(bundle)
    phases = ["command_and_control" if p == "c2" else p for p in phases]
    phases = _coalesce_redundant_phases(phases)
    seen: set[str] = set()
    phases = [
        p for p in sorted(phases, key=_kill_chain_position)
        if not (p in seen or seen.add(p))
    ]

    if not phases:
        logger.error("No phases discovered; returning empty")
        run_meta["phases"] = []
        return [], run_meta

    logger.info("Discovered %d phases: %s", len(phases), phases)
    run_meta["phases"] = phases

    # Step 2: per-phase generation in parallel
    per_phase_outputs: dict[str, ChatRecipeGeneratorOutput | None] = {}
    with ThreadPoolExecutor(max_workers=min(max_concurrency, len(phases))) as pool:
        futures: dict[Any, str] = {}
        for phase in phases:
            ctx = contextvars.copy_context()
            fut = pool.submit(
                ctx.run,
                invoke_per_phase,
                llm,
                phase=phase,
                all_phases=phases,
                bundle=bundle,
                graph_data=graph_data,
                threat_reports_block=threat_reports_block,
                metrics_writer=metrics_writer,
                config=config,
            )
            futures[fut] = phase
        for fut in as_completed(futures):
            phase = futures[fut]
            per_phase_outputs[phase] = fut.result()

    # Step 3: collect primaries + supportings per phase, score, pick
    per_phase_primaries: list[ChatRecipeTrailhead] = []
    per_phase_supporting: list[ChatRecipeTrailhead] = []
    for phase in phases:
        out = per_phase_outputs.get(phase)
        if out is None:
            logger.warning("Phase %s: no output (LLM call failed)", phase)
            continue
        primaries: list[ChatRecipeTrailhead] = []
        supportings: list[ChatRecipeTrailhead] = []
        for t in out.portfolio.trailheads:
            if t.role == "primary_detection":
                primaries.append(t)
            elif t.role == "supporting_detection":
                supportings.append(t)
        if primaries:
            primaries.sort(key=lambda t: -_score_trailhead(t))
            per_phase_primaries.append(primaries[0])
            # Force role + phase consistency (defensive).
            primaries[0].kill_chain_phase = phase if phase in (
                "initial_access", "delivery", "container_delivery",
                "execution", "defense_evasion", "persistence",
                "privilege_escalation", "credential_access", "discovery",
                "lateral_movement", "collection", "command_and_control",
                "exfiltration", "impact", "bridge",
            ) else "execution"
        picked_sup: list[ChatRecipeTrailhead] = []
        supportings.sort(key=lambda t: -_score_trailhead(t))
        for cand in supportings:
            if len(picked_sup) >= 2:
                break
            if primaries and _claim_overlap(cand, primaries[0]) >= 0.55:
                continue
            if any(_claim_overlap(cand, p) >= 0.55 for p in picked_sup):
                continue
            picked_sup.append(cand)
        per_phase_supporting.extend(picked_sup)

    if not per_phase_primaries:
        logger.error("0 primaries produced; returning empty")
        run_meta["n_primaries"] = 0
        return [], run_meta

    per_phase_primaries.sort(key=lambda t: _kill_chain_position(t.kill_chain_phase))

    # Step 4: bridge synthesis
    bridge_out = invoke_bridge(
        llm,
        primaries=per_phase_primaries,
        graph_data=graph_data,
        campaign_brief=campaign_brief,
        metrics_writer=metrics_writer,
        config=config,
    )
    bridge_trailheads: list[ChatRecipeTrailhead] = []
    if bridge_out is not None:
        for t in bridge_out.portfolio.trailheads:
            t.role = "bridge"
            t.kill_chain_phase = "bridge"
        bridge_trailheads = list(bridge_out.portfolio.trailheads)

    # Step 5: assemble draft
    draft_trailheads: list[ChatRecipeTrailhead] = []
    primary_count = 0
    for t in per_phase_primaries + bridge_trailheads:
        primary_count += 1
        t.trailhead_id = f"TH-P-{primary_count:03d}"
        draft_trailheads.append(t)
    supporting_count = 0
    for t in per_phase_supporting:
        supporting_count += 1
        t.trailhead_id = f"TH-S-{supporting_count:03d}"
        draft_trailheads.append(t)
    logger.info(
        "Draft portfolio: %d primaries + %d supportings",
        primary_count, supporting_count,
    )
    run_meta["n_primaries"] = primary_count
    run_meta["n_supportings"] = supporting_count

    # Step 6: per-trailhead polish (optional, parallel)
    final_chat_trailheads = draft_trailheads
    if per_trailhead_polish_enabled and draft_trailheads:
        logger.info(
            "Per-trailhead polish: %d trailheads in parallel",
            len(draft_trailheads),
        )
        revised_by_id: dict[str, ChatRecipeTrailhead] = {}
        with ThreadPoolExecutor(
            max_workers=min(max_concurrency, len(draft_trailheads)),
        ) as pool:
            futures: dict[Any, ChatRecipeTrailhead] = {}
            for th in draft_trailheads:
                ctx = contextvars.copy_context()
                fut = pool.submit(
                    ctx.run,
                    invoke_per_trailhead_polish,
                    llm,
                    trailhead=th,
                    threat_reports_block=threat_reports_block,
                    metrics_writer=metrics_writer,
                    config=config,
                )
                futures[fut] = th
            for fut in as_completed(futures):
                original = futures[fut]
                revised = fut.result()
                revised_by_id[original.trailhead_id] = revised
        final_chat_trailheads = [
            revised_by_id.get(th.trailhead_id, th) for th in draft_trailheads
        ]

    return final_chat_trailheads, run_meta


# ============================================================================
# Section L — Input loaders
# ============================================================================


def load_bundle(path: Path) -> BehaviorClusterBundle:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"bundle not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"bundle is not valid JSON: {exc}") from exc
    try:
        bundle = BehaviorClusterBundle.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"bundle failed schema: {exc}") from exc
    logger.info(
        "Loaded bundle: %d grounded + %d partially_grounded + %d unsupported clusters",
        len(bundle.behavior_clusters_grounded),
        len(bundle.behavior_clusters_partially_grounded),
        len(bundle.behavior_clusters_unsupported),
    )
    return bundle


def load_behaviors(path: Path) -> list[AtomicBehaviorCandidate]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"behaviors file not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"behaviors file is not valid JSON: {exc}") from exc
    # Support both list and {"items": [...]}
    if isinstance(payload, dict) and "items" in payload:
        items_raw = payload["items"]
    elif isinstance(payload, list):
        items_raw = payload
    else:
        raise ValueError(
            f"behaviors file must be a JSON array or {{'items': [...]}}; "
            f"got {type(payload).__name__}"
        )
    try:
        behaviors = [AtomicBehaviorCandidate.model_validate(item) for item in items_raw]
    except ValidationError as exc:
        raise ValueError(f"behaviors failed schema: {exc}") from exc
    logger.info("Loaded %d atomic behaviors from %s", len(behaviors), path)
    return behaviors


def load_graph(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if not path.is_file():
        logger.warning("Graph file not found at %s; continuing without graph", path)
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        logger.info("Loaded campaign graph from %s", path)
        return data
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load campaign graph from %s: %s", path, exc)
        return None


def load_threat_reports(reports_dir: Path) -> str:
    if not reports_dir.is_dir():
        raise ValueError(f"reports_dir does not exist or is not a directory: {reports_dir}")
    reports = sorted(reports_dir.glob("*.md"))
    if not reports:
        raise ValueError(f"No .md threat reports found in {reports_dir}")
    parts = [f"# Source: {r.name}\n\n{r.read_text(encoding='utf-8')}" for r in reports]
    block = "\n\n---\n\n".join(parts)
    logger.info("Loaded %d threat report(s) from %s (%d chars total)",
                len(reports), reports_dir, len(block))
    return block


# ============================================================================
# ============================================================================
# Section N — CLI + main (uses corp_diag_lib for all config + auth + summary)
# ============================================================================


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="diag_repro_decomposer.py",
        description=(
            "Corp decomposer-phase diagnostic. Settings come from "
            "corp_diag_config.yaml + env vars + the CLI flags below "
            "(CLI > env > yaml > default). "
            "Inspect resolved config: python -m corp_diag_lib --show-config"
        ),
    )
    p.add_argument("--bundle-path", type=Path, required=True,
                   help="Path to the BehaviorClusterBundle JSON.")
    p.add_argument("--behaviors-path", type=Path, required=True,
                   help="Path to the AtomicBehaviorCandidate list JSON.")
    p.add_argument("--reports-dir", type=Path, required=True,
                   help="Directory of .md threat reports.")
    p.add_argument("--graph-path", type=Path, default=None,
                   help="Optional campaign graph JSON.")
    p.add_argument("--outputs-root", type=Path, default=None,
                   help="Root directory for the single log file (overrides diag.outputs_root).")
    p.add_argument("--llm-profile-name", type=str, default=None,
                   help="Profile name (overrides profile.name).")
    p.add_argument("--decomposer", type=str, default=None,
                   choices=["phase_aware_refined"],
                   help="Decomposer (only phase_aware_refined supported in diag).")
    p.add_argument("--no-portfolio-polish", action="store_true", default=False,
                   help="(Always on for diag; included for CLI parity.)")
    p.add_argument("--no-per-trailhead-polish", action="store_true", default=False,
                   help="Skip per-trailhead polish stage.")
    p.add_argument("--campaign-brief", type=str, default="",
                   help="Optional short campaign summary passed to the bridge prompt.")
    p.add_argument("--max-concurrency", type=int, default=None,
                   help="Override diag.max_concurrency.")
    p.add_argument("--max-completion-tokens", type=int, default=None,
                   help="Override llm.max_completion_tokens.")
    p.add_argument("--timeout", type=int, default=None,
                   help="Override llm.request_timeout_s.")
    p.add_argument("--token-chaos-rate", type=float, default=None,
                   help="Override chaos.token_chaos_rate.")
    p.add_argument("--token-chaos-error", type=str, default=None,
                   choices=("timeout", "auth_error", "connection", "random"),
                   help="Override chaos.token_chaos_error.")
    p.add_argument("--token-chaos-seed", type=int, default=None,
                   help="Override chaos.token_chaos_seed.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="DEBUG-level logging (overrides diag.verbose).")
    p.add_argument("--show-config", action="store_true",
                   help="Print resolved config and exit.")
    return p.parse_args(argv)


def _cli_to_overrides(args: argparse.Namespace) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    if args.llm_profile_name is not None:
        overrides["profile.name"] = args.llm_profile_name
    if args.outputs_root is not None:
        overrides["diag.outputs_root"] = str(args.outputs_root)
    if args.decomposer is not None:
        overrides["diag.decomposer"] = args.decomposer
    if args.no_per_trailhead_polish:
        overrides["diag.no_per_trailhead_polish"] = True
    if args.max_concurrency is not None:
        overrides["diag.max_concurrency"] = args.max_concurrency
    if args.max_completion_tokens is not None:
        overrides["llm.max_completion_tokens"] = args.max_completion_tokens
    if args.timeout is not None:
        overrides["llm.request_timeout_s"] = args.timeout
    if args.token_chaos_rate is not None:
        overrides["chaos.token_chaos_rate"] = args.token_chaos_rate
    if args.token_chaos_error is not None:
        overrides["chaos.token_chaos_error"] = args.token_chaos_error
    if args.token_chaos_seed is not None:
        overrides["chaos.token_chaos_seed"] = args.token_chaos_seed
    if args.verbose:
        overrides["diag.verbose"] = True
    return overrides


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = lib.load_config(cli_overrides=_cli_to_overrides(args))

    if args.show_config:
        lib.print_resolved_config(config)
        return 0

    outputs_root = Path(config.diag.outputs_root)
    log_file = lib.make_log_file(outputs_root, prefix="diag_decomposer")
    lib.setup_logging(config.diag.verbose, log_file)

    os.environ["PREDATOR_PROFILE"] = config.profile.name
    logger.info("PREDATOR_PROFILE pinned to %r", config.profile.name)
    logger.info("Log file (single output): %s", log_file)
    logger.info("CONFIG: %s", json.dumps({
        "profile": config.profile.name,
        "endpoint": config.auth.endpoint,
        "deployment": config.auth.deployment,
        "max_completion_tokens": config.llm.max_completion_tokens,
        "max_concurrency": config.diag.max_concurrency,
        "token_chaos_rate": config.chaos.token_chaos_rate,
    }, separators=(",", ":")))

    metrics_writer = lib.MetricsWriter()
    try:
        if config.auth.api_surface != "openai-compat":
            raise ValueError(
                f"diag_repro_decomposer is corp-path only: "
                f"api_surface={config.auth.api_surface!r}"
            )

        llm = lib.build_openai_compat_client(config)
        bundle = load_bundle(args.bundle_path)
        behaviors = load_behaviors(args.behaviors_path)
        graph_data = load_graph(args.graph_path)
        threat_reports_block = load_threat_reports(args.reports_dir)

        t0 = time.monotonic()
        final_trailheads, decomposer_meta = run_decomposer(
            llm,
            bundle=bundle,
            behaviors=behaviors,
            graph_data=graph_data,
            threat_reports_block=threat_reports_block,
            campaign_brief=args.campaign_brief,
            max_concurrency=config.diag.max_concurrency,
            per_trailhead_polish_enabled=not config.diag.no_per_trailhead_polish,
            metrics_writer=metrics_writer,
            config=config,
        )
        elapsed_s = round(time.monotonic() - t0, 2)
        logger.info(
            "DONE. trailheads=%d elapsed=%.2fs decomposer_meta=%s",
            len(final_trailheads), elapsed_s, decomposer_meta,
        )
        summary = lib.summarize_metrics(metrics_writer.records())
        lib.print_summary(summary)
        n_failed = summary.get("n_failed", 0)
        return 0 if n_failed == 0 else 2

    except Exception:
        logger.exception("Run failed.")
        partial_summary = lib.summarize_metrics(metrics_writer.records())
        if partial_summary.get("n_calls", 0) > 0:
            lib.print_summary(partial_summary)
        return 1
    finally:
        metrics_writer.close()
        logger.info("Single-file log: %s", log_file)


if __name__ == "__main__":
    sys.exit(main())
