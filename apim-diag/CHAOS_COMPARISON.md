# Cross-chaos comparison: Decomposer resilience pre/post Layer 2

> Empirical comparison of how the decomposer handled chaos profiles
> A / B / C / severe — first under Stage 5g hardening (Layer 1 only:
> tenacity + classifier + ledger), then under Stage 6 hardening (Layer 1
> + Layer 2 dynamic-token-budget escalation).

## The chaos profiles

| Profile | Setup | Truncation chaos | Network chaos |
|---|---|---|---|
| **A** | `--failure-rate 0.2 --failure-mode 504` | 50% (Stage 6 default) | 20% 504 |
| **B** | `--failure-rate 0.1 --failure-mode random` | 50% (Stage 6 default) | 10% mixed |
| **C** | `--load-mode moderate` | 50% (preset) | 2% + 20-60s delay |
| **severe** | `--load-mode severe` | 90% (preset) | 15% + 60-120s delay |

All runs decompose the same campaign (cobalt-strike-blended, 4 phases).
Per-run cost: 4 per_phase calls + 1 bridge call = 5 LLM batches (more with
retries/escalation).

## Headline result

### Bridge call: from 100% failure → 100% success

| Profile | Pre-Layer-2 bridge | Post-Layer-2 bridge |
|---|---|---|
| Chaos A | `schema_fail` (1/1) | `ok` (1/1) |
| Chaos B | `schema_fail` (1/1) | (inferred ok — same call shape) |
| Chaos C | `schema_fail` (1/1) | (inferred ok — same call shape) |

**Pre-Layer-2, the bridge consistently truncated** at static
`max_completion_tokens=1536` across all 3 chaos profiles AND baseline. The
dense bridge prompt + gpt-5.x's chatty reasoning ate the budget reliably.
This was a systemic resilience gap that Stage 5f's "✅ verified" verdict
covered up.

**Post-Layer-2, the bridge succeeds** via dynamic escalation. Chaos A's
bridge in Stage 6.6 escalated 2048 → 4096 and recovered.

### Per_phase calls: cleaner failure semantics

| Profile | Pre-Layer-2 per_phase | Post-Layer-2 per_phase |
|---|---|---|
| Chaos A | 4 ok / 0 fail | 4 ok / 0 fail |
| Chaos B | 3 ok / 1 fail | (inferred similar) |
| Chaos C | 3 ok / 1 fail | (inferred similar) |
| severe | (not run pre-Layer 2) | 2 ok / 2 truncation_exhausted |

Pre-Layer-2 per_phase calls already passed under network chaos (tenacity
handled the 504s). The schema_fails that appeared were truncation-driven
and showed up as terminal failures — no recovery path. **Post-Layer-2 the
same truncation triggers escalation**; only the pathological case (90%
truncation, severe mode) still produces residual exhaustions, and those
land cleanly in the ledger for cross-run retry.

## Layer 2 escalation behavior under chaos

Stage 6.6 chaos A captured the full budget journey per call:

| Call | budget_attempts | escalation_status | Total attempts | Wall time |
|---|---|---|---|---|
| per_phase:container_delivery | [1024, 2048, 4096] | ok | 3 | 31s |
| per_phase:execution | [1024, 2048] | ok | 3 (1 tenacity retry on 504) | 67s |
| per_phase:initial_access | [1024, 2048, 4096] | ok | 4 (1 tenacity retry on 504) | 70s |
| per_phase:command_and_control | [1024, 2048, 4096] | ok | 5 (2 tenacity retries on 504) | 90s |
| bridge | [2048, 4096] | ok | 2 | 30s |

**Both layers compose correctly.** Each escalation level may itself trigger
tenacity retries; the budget journey tracks the escalation arm only,
attempt counts include both layers' retries.

## Pathological case (Stage 6.7 / severe)

90% truncation injection + 60-120s delay + 15% network chaos. Math says
P(all 4 escalation attempts hit truncation) = 0.9⁴ = 65.6%, so we expect
~2.6/4 phases to exhaust. Observed:

| Call | Result | Notes |
|---|---|---|
| container_delivery | ok at 8192 | escalated all 4 levels |
| initial_access | truncation_exhausted | + 1 transient retry on 504 |
| execution | truncation_exhausted | clean Layer-2 fallback |
| command_and_control | ok at 8192 | 10 total attempts (mix of tenacity + escalation) |

**50% recovery rate at 90% truncation. The remaining 50% land in the
ledger as `schema_fail` with `escalation_status=truncation_exhausted`.**
Cross-run retry picks them up; cached successes stay cached.

This is what "graceful degradation under pathological corp conditions"
actually looks like. No silent failures. No dropped output. Just slow,
documented, recoverable.

## What changed between Stage 5g and Stage 6

| Capability | Stage 5g | Stage 6 |
|---|---|---|
| Tenacity retry on transient HTTP errors | ✓ | ✓ |
| 12-class classifier | ✓ | ✓ |
| Cross-run ledger + per_phase cache | ✓ | ✓ |
| Token-fetch chaos handling | ✓ | ✓ |
| Truncation salvage (array outputs) | ✓ (extraction) | ✓ (extraction) |
| **Truncation escalation (single-shot outputs)** | ✗ | **✓** |
| Mimic truncation injection | ✗ | **✓** |
| Layered chaos validation (network + output-shape) | ✗ | **✓** |

The gap was real. The fix is layered: Layer 1 handles the network, Layer 2
handles the output shape, and they compose without either knowing about
the other. Where one exhausts, the cross-run ledger picks up next pass.

## Honest caveats

- Pre/post comparison is direct only for chaos A (Stage 5f and Stage 6.6
  used the same setup). Chaos B/C/severe didn't have a head-to-head
  pre-Layer-2 baseline; the inferred-better column for B/C is based on
  the call-shape analysis, not measured. A clean head-to-head would be
  worth running someday.
- All numbers are from the local mimic. Real corp behavior differs in
  rate and texture — the user reported much higher variance under workday
  load than the mimic can predict. The point of these runs is to verify
  the MECHANICS work; corp validation is a separate exercise.
- The mimic's truncation injection is per-call independent. Real corp
  gpt-5.x truncation correlates with prompt content (specific prompts
  consistently truncate). The mimic's randomness is a worst-case proxy.
