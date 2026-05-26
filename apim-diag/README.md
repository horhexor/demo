# Corp diagnostic tools — `diag_repro.py` & `diag_repro_decomposer.py`

> Two single-purpose Python scripts that exercise the **exact** wolfpack
> auth + LLM-call pattern against the corp APIM/Foundry path, capture rich
> per-call telemetry (APIM headers, finish_reason, token usage, retry
> behavior, error class), and surface failure modes that wolfpack's
> built-in logging hides.

## TL;DR

| Tool | What it diagnoses |
|---|---|
| **`diag_repro.py`** | The **extraction phase**: ~29 small structured-output LLM calls (one per Understand context window). Tells you how the *narrow-window* call shape behaves under corp load. |
| **`diag_repro_decomposer.py`** | The **trailhead/decomposer phase**: 4-12 *large* structured-output calls (per-phase + bridge + per-trailhead-polish). Tells you how the *large-output* call shape behaves under corp load. |

Both scripts:

- Use the canonical corp auth pattern (`DefaultAzureCredential` →
  `get_bearer_token_provider("https://ai.azure.com/.default")` →
  `ChatOpenAI(model=..., base_url=..., api_key=token_provider)`).
- Produce **one single log file per run** under `--outputs-root`.
- Emit a structured `CALL_METRIC {...}` JSON line per LLM call (grep-able).
- Capture the APIM-correlation + admission-control headers
  (`apim-request-id`, `x-request-id`, `x-ratelimit-remaining-*`) on every
  attempt.
- Read all settings from `corp_diag_config.yaml` with env/CLI overrides.
  Run `python -m corp_diag_lib --show-config` (or `<tool> --show-config`)
  to see exactly where each value came from.

---

## When to reach for these

| Symptom | Run |
|---|---|
| Wolfpack run completed but quality is suspiciously low; need to know if calls were silently truncated. | `diag_repro.py` (extraction) and/or `diag_repro_decomposer.py` (decomposer) against the same inputs. |
| You want to *measure* corp APIM behavior — front-door latency, ratelimit headroom, retry rate, finish-reason distribution. | Either tool against the corp profile. |
| You're choosing between `max_completion_tokens=1024` vs `2048` and want evidence, not guesswork. | Run the decomposer diag at both values; compare `hit_token_cap` and `latency_s.max` between the two runs. |
| You suspect intermittent auth/token failures crash the workflow. | Either tool with `--token-chaos-rate 0.3` to reproduce locally. |
| You want to validate a resilience change before shipping to corp. | Either tool against the local `apim_mimic.py` (in the sibling `apim-mimic/` folder) with `--load-mode heavy`. |

---

## Architecture — how the two scripts fit together

```
                                          corp_diag_config.yaml
                                                  │
                                                  ▼
        ┌────────────────────────────  corp_diag_lib  ───────────────────────┐
        │  - load_config() + print_resolved_config()                          │
        │  - build_openai_compat_client(config)  (the canonical pattern)     │
        │  - resilient_invoke() with tenacity                                 │
        │  - CallMetric / CallAttempt / MetricsWriter                         │
        │  - APIM header capture (httpx hooks + thread-local)                 │
        │  - Error classification (transient vs non-transient)                │
        │  - Token chaos injection                                            │
        │  - Logging setup + summary helpers                                  │
        └────┬────────────────────────────┬───────────────────────────────────┘
             │ imports                    │ imports
             ▼                            ▼
       diag_repro.py             diag_repro_decomposer.py
       (extraction)              (decomposer)
             │                            │
             ▼                            ▼
       LLM endpoint (real corp APIM, personal-tenant APIM, or corp_mimic_wrapper)
```

All shared infrastructure lives in `corp_diag_lib.py`. Both tools only own
their **phase-specific** logic:

- `diag_repro.py`: Understand-output loader, context-window builder,
  extraction prompt, atomic-behavior schema, sequential/concurrent batch
  dispatch.
- `diag_repro_decomposer.py`: bundle/behaviors/graph loader, 10 inlined
  phase-aware-refined prompts, phase discovery + TTP map, ChatRecipe
  schema, per-phase + bridge + per-trailhead-polish call wrappers.

---

## `diag_repro.py` — extraction-phase diagnostic

Mirrors `python -m wolfpack.scripts.run_extraction_phase` exactly. Same
auth, same prompt, same per-window template, same sequential/concurrent
dispatch, same `max_completion_tokens` plumbing.

### Usage

```bash
python diag_repro.py \
    --understand-output-path <path-to>/understand-output.json \
    --outputs-root outputs/extraction-runs/corp \
    --llm-profile-name corp \
    --extract-batch-size 1 --extract-concurrency 8 \
    -v
```

### CLI flags

| Flag | Overrides config | Notes |
|---|---|---|
| `--understand-output-path` | n/a (required) | The extraction phase's input. Same file wolfpack consumes. |
| `--outputs-root` | `diag.outputs_root` | Where the single log file lands. |
| `--llm-profile-name` | `profile.name` | Profile to use (`corp`, `non-corp`, etc.). |
| `--extract-batch-size` | `diag.extract_batch_size` | Windows per LLM call. Use `1` to match the corp-tolerant recipe. |
| `--extract-concurrency` | `diag.extract_concurrency` | Max parallel batches. `8` matches wolfpack's recommended corp shape. |
| `--max-completion-tokens` | `llm.max_completion_tokens` | Output budget cap. **`1024` reproduces the corp truncation problem; `2048` lets it complete.** |
| `--timeout` | `llm.request_timeout_s` | Per-call HTTP timeout. |
| `--token-chaos-rate` | `chaos.token_chaos_rate` | Inject simulated token-fetch failures at this rate. |
| `--token-chaos-error` | `chaos.token_chaos_error` | `timeout` / `auth_error` / `connection` / `random`. |
| `--token-chaos-seed` | `chaos.token_chaos_seed` | RNG seed for reproducible chaos. |
| `-v / --verbose` | `diag.verbose` | DEBUG logging including `azure.*` / `httpx.*` / `openai.*`. |
| `--show-config` | n/a | Print resolved config + source per value, then exit. |

### Output (single file)

`<outputs-root>/diag_repro_<timestamp>-<uuid8>.log`

Contains:

1. **Setup**: profile resolution, auth path, ChatOpenAI construction.
2. **Per-batch**: `START`, `RAW_RESPONSE_BEGIN/END` block (full text,
   file-only — terminal stays clean), `CALL_METRIC {...}` JSON line,
   `OK`/`FAIL` line.
3. **End-of-run summary**: latency percentiles, finish-reason histogram,
   hit-token-cap rate, retry rate, per-attempt outcomes, error-class
   histogram.

### Reading the result

The five things to look at, in order:

1. **`success_rate`** in the OVERALL block. Below 95% on real corp is
   the early signal something's wrong.
2. **`finish_reason_breakdown`**. A high count of `length` means the
   output is being truncated — `max_completion_tokens` is too small.
   A `content_filter` count means Foundry's safety filter triggered.
3. **`hit_token_cap` percentage**. >5% = output budget is undersized
   for the workload shape.
4. **`latency_s` percentiles**. Compare `max` to your APIM timeout.
   If `max` is approaching the wall, the right tail is at risk.
5. **`error_class_histogram_across_attempts`**. Tells you *what kind*
   of transient errors fired (timeout, http_504, transport_disconnect,
   etc.) — informs the retry/fallback strategy.

### Common runs

```bash
# Baseline corp run (matches wolfpack's recommended shape)
python diag_repro.py \
    --understand-output-path outputs/understand-output.json \
    --outputs-root outputs/diag-baseline \
    --extract-batch-size 1 --extract-concurrency 8

# Compare 1024 vs 2048 cap to characterize truncation impact
WOLFPACK_MAX_COMPLETION_TOKENS=1024 python diag_repro.py ... --outputs-root outputs/diag-1024
WOLFPACK_MAX_COMPLETION_TOKENS=2048 python diag_repro.py ... --outputs-root outputs/diag-2048
# Compare hit_token_cap, latency_s.max, success_rate between the two.

# Reproduce intermittent auth failures locally
python diag_repro.py ... --token-chaos-rate 0.3 --token-chaos-error random --token-chaos-seed 42

# Just see what config will be used; don't run extraction
python diag_repro.py --understand-output-path /dev/null --show-config
```

---

## `diag_repro_decomposer.py` — decomposer-phase diagnostic

Mirrors `python -m wolfpack.scripts.run_trailhead_phase --decomposer
phase_aware_refined --no-portfolio-polish`. Same prompt fragments, same
phase discovery, same per-phase/bridge/per-trailhead-polish call shape.

Portfolio polish is intentionally NOT exercised (matches the
`--no-portfolio-polish` recipe — that single huge call is the one most
likely to time out under corp APIM caps; the diag focuses on the call
patterns that fit the cap).

### Usage

```bash
python diag_repro_decomposer.py \
    --bundle-path <path-to>/50_behavior_cluster_bundle_adjudicated.json \
    --behaviors-path <path-to>/10_atomic_behaviors_candidate.json \
    --reports-dir <path-to>/threat-reports-dir \
    --graph-path <path-to>/01b_campaign_graph.json \
    --outputs-root outputs/decomposer-runs/corp \
    --llm-profile-name corp \
    --decomposer phase_aware_refined --no-portfolio-polish \
    -v
```

### CLI flags

| Flag | Overrides config | Notes |
|---|---|---|
| `--bundle-path` | n/a (required) | `BehaviorClusterBundle` JSON — the adjudicated extraction output. |
| `--behaviors-path` | n/a (required) | `AtomicBehaviorCandidate` list JSON (`10_atomic_behaviors_candidate.json`). |
| `--reports-dir` | n/a (required) | Directory of `.md` threat reports the decomposer reads in addition to the bundle. |
| `--graph-path` | n/a (optional) | Campaign graph JSON. Improves phase discovery + bridge prompt. |
| `--outputs-root` | `diag.outputs_root` | Where the single log file lands. |
| `--llm-profile-name` | `profile.name` | Profile to use. |
| `--decomposer` | `diag.decomposer` | Only `phase_aware_refined` supported in diag scope. |
| `--no-portfolio-polish` | `diag.no_portfolio_polish` | Always on (parity with CLI). |
| `--no-per-trailhead-polish` | `diag.no_per_trailhead_polish` | Skips the polish stage too. Useful for tight-budget runs. |
| `--campaign-brief` | n/a | Optional short campaign summary fed to the bridge prompt. |
| `--max-concurrency` | `diag.max_concurrency` | Max parallel calls within a phase batch. |
| `--max-completion-tokens` | `llm.max_completion_tokens` | **`1024` truncates almost every per-phase call.** Use `2048` for the realistic decomposer shape. |
| `--timeout` | `llm.request_timeout_s` | Per-call HTTP timeout. |
| `--token-chaos-rate` | `chaos.token_chaos_rate` | Same as extraction diag. |
| `--token-chaos-error` | `chaos.token_chaos_error` | Same. |
| `--token-chaos-seed` | `chaos.token_chaos_seed` | Same. |
| `-v / --verbose` | `diag.verbose` | DEBUG logging. |
| `--show-config` | n/a | Print resolved config + source per value, then exit. |
| `--decomposer-ledger` | `diag.decomposer_ledger_path` | Path to JSONL status ledger. Opt-in; enables **cross-run resume** + per-call audit. See "Cross-run resume + cache" below. |
| `--decomposer-cache-root` | `diag.decomposer_cache_root` | Directory root for **per_phase** output cache. Same key derivation as the wolfpack decomposer's Stage 5d cache. Bridge + polish always run fresh (by design). |
| `--decomposer-run-id` | `diag.decomposer_run_id` | Free-form id stored in ledger rows. Useful for distinguishing back-to-back runs in audits. |

### Call-type breakdown

The decomposer makes three distinct *kinds* of LLM call. The diag's
summary breaks them out:

| `call_type` | When fired | Prompt size (typical) | Output size (typical) |
|---|---|---|---|
| `per_phase` | One per discovered kill-chain phase, in parallel. | ~4000-4500 tokens (system + threat reports + cluster summary) | 1300-1700 tokens |
| `bridge` | One after all per-phase calls return. Receives the per-phase primaries + graph edges. | ~2000-2500 tokens | 1500-2000 tokens |
| `per_trailhead_polish` | One per draft trailhead, in parallel. Optional. | ~4000-5000 tokens | 500-1500 tokens |

A typical campaign has 4 phases → 4 per_phase + 1 bridge + ~8 polish =
~13 total LLM calls (vs ~29 for extraction).

### Reading the result

Look at the **`by_call_type`** breakdown first:

- If `per_phase` has high `hit_token_cap` and low success_rate →
  `max_completion_tokens` is too small for the per-phase prompt shape.
- If `bridge` failures are common but per_phase succeeds → the bridge
  is the bottleneck (it's the biggest single call).
- If `per_trailhead_polish` is the only thing failing → use
  `--no-per-trailhead-polish` for corp-tolerant runs.

### Common runs

```bash
# Baseline with realistic cap (per APIM-Analysis.md observations)
WOLFPACK_MAX_COMPLETION_TOKENS=2048 python diag_repro_decomposer.py \
    --bundle-path .../50_behavior_cluster_bundle_adjudicated.json \
    --behaviors-path .../10_atomic_behaviors_candidate.json \
    --reports-dir .../threat-reports \
    --outputs-root outputs/diag-decomposer-baseline

# Validate the corp 1024-cap hits the wall (you'll see ~100% length truncation)
WOLFPACK_MAX_COMPLETION_TOKENS=1024 python diag_repro_decomposer.py ... \
    --outputs-root outputs/diag-decomposer-1024

# Corp-tolerant shape: skip polish + tight concurrency
python diag_repro_decomposer.py ... --no-per-trailhead-polish --max-concurrency 4
```

### Dynamic token-budget escalation (Layer 2, on by default)

The decomposer's structured-output calls escalate `max_completion_tokens`
whenever they hit `finish_reason=length`. Each escalation level retries the
SAME prompt with a doubled budget (`1024 → 2048 → 4096 → 8192`), recording
the budget journey in `CallMetric.payload.budget_attempts`. This sits ABOVE
the tenacity retry layer — Layer 1 handles transient HTTP errors, Layer 2
handles output-shape failures from chatty gpt-5.x reasoning eating the cap.

Why this matters: with a static `max_completion_tokens`, gpt-5.x's
non-deterministic reasoning length means the same prompt can succeed once
and truncate the next time. The escalation layer adapts per-call: if 1024
truncates, try 2048; if 2048 truncates, try 4096; eventually succeed or hit
the corp APIM's 30s cap (which surfaces as a transient timeout to Layer 1).

Per-call-type initial budgets:

| Call type | Initial budget | Env override |
|---|---|---|
| `per_phase` | 1024 | `CORP_DIAG_PER_PHASE_INITIAL_BUDGET` |
| `bridge` | 2048 (denser prompt) | `CORP_DIAG_BRIDGE_INITIAL_BUDGET` |
| `per_trailhead_polish` | 1024 | `CORP_DIAG_POLISH_INITIAL_BUDGET` |

Globally tunable:

| Setting | Default | Env override |
|---|---|---|
| Escalation factor (multiplier per attempt) | 2.0 | `CORP_DIAG_ESCALATION_FACTOR` |
| Max escalation attempts | 4 | `CORP_DIAG_ESCALATION_MAX_ATTEMPTS` |

Each CallMetric grows two new payload fields:
```json
"payload": {
  "budget_attempts": [1024, 2048, 4096],
  "escalation_status": "ok"  // or "truncation_exhausted"
}
```

When all escalation attempts truncate (`truncation_exhausted`), the result
is recorded in the ledger as `schema_fail` — the cross-run retry pattern
(`--decomposer-ledger` + `--decomposer-cache-root`, below) picks them up
on next run while cached successes are skipped.

### Cross-run resume + cache (opt-in)

The decomposer diag also wires the same **status-ledger + per_phase cache**
pattern the production decomposer uses. Off by default; enable by setting
`--decomposer-ledger` (and optionally `--decomposer-cache-root`).

```bash
# Run 1: enable ledger + cache
python diag_repro_decomposer.py \
    --bundle-path .../50_behavior_cluster_bundle_adjudicated.json \
    --behaviors-path .../10_atomic_behaviors_candidate.json \
    --reports-dir .../threat-reports \
    --decomposer-ledger     ./outputs/decomposer-status-ledger.jsonl \
    --decomposer-cache-root ./outputs/decomposer-cache \
    --decomposer-run-id     run-1

# Run 2: same flags → per_phase cache hits skip already-done LLM calls;
#                    ledger records each batch's latest status.
python diag_repro_decomposer.py ... \
    --decomposer-ledger     ./outputs/decomposer-status-ledger.jsonl \
    --decomposer-cache-root ./outputs/decomposer-cache \
    --decomposer-run-id     run-2
```

What lands on disk:

- `decomposer-status-ledger.jsonl` — one row per LLM call, with
  `{report_id, batch_key, call_type, status, error_class, run_id, ts, ...}`.
  Latest-row-wins per `(report_id, batch_key)`: a `schema_fail` followed by
  an `ok` is treated as `ok`.
- `decomposer-cache/<report_id>/<batch_key>.json` — pydantic-serialized
  per_phase output for each successful per_phase call. `bridge` and
  `per_trailhead_polish` calls are **not** cached (always re-run by
  design — they're sensitive to inputs that change across runs).

Why per_phase only: per_phase calls are parallel + independent, so a
cache hit is a clean skip. Bridge depends on the set of primaries
(non-deterministic), and polish interacts with portfolio arbitration —
caching either is a quality risk for no real cost win.

The diag's ledger + cache files are **byte-compatible** with the
wolfpack production decomposer's Stage 5d cache (same `compute_call_batch_key`
hash, same serialization). You can use one to seed the other.

---

## Single-file paste artifact

`diag_repro_decomposer_bundled.py` is an auto-generated single-file build
of the decomposer diag that **inlines `corp_diag_lib.py`** via an exec
shim. It exists for cases where copying the whole `apim-diag/` directory
to a corp box is awkward — you can paste this one file (plus optionally
`corp_diag_config.yaml`, env vars also work) and run.

```bash
# Same CLI, same behavior, same ledger + cache files:
python diag_repro_decomposer_bundled.py \
    --bundle-path ... --behaviors-path ... --reports-dir ... \
    --decomposer-ledger     ./outputs/ledger.jsonl \
    --decomposer-cache-root ./outputs/cache
```

The bundled file is byte-compatible with the multi-file `diag_repro_decomposer.py`:
both produce the same `report_id`, the same per_phase `batch_key`s, and
write/read the same cache file format. You can interleave runs of both
versions against a shared cache + ledger directory.

**Regenerating after lib/diag edits:**

```bash
python bundle_decomposer.py
```

The bundler reads `corp_diag_lib.py` + `diag_repro_decomposer.py`, embeds
the lib as an exec'd string with a synthetic module shim so the diag's
`lib.X` references work unchanged, and writes the result to
`diag_repro_decomposer_bundled.py`. Re-run whenever either source file
changes. The bundled file is in git; the bundler is just a build tool.

---

## Reading the output (common to both)

### Sample `CALL_METRIC` line

Each LLM call produces one of these. They're JSON, one per line.

```json
{
  "call_type": "extract_batch",
  "call_label": "batch_24_of_29",
  "started_at": "20260522T221607Z",
  "finished_at": "20260522T221616Z",
  "total_elapsed_s": 9.012,
  "prompt_chars": 1560,
  "response_chars": 4026,
  "n_attempts": 1,
  "attempts": [
    {
      "attempt_number": 1,
      "started_at": "20260522T221607Z",
      "elapsed_s": 9.011,
      "status": "ok",
      "error_class": null,
      "error_message": null,
      "client_request_id": "b844e19fdf7b40168093b825959e5d88",
      "http_status": 200,
      "apim_request_id": "d81535a5-d955-4895-9103-1d0ccf566b36",
      "x_request_id": "83ef1476-8df6-4c27-9fe1-ca0802b96d6d",
      "ratelimit_remaining_requests": 2499,
      "ratelimit_remaining_tokens": 249594,
      "ratelimit_limit_requests": 2500,
      "ratelimit_limit_tokens": 250000,
      "request_context": null,
      "apim_date": "Fri, 22 May 2026 22:16:15 GMT"
    }
  ],
  "final_status": "parse_fail",
  "final_error": "JSONDecodeError: Unterminated string starting at: line 156 column 26 (char 4020)",
  "finish_reason": "length",
  "prompt_tokens": 406,
  "completion_tokens": 1024,
  "total_tokens": 1430,
  "payload": {
    "n_windows": 1,
    "anchors": ["c7efff4a596e"],
    "behaviors_extracted": 0
  }
}
```

**What you can do with this:**

- Extract all metrics across a run: `grep "CALL_METRIC " <log> | awk '{$1=$2=$3=""; print}' | jq .`
- Find every call that hit the token cap:
  `grep "CALL_METRIC " <log> | grep -o '"finish_reason":"length"' | wc -l`
- Pivot on a specific corp APIM request:
  `grep "CALL_METRIC " <log> | grep "apim_request_id\":\"<id>" | jq .`
- Find every call where APIM ratelimit dropped sharply:
  `grep "CALL_METRIC " <log> | jq '.attempts[].ratelimit_remaining_tokens' | uniq -c`

### Final-status taxonomy

| `final_status` | Meaning | Where it fails |
|---|---|---|
| `ok` | LLM call succeeded, response parsed, schema validated. | Nowhere. |
| `blank` | HTTP 200 but `.content` empty after fence-strip. | Post-LLM. The model returned nothing useful. |
| `parse_fail` | HTTP 200, content non-empty, but JSON didn't parse. | Post-LLM. Almost always a truncation symptom (look at `finish_reason`). |
| `schema_fail` | Parsed JSON but a Pydantic validator rejected an item. | Post-LLM. The model produced shape the schema didn't expect (decomposer-only — extraction's schema is permissive enough that this is rare). |
| `exhausted` | All retries exhausted on transient errors. | The HTTP/network layer. Look at `attempts[].error_class` for the dominant class. |
| `non_transient` | First attempt raised a non-transient error; no retry. | The HTTP/network layer. `error_class=non_transient` or `local_winerror` or similar. |

### Error-class taxonomy (per-attempt)

| `error_class` | Transient? | What it means |
|---|:---:|---|
| `timeout` | ✓ | HTTP-level timeout (`timeout` / `timed out` in the exception). |
| `rate_limit` | ✓ | `429` or "rate limit" in the response. |
| `http_500` / `502` / `503` / `504` | ✓ | Backend status codes. `504` is the dominant corp APIM signal under load. |
| `gateway_504_html` | ✓ | Azure Application Gateway HTML 504. Multi-hop intermediary timeout. |
| `transport_disconnect` | ✓ | `Server disconnected without sending a response` / `RemoteProtocolError`. The corp ~134s disconnect class. |
| `overloaded` | ✓ | "overloaded" / "capacity" message — backend saturation. |
| `connection` | ✓ | Generic connection error. |
| `local_winerror` | ✗ | Windows socket-level error (10013/10054/etc.). **Host-side problem, NOT retried.** Investigate the local machine before blaming APIM. |
| `non_transient` | ✗ | Anything else (e.g. `ClientAuthenticationError`). Won't retry. |

The retry policy and the histogram use the **same classifier**, so they
can't drift apart. `local_winerror` and `non_transient` are explicitly
excluded from retries.

### End-of-run summary

Last lines of every log file. Looks like:

```
========================================================================
DIAGNOSTIC SUMMARY
========================================================================
-- OVERALL (29 calls)
  ok=20 failed=9 success_rate=69.0%
  status:        {'ok': 20, 'parse_fail': 9}
  finish_reason: {'stop': 20, 'length': 9}
  hit_token_cap: 9 (31.0%)
  retried:       0 (0.0%)
  attempt_count: {1: 29}
  per-attempt:   {'ok': 29, 'transient_error': 0, 'non_transient_error': 0}
  latency(s):    min=0.604 mean=7.424 p50=9.066 p90=10.45 p95=10.498 p99=10.659 max=10.715
  comp_tokens:   min=5 mean=696.7 p50=831.0 p90=1024.0 p95=1024.0 p99=1024.0 max=1024
  prompt_tokens: min=288 mean=342.7 p50=334.0 p90=388.2 p95=399.2 p99=413.2 max=416
-- EXTRACT_BATCH (29 calls)
  ...
========================================================================
```

The decomposer diag's summary additionally splits by `call_type`
(`PER_PHASE`, `BRIDGE`, `PER_TRAILHEAD_POLISH`).

---

## Configuration

### Precedence chain

For every setting:

```
CLI flag  >  Environment variable  >  corp_diag_config.yaml  >  built-in default
```

### Where settings live

`corp_diag_config.yaml` is the single source of truth. Every value has
its env-var name documented next to it in the file. Key sections:

| Section | Controls |
|---|---|
| `profile` | Which `corp` / `non-corp` profile to resolve. Defaults to reading `llm-profiles.local.yaml`. |
| `auth` | Endpoint, deployment, api_version, credential, scope. Used when `profile.source=inline`. |
| `llm` | `max_completion_tokens`, `request_timeout_s`, `max_retries`, retry wait bounds. |
| `chaos` | Token-fetch chaos rate + error type + seed. |
| `mimic` | Settings for the local `apim_mimic.py` (in the sibling `apim-mimic/` folder) (delay range, failure rate, etc.). |
| `diag` | Diag-tool defaults: outputs_root, batch_size, concurrency, decomposer choice. |

### Inspecting resolved config

`--show-config` is on every tool. Outputs every value with its source
tag `[cli|env|yaml|default]`. Example:

```
$ WOLFPACK_MAX_COMPLETION_TOKENS=2048 python diag_repro.py --understand-output-path /dev/null --show-config
...
[llm]
  max_completion_tokens                = 2048                       [env]
  request_timeout_s                    = 300                        [yaml]
  max_retries                          = 3                          [yaml]
...

$ python diag_repro.py --understand-output-path /dev/null --max-completion-tokens 512 --show-config
[llm]
  max_completion_tokens                = 512                        [cli]
...
```

You should never have to wonder "where did this value come from?" again.

---

## Running through the local corp-mimic wrapper

`apim_mimic.py` (in the sibling `apim-mimic/` folder) (sibling file) is a local FastAPI service that
sits between a diag and Foundry, injecting **front-door queueing delay**
and **failure-mode surfaces** that match the corp behavior documented in
`__human-notes/APIM-Analysis.md`.

Use case: validate a resilience change against corp-like delays
*without waiting until Monday* to hit corp load. The personal-tenant APIM mimic
alone doesn't reproduce the corp's 50-90s front-door queueing — the
wrapper does.

### Start the wrapper

```bash
# Light: no delay, no chaos (just adds corp-shaped APIM headers to responses)
python corp_mimic_wrapper.py --port 8088

# Moderate: 20-60s sampled delay, 2% chaos rate
python corp_mimic_wrapper.py --port 8088 --load-mode moderate --seed 42

# Heavy: 50-90s sampled delay, 5% chaos rate (matches Monday corp load)
python corp_mimic_wrapper.py --port 8088 --load-mode heavy --seed 42
```

### Point a diag at it

The pattern preserves exactly — only `base_url` changes. Two options:

**Option 1: env override** (quick, one-shot):

```bash
CORP_DIAG_PROFILE_SOURCE=inline \
AZURE_OPENAI_ENDPOINT=http://127.0.0.1:8088 \
python diag_repro.py --understand-output-path ... --outputs-root ...
```

**Option 2: add a profile** to `llm-profiles.local.yaml`:

```yaml
profiles:
  corp-loaded:
    default_provider: azure
    providers:
      azure:
        default_endpoint: "http://127.0.0.1:8088"
        api_surface: openai-compat
        default_deployment: "gpt-5-4"
        credential: DefaultAzureCredential
        credential_args:
          scope: "https://ai.azure.com/.default"
```

Then `--llm-profile-name corp-loaded`.

### What you'll see

The wrapper sleeps the configured delay before forwarding the request
to Foundry. The diag's wall-time measurement *includes* the sleep, so
the perceived corp behavior is faithful. Failures (when chaos fires)
are returned with the right HTTP status/timing per the failure band:

- `504` after ~30s (historical corp clean-baseline 504s)
- `html_gateway_504` after ~30s (Application Gateway HTML 504)
- `disconnect` after ~134s (today's 80k-char disconnect class)
- `timeout` after ~194s (Monday heavy-load 504-after-very-long-wait)

The diag classifies each of these into the appropriate `error_class`
and decides retry vs not based on transient-class membership.

---

## Token-fetch chaos

Both diags accept `--token-chaos-rate`/-`error`/-`seed` to reproduce
intermittent auth-token-acquisition failures *locally*, without needing
to wait for corp's auth service to flake.

Wraps the real bearer-token provider with a callable that rolls a coin
per request. When the roll fires, the wrapped provider raises one of:

- `timeout` — `TimeoutError("CHAOS: token retrieval timeout ...")` →
  classified `timeout` → transient → retried.
- `connection` — `ConnectionError("CHAOS: connection error ...")` →
  classified `connection` → transient → retried.
- `auth_error` — `ClientAuthenticationError("CHAOS: AADSTS50105 ...")`
  → classified `non_transient` → **not** retried, crashes the batch.

The point is to see how each failure class propagates through your retry
layer. A typical observation:

| chaos | timeout | auth_error | random |
|---|---|---|---|
| success rate at 30% rate | 55% (most recovered via retry) | 35% (no recovery — non-transient) | 65% |

---

## Troubleshooting

### "Profile 'corp' not found"

Either:
- Your `llm-profiles.local.yaml` doesn't have a `corp:` profile, or
- `profile.source` is `yaml` (default) but the file isn't being found.

Fix: `--show-config` to see what `profile.yaml_path` resolved to. If
empty, the lib walked up from the script's directory and found nothing;
either add `LLM_PROFILES_PATH=/path/to/llm-profiles.yaml` or set
`profile.source=inline` in `corp_diag_config.yaml` and fill in the
`auth:` block directly.

### Every call shows `final_status=schema_fail` with finish_reason=length

The model is hitting `max_completion_tokens` mid-emission. Either raise
the cap (`--max-completion-tokens 2048`) or narrow the work-per-call
(smaller batch size for extraction; `--no-per-trailhead-polish` for
decomposer).

### Every call shows `final_status=non_transient` with no apim_request_id

Auth is failing locally before the request ever reaches APIM. Check:
- `az login` is active (`az account show`)
- The signed-in account has access to the Foundry deployment
- The bearer token scope is correct (`https://ai.azure.com/.default`)

`--show-config` confirms what scope/endpoint/credential will be used.

### `local_winerror` in error_class histogram

Host-side networking problem, not APIM. Common culprits on Windows:
- Outbound proxy not configured
- Local firewall blocking the connection
- VPN dropping during the call

The diag deliberately doesn't retry these — retrying won't help.

### Wrapper-routed runs are slower than expected

Check the wrapper's `--load-mode`. `light` injects no delay; `heavy`
adds 50-90s per call. Match the load mode to what you're trying to
diagnose. The wrapper's `/healthz` endpoint reports its current
effective config (delay range + failure rate + load mode).

---

## What the diags instrument that wolfpack itself doesn't

Worth being explicit about, because this is exactly the gap that hid
real failures earlier in the project:

| Telemetry | wolfpack today | the diags |
|---|---|---|
| HTTP success / wall time | ✓ | ✓ |
| Token usage | ✓ | ✓ |
| `finish_reason` per call | ✗ (silently absorbed) | ✓ (separately tracked + histogrammed) |
| Per-attempt retry detail | partial | ✓ (every attempt logged with its own latency + APIM headers) |
| Error classification | binary (transient vs not) | 11 distinct classes |
| APIM correlation headers | not captured | every header in every attempt |
| Outbound `x-ms-client-request-id` | **always "Not-Set"** | unique UUID per HTTP attempt |
| Failure mode breakdown | "ok_with_failures" status | per-status `final_status_breakdown` |
| Per-call-type breakdown (decomposer) | no | `by_call_type` summary |

If you run a wolfpack run and a diag run side-by-side on the same
inputs, the diag will surface failure modes that wolfpack's "completed"
status hides.

---

## Known gaps & follow-ups

- **No MLflow autolog**. Out of scope for the file-shaped diag; if you
  want trace history + a searchable UI, enable `mlflow.langchain.autolog()`
  in parallel. The two don't conflict.
- **The decomposer diag skips `portfolio_polish`** by design
  (`--no-portfolio-polish` is always on). If you want to characterize
  that stage's behavior, you'd have to add a `--portfolio-polish` flag
  and inline the two missing prompts. Worth doing if portfolio polish
  becomes the bottleneck under corp.
- **Continuation recovery for truncated extraction calls is NOT
  exercised** in the diag — wolfpack does this (per APIM-Analysis.md
  it recovers 6/7 truncated windows with a cheap remainder call), but
  the diag deliberately doesn't, so you can see the raw truncation rate
  before recovery masks it.
- **The personal-tenant APIM mimic is structurally corp-shaped but not
  behaviorally corp-shaped** — that's what the local
  `apim_mimic.py` (in the sibling `apim-mimic/` folder) is for. Run through the wrapper when you want
  the latency distribution to match real corp.

---

## Related files

```
apim-diag/                              ← this folder
├── corp_diag_config.yaml               ← single source of truth for all settings
├── corp_diag_lib.py                    ← shared library (auth, retry, instrumentation,
│                                          ledger + per_phase cache, config)
├── diag_repro.py                       ← extraction-phase diagnostic
├── diag_repro_decomposer.py            ← decomposer-phase diagnostic (multi-file)
├── diag_repro_decomposer_bundled.py    ← decomposer diag, single-file (lib inlined).
│                                          Auto-generated — see bundle_decomposer.py.
├── bundle_decomposer.py                ← build tool: regenerates the bundled file.
└── README.md                           ← this file

apim-mimic/                      ← separate sibling folder (the fake APIM)
├── apim_mimic.py                ← local FastAPI service that mimics corp APIM behavior
├── config.yaml                  ← mimic-specific settings
└── README.md                    ← how to run the mimic + integration with apim-diag

predator/                        ← the wolfpack project (separate)
└── llm-profiles.local.yaml      ← wolfpack's profile data. apim-diag can OPTIONALLY
                                   share it via profile.source=yaml +
                                   profile.yaml_path; default is profile.source=inline
                                   so apim-diag stands alone.

__human-notes/
└── APIM-Analysis.md             ← what the corp APIM actually does, with measured numbers
```
