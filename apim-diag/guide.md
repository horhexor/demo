# Stage 2 — Corp validation runs for `diag_repro.py`

> Step-by-step recipe to run `diag_repro.py` in your corp environment, what
> to look for, and what to share back. **Estimated time: ~10–20 min total
> for both runs**, assuming `az login` is already valid and an
> `understand-output.json` is available.

This validates that the per-call chaos handling work (12-class classifier,
exception-type-name matching, `max_retries=0` to disable openai SDK's
silent retries, `token_acquisition_failed` recognition, continuation
recovery with `(items, ok_status)` tuple) survives real corp APIM
behavior, not just the local mimic.

If both runs land cleanly we move to Stage 3 (cross-run retry safety net).
If they don't, we tune the classifier before building anything more.

---

## 0. Prerequisites checklist

Before starting, confirm in your corp shell:

| Check | Command | Expected |
|---|---|---|
| Python venv activated | `python -c "import sys; print(sys.executable)"` | Path inside your apim-diag venv |
| Wolfpack/diag deps installed | `python -c "import openai, azure.identity, azure.core.exceptions, langchain_openai, tenacity, pydantic, httpx; print('ok')"` | `ok` |
| `az login` is fresh | `az account show --query "user.name" -o tsv` | Your corp identity |
| In `apim-diag/` dir | `pwd` | `...\apim-diag` |
| `corp_diag_config.yaml` has `name: corp` | `python diag_repro.py --show-config` | Shows `profile.name: 'corp'` at top + corp endpoint+deployment lower down |
| `understand-output.json` available | `Test-Path <path>` | `True` |

If `--show-config` shows the wrong endpoint (e.g. the local mimic
`http://127.0.0.1:8080`), set the corp endpoint explicitly for the
session:

```powershell
$env:AZURE_OPENAI_ENDPOINT = "https://<your-corp-apim>/<path>"
```

---

## 1. Run 1 — Clean baseline (NO synthetic chaos)

**Goal:** measure corp's *intrinsic* chaos rate. Every chaos event you see
here is real — APIM 504s, disconnects, token chain flaps, etc. — not
injected by us.

```powershell
# From apim-diag/ directory:
python diag_repro.py `
    --understand-output-path <path-to-your-understand-output.json> `
    --outputs-root .\outputs\diag-corp-baseline `
    --extract-batch-size 1 `
    --extract-concurrency 4 `
    --max-completion-tokens 1024 `
    -v
```

**Expected runtime:** 1–5 min for a typical Cobalt-Strike-sized report
(~29 batches). Slower if corp APIM is under load.

**Console output to expect** (last ~30 lines):

```
========================================================================
RUN SUMMARY
========================================================================
-- EXTRACT_BATCH (N calls)
  ok=29 failed=0 success_rate=100.0%
  status:        {'ok': 29}
  finish_reason: {'stop': 19, 'length': 10}
  hit_token_cap: 10 (34.5%)
  retried:       <K> (...%)
  attempt_count: {1: <a>, 2: <b>, 3: <c>}
  per-attempt:   {'ok': N, 'transient_error': <K>, 'non_transient_error': 0}
  errors:        {'http_500': X, 'connection': Y, 'token_acquisition_failed': Z, ...}
  latency(s):    p50=... p95=... max=...
-- EXTRACT_CONTINUATION (M calls)
  ok=M failed=0 success_rate=100.0%
  ...
========================================================================
Single-file log: outputs\diag-corp-baseline\diag_repro_<ts>-<id>.log
```

### What "green" looks like for Run 1

- `failed=0` and `success_rate=100.0%` on both EXTRACT_BATCH and EXTRACT_CONTINUATION
- `non_transient_error: 0` in per-attempt
- Any `errors` you see should be one of these known classes (each
  should map to a retry that eventually succeeded):
  - `http_500`, `http_502`, `http_503`, `http_504` (5xx — collapsed into
    `http_500` for openai SDK exceptions)
  - `gateway_504_html` (APIM gateway HTML page)
  - `transport_disconnect`, `connection` (wire-level closes)
  - `timeout`
  - `rate_limit` (429)
  - `overloaded`
  - `token_acquisition_failed` (intermittent `az login` / KV / cred chain flap)

### What "red" looks like (worth flagging)

- `failed > 0` or `success_rate < 100%`
- `non_transient_error > 0` in per-attempt — means the classifier saw an
  exception it didn't bucketize as transient. Share the log; we add it.
- A new `errors:` key we haven't enumerated above (e.g. `non_transient`
  with a count > 0) — same: share the log; new class to add.
- Per-batch latency `max` > 300s — request timeout was hit; either corp
  is genuinely that slow or something hung.

---

## 2. Run 2 — Token-chaos validation

**Goal:** confirm the new `token_acquisition_failed` classification +
tenacity retry survives end-to-end in corp. Injects fake auth failures
on top of the real corp token provider.

```powershell
# In the same shell after Run 1 finishes:
$env:CORP_DIAG_TOKEN_CHAOS_RATE  = "0.15"
$env:CORP_DIAG_TOKEN_CHAOS_ERROR = "auth_error"
$env:CORP_DIAG_TOKEN_CHAOS_SEED  = "42"

python diag_repro.py `
    --understand-output-path <path-to-your-understand-output.json> `
    --outputs-root .\outputs\diag-corp-tokenchaos `
    --extract-batch-size 1 `
    --extract-concurrency 4 `
    --max-completion-tokens 1024 `
    -v

# IMPORTANT: clear the env vars so subsequent commands don't pick them up
Remove-Item Env:CORP_DIAG_TOKEN_CHAOS_RATE
Remove-Item Env:CORP_DIAG_TOKEN_CHAOS_ERROR
Remove-Item Env:CORP_DIAG_TOKEN_CHAOS_SEED
```

**Expected runtime:** ~2–6 min — token chaos adds tenacity retry latency
(1–30s backoff × retries) on top of Run 1's profile.

### What "green" looks like for Run 2

- `errors: {'token_acquisition_failed': X}` in per-attempt — proves the
  classifier recognized injected `ClientAuthenticationError` correctly
- `retried: K (...%)` is > 0 — proves tenacity engaged on those events
- Final `failed=0` — proves recovery worked
- An `attempt_count` line like `{1: N, 2: K, 3: J}` shows the retry
  distribution. Expect mostly `attempt=1` ok with some `attempt=2`
  recoveries; at 15% rate, maybe 1 `attempt=3` per ~30 calls (the
  chaos-twice-in-a-row case).

### What "red" looks like for Run 2

- `errors:` shows `non_transient` (count > 0) — means classifier
  misrouted `ClientAuthenticationError`; share the log.
- `retried: 0` despite `errors:` having `token_acquisition_failed`
  events — means tenacity didn't engage; share the log.
- `failed > 0` AND the failed calls' `error_class` is
  `token_acquisition_failed` AND the call had `attempt_count: 3` — that's
  the expected statistical worst case (3 chaos rolls in a row at 15%
  ≈ 0.34%). Not a bug. But worth noting.

---

## 3. What to share back

**Per run** (so two of each, total):

1. **The single log file path** printed at the very end (it'll be like
   `outputs\diag-corp-baseline\diag_repro_<ts>-<id>.log`). Either share
   the file itself, or just grep these out:

   ```powershell
   # Grep just the high-value lines:
   Select-String -Path <path-to-logfile> -Pattern "CALL_METRIC|RUN SUMMARY|^--|EXTRACT_BATCH|EXTRACT_CONTINUATION|errors:|failed=|hit_token_cap|attempt_count|TOKEN-CHAOS|TOKEN CHAOS|exhausted|non_transient_error|partial_recovery" | Out-File -FilePath <path-to-summary>.txt
   ```

2. **The console RUN SUMMARY block** — the lines between the two `===`
   bars at the end of the console output. If you have it on screen, just
   paste it; if not, grep for `RUN SUMMARY` in the log file with ~80
   lines of context after.

If you have time and the run was interesting (errors, retries, anything
unexpected), also share `Select-String -Path <log> -Pattern "WARNING\|ERROR"`
output.

---

## 4. Common errors and what they mean

| Symptom in console | Meaning | Action |
|---|---|---|
| `auth.endpoint is required` at startup | corp profile didn't resolve an endpoint | Run `python diag_repro.py --show-config` to see what's resolved; set `$env:AZURE_OPENAI_ENDPOINT` if YAML is wrong |
| `CredentialUnavailableError: DefaultAzureCredential failed` at startup | Real corp auth chain flap (not injected) | Try `az login` again; retry diag |
| `HTTP 401 Unauthorized` on first call | Bearer token issued but APIM/Foundry rejected it | Token scope wrong (`ai.azure.com` vs `cognitiveservices.azure.com`); check `corp_diag_config.yaml` `auth.scope` |
| `HTTP 404 Not Found` on first call | Endpoint URL shape wrong | Confirm `auth.endpoint` ends without `/openai/...` (openai-compat strips that); check `--show-config` |
| Run hangs >5 min before first response | Either real corp slowness or hung connection | Wait until 300s timeout; expect tenacity to retry with classified error class. If it hangs >10 min something below tenacity is stuck — Ctrl-C and share the stack trace |
| Run finishes but ALL calls are `non_transient_error` and `failed=N` | Classifier is misrouting — the exception type isn't recognized | Critical — share the log immediately; we add the exception type to the classifier before going further |
| Some `failed=K` with `error_class: token_acquisition_failed` and `attempt_count: 3` | The 3-in-a-row statistical worst case at 15% chaos | Expected; ~0.34% of calls. Note the count and continue |

---

## 5. After you share results

Based on Run 1 + Run 2 outcomes:

- **Both clean (failed=0, all errors mapped to known classes, all retried + recovered)** →
  per-call resilience is genuinely solved in corp. Proceed to **Stage 3**
  (cross-run retry safety net — the ~500 LOC status ledger + per-report
  retry + content-addressing items).
- **Unknown error class surfaced** → I add it to the classifier
  (5-min change, 1 test), you re-run, then we proceed to Stage 3.
- **Persistent failures even after retry (e.g. corp KV is genuinely
  down for minutes at a time)** → this is exactly what Stage 3 was
  designed for. Confirms the safety net is worth building.

---

## Appendix — file locations

- This guide: `apim-diag/CORP_STAGE2_RUN_GUIDE.md`
- The tool: `apim-diag/diag_repro.py`
- Shared lib: `apim-diag/corp_diag_lib.py`
- Config: `apim-diag/corp_diag_config.yaml`
- Tests (for reference): `apim-diag/test_corp_diag_lib_chaos_sync.py`,
  `apim-diag/test_diag_repro_continuation.py`
