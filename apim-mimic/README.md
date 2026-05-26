# apim_mimic — local fake APIM for testing corp LLM clients

> A small FastAPI service that sits between an LLM client and a real Azure
> AI Foundry deployment and **injects corp-APIM-like behavior** —
> front-door queueing delay, failure-mode surfaces, and APIM-shaped response
> headers — so you can reproduce corp pain locally without waiting for
> Monday's actual corp load.

## What problem this solves

The Corp APIM mimic (the real APIM instance in our corp tenant)
is *structurally* corp-shaped: same `/chat/completions` URL, same bearer
token shape, same APIM emits real `apim-request-id` headers. But it's
**behaviorally clean** — sub-second front-door overhead, no chaos.

The corp APIM is the opposite. Per `__human-notes/APIM-Analysis.md`:

- Tiny calls (5-token responses) regularly take **57-62s wall time** with
  only **220-240ms backend time** — that's ~57s of front-door queueing.
- Failures show up at multiple intermediary surfaces:
  - ~30s 504s (Azure Application Gateway HTML 504)
  - ~134s connection disconnects (no clean HTTP response)
  - ~194s 504s (deepest-hop timeout)
- Rate limit headers are present but not enforcement-grade.

If you test resilience changes against the clean corp mimic, your
local results lie. This wrapper closes that gap by sleeping the configured
delay and rolling configured failures *before* forwarding to Foundry, so
your client perceives a corp-like latency distribution while still getting
real Foundry responses (real `finish_reason`, real tokens, real schema).

## How it works

```
client                                                 Foundry
  │                                                       ▲
  │  POST /chat/completions                               │
  │  Authorization: Bearer <token-from-DefaultAzureCred>  │
  │                                                       │
  ▼                                                       │
┌───────────────── apim_mimic ─────────────────┐          │
│  1. sleep(delay)  ← from config              │          │
│  2. maybe raise failure ← from config        │          │
│  3. forward Authorization header unchanged   │          │
│  4. rewrite URL to /openai/deployments/...   │──────────┘
│  5. add APIM-shaped response headers         │
│  6. return Foundry response to client        │
└──────────────────────────────────────────────┘
```

**No re-auth.** The Authorization header from the incoming client is
passed through to Foundry as-is. The token from
`get_bearer_token_provider(credential, "https://ai.azure.com/.default")`
is already valid for Foundry, so the mimic doesn't need its own
credential setup.

**No APIM in the path.** The mimic talks to Foundry directly, bypassing
the real Corp APIM. This avoids fighting that APIM's 30s
`forward-request` timeout (which would kill our injected 60s queueing
delay before the test even started).

**Fake APIM headers added on response.** The wrapper synthesizes
`apim-request-id`, `x-request-id`, `x-ratelimit-*`, `request-context`
with corp-magnitude values (5M tokens / 50k requests, per the analysis).
Client-side diagnostics that look for these headers see realistic
values — though the IDs don't correlate to any real APIM log.

## Files

```
apim-mimic/
├── apim_mimic.py    ← the FastAPI service (self-contained, no shared lib)
├── config.yaml      ← all settings, with env-var name next to each value
└── README.md        ← this file
```

Self-contained — no dependency on other directories. Drop the folder
anywhere, install the deps (`fastapi uvicorn httpx pyyaml`), run.

## Running it

### Quick start

```bash
cd /Users/horhexor/Projects/ath/apim-mimic
python apim_mimic.py                                    # uses config.yaml defaults (no delay, no chaos)
```

That starts the mimic on `http://127.0.0.1:8080` with light behavior — it
just adds APIM-shaped headers and forwards. Useful baseline.

### Realistic load modes

The four presets in `config.yaml.load_presets` map to the latency bands
the analysis identified:

```bash
# Light: no delay, no chaos (just shape — useful baseline)
python apim_mimic.py --load-mode light

# Moderate shared pressure: 20-60s delay, 2% failure rate
python apim_mimic.py --load-mode moderate

# Heavy shared pressure (Monday-class): 50-90s delay, 5% failure rate
python apim_mimic.py --load-mode heavy

# Severe / unstable: 60-120s delay, 15% failure rate
python apim_mimic.py --load-mode severe
```

### Fine-grained control

Override individual knobs (CLI > env > config.yaml > default):

```bash
# Exact delay range + failure rate (overrides load_mode)
python apim_mimic.py --delay-min-ms 30000 --delay-max-ms 90000 \
                     --failure-rate 0.1 --failure-mode random

# Pick a specific failure shape instead of "random"
python apim_mimic.py --load-mode heavy --failure-mode disconnect

# Reproducible chaos (same seed → same delay samples + chaos rolls)
python apim_mimic.py --load-mode heavy --seed 42

# Bind to a non-default port
python apim_mimic.py --port 8088
```

### Via environment variables

Same precedence chain. Useful for shell-session-scoped config:

```bash
export MIMIC_LOAD_MODE=heavy
export MIMIC_PORT=8088
export MIMIC_FOUNDRY_ENDPOINT=https://my-other-foundry.openai.azure.com
python apim_mimic.py
```

### Inspecting resolved config

You should never have to wonder where a value came from. Use
`--show-config`:

```bash
$ python apim_mimic.py --show-config
==============================================================================
APIM_MIMIC — RESOLVED CONFIG
==============================================================================
  host                             = '127.0.0.1'                                          [yaml]
  port                             = 8080                                                 [yaml]
  foundry_endpoint                 = 'https://aoai-<your-foundry>.openai.azure.com'     [yaml]
  api_version                      = '2024-12-01-preview'                                 [yaml]
  load_mode                        = None                                                 [yaml]
  delay_min_ms                     = 0                                                    [yaml]
  delay_max_ms                     = 0                                                    [yaml]
  failure_rate                     = 0.0                                                  [yaml]
  failure_mode                     = 'random'                                             [yaml]
  ...

$ MIMIC_LOAD_MODE=heavy python apim_mimic.py --port 8088 --show-config
  port                             = 8088                                                 [cli]
  load_mode                        = 'heavy'                                              [env]
  ...
```

The `[cli|env|yaml|default]` tag tells you exactly which layer set each
value.

## Pointing a client at the mimic

The mimic exposes the openai-compat `/chat/completions` surface. Any
client that speaks that protocol can hit it. The **only** thing the
client needs to change is its `base_url`:

```python
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from langchain_openai import ChatOpenAI

credential = DefaultAzureCredential()
token_provider = get_bearer_token_provider(
    credential, "https://ai.azure.com/.default",
)
llm = ChatOpenAI(
    model="gpt-5-4",
    base_url="http://127.0.0.1:8080",   # ← was https://apim.corp.com/...
    api_key=token_provider,
)
```

That's it. Auth pattern preserved. Scope unchanged. The mimic accepts
the bearer token, forwards it to Foundry, and returns the response with
corp-style headers attached.

### Pointing apim-diag at it

If you're running the diag tools from `apim-diag/`, set the inline auth
endpoint to the mimic via env override:

```bash
cd /Users/horhexor/Projects/ath/apim-diag
CORP_DIAG_PROFILE_SOURCE=inline AZURE_OPENAI_ENDPOINT=http://127.0.0.1:8080 \
  python diag_repro.py --understand-output-path <path> --outputs-root /tmp/diag-vs-mimic
```

Or add a new profile in your `corp_diag_config.yaml`'s `auth:` block
that points at the mimic.

### Pointing wolfpack at it

Edit `llm-profiles.local.yaml` to add a profile, e.g. `corp-mimic-loaded`,
with `default_endpoint: "http://127.0.0.1:8080"` and the same auth
pattern as `corp`. Run wolfpack with `--llm-profile-name corp-mimic-loaded`.

## What you'll see

The mimic logs every request:

```
2026-05-22 17:59:17 [INFO] apim_mimic: [715bf08f] IN  model=gpt-5-4 body=1.5kB client_request_id=fe5da2e22b984c70b758c7d982bbf829
2026-05-22 17:59:17 [INFO] apim_mimic: [715bf08f] sleeping front-door delay 27296ms
2026-05-22 17:59:54 [INFO] apim_mimic: [715bf08f] DONE 37152ms status=200 body=5655B
```

When chaos fires:

```
2026-05-22 17:59:17 [WARNING] apim_mimic: [a1b2c3d4] CHAOS injecting 504 after 30.2s sleep
2026-05-22 17:59:47 [WARNING] apim_mimic: [a1b2c3d4] DONE 30215ms FAIL 504 injected (status=504)
```

Health check (also useful for verifying effective config at runtime):

```bash
$ curl -s http://127.0.0.1:8080/healthz | jq
{
  "status": "ok",
  "config_source": "config.yaml + env + cli",
  "foundry_endpoint": "https://aoai-<your-foundry>.openai.azure.com",
  "api_version": "2024-12-01-preview",
  "load_mode": "heavy",
  "delay_ms_effective_min": 50000,
  "delay_ms_effective_max": 90000,
  "failure_rate_effective": 0.05,
  "failure_mode": "random",
  "rate_limit_requests": 50000,
  "rate_limit_tokens": 5000000,
  "remaining_requests": 50000,
  "remaining_tokens": 5000000
}
```

## The failure modes

When chaos fires, the mimic sleeps for the failure's latency band, then
raises the configured shape:

| Mode | Sleep band | Returns | What it simulates |
|---|---|---|---|
| `504` | 28-32s | `504 Gateway Timeout` (JSON body) | Historical corp clean-baseline 504. |
| `html_gateway_504` | 28-35s | `504` with Azure Application Gateway HTML body | Multi-hop intermediary timeout. The corp Application Gateway HTML 504. |
| `disconnect` | 120-150s | Connection abruptly closed (no HTTP response) | Today's 80k-char input disconnect class. |
| `timeout` | 180-210s | `504 Upstream timeout` | Monday heavy-load 504-after-very-long-wait. |
| `auth_error` | 0.05-0.5s | `401 Unauthorized` | Quick auth-class failure. |
| `connection` | 0.05-1s | Connection error before forwarding | Network-class transient. |
| `random` | — | Picks uniformly across 504, html_gateway_504, disconnect, timeout | Realistic mix of corp failure shapes. |

Latency bands live in `config.yaml.failure_bands` — adjust there if the
analysis numbers change.

## Configuration reference

All knobs documented inline in `config.yaml`. Highlights:

| Setting | What it does | Env var |
|---|---|---|
| `host` / `port` | Where the mimic listens. Default `127.0.0.1:8080`. | `MIMIC_HOST` / `MIMIC_PORT` |
| `foundry_endpoint` | Backend Azure OpenAI/Foundry account. The mimic forwards here. | `MIMIC_FOUNDRY_ENDPOINT` |
| `api_version` | Foundry API version (in the rewritten URL's `?api-version=`). | `MIMIC_API_VERSION` |
| `load_mode` | Preset selector. Maps to the four bands the analysis identified. | `MIMIC_LOAD_MODE` |
| `delay_min_ms` / `delay_max_ms` | Direct delay range; overrides load_mode if `>0`. | `MIMIC_DELAY_MIN_MS` / `MAX_MS` |
| `failure_rate` | Per-call chaos probability. Overrides load_mode if `>0`. | `MIMIC_FAILURE_RATE` |
| `failure_mode` | Which failure shape to inject when chaos fires. | `MIMIC_FAILURE_MODE` |
| `seed` | RNG seed — reproducible delay + chaos. | `MIMIC_SEED` |
| `rate_limit.requests` / `.tokens` | Static values emitted in `x-ratelimit-limit-*` headers. | `MIMIC_RATELIMIT_*` |
| `failure_bands` | Sleep duration per failure mode (no env override; edit yaml). | — |
| `load_presets` | Maps preset name → (delay range, failure rate) (no env override; edit yaml). | — |

## When to use which mode

| Goal | Run |
|---|---|
| Verify a client speaks the API correctly | `--load-mode light` (no delay, just shape) |
| Test resilience under realistic corp load | `--load-mode heavy` or `severe` |
| Reproduce a specific failure pattern | `--failure-rate 1.0 --failure-mode <mode>` |
| A/B between two failure modes deterministically | `--seed 42 --failure-mode <mode-a>` then `--seed 42 --failure-mode <mode-b>` |
| Stress-test continuation/recovery logic | `--load-mode heavy --failure-mode disconnect --failure-rate 0.3` |

## Limitations / things this isn't

- **Not a real APIM**. It synthesizes APIM-shaped headers, but the
  `apim-request-id` it returns doesn't correlate to any real APIM log.
  Don't expect to back-trace these IDs through Azure portal.
- **Doesn't simulate APIM auth/throttling enforcement**. Quota policies,
  IP filters, JWT validation — none of that. The mimic accepts any
  bearer token and passes it through.
- **No retry on backend errors**. If Foundry itself is down, the mimic
  returns a `502 wrapper_backend_error`. That's not the corp APIM
  behavior (corp APIM may retry to a different backend).
- **No streaming**. `stream: true` requests will work end-to-end but
  the wrapper buffers the full body. For diagnostic purposes this is
  usually fine; for streaming-throughput tests it's not.
- **Single-process**. Not suitable for high-RPS load tests; uvicorn
  defaults to one worker.

## Troubleshooting

### "missing Authorization header" 401 from the mimic

The client isn't sending a bearer token. Verify:

```python
# Wrong — api_key as a string of "Bearer ..." doesn't work for ChatOpenAI
ChatOpenAI(api_key="Bearer xyz...")

# Right — api_key as the callable returned by get_bearer_token_provider
ChatOpenAI(api_key=token_provider)
```

The openai SDK calls the callable per-request to fill the Authorization
header.

### "wrapper_backend_error" 502 from the mimic

The mimic couldn't reach Foundry. Check:

- `foundry_endpoint` is reachable from the host running the mimic
- The bearer token the client sent is valid for that Foundry endpoint
- The `model` field in the request body matches an actual deployment

### Delay is shorter / longer than expected

`--show-config` to confirm the effective range. Two things can override
the preset:

- `--delay-min-ms` and `--delay-max-ms` win if set to `>0` (they
  override the preset)
- `MIMIC_DELAY_MIN_MS` / `MAX_MS` env vars

The `/healthz` endpoint also reports the *effective* range at runtime.

### Chaos never fires

Either `failure_rate` is 0 (config / env / preset light all use 0), or
the seed sequence is just unlucky for this run. Use `--seed <N>` for
reproducibility, or raise `--failure-rate 1.0` to make it fire every
call.
