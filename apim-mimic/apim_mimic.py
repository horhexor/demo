"""apim_mimic — local FastAPI service that mimics corp APIM behavior.

Sits between an LLM client (e.g. the apim-diag tools or wolfpack itself)
and a real Foundry deployment. Injects:

  - **Front-door queueing delay** sampled from a configurable range (the
    dominant pain pattern in corp APIM per APIM-Analysis.md observations).
  - **Failure-mode surfaces** at realistic latency bands (~30s 504s,
    ~134s disconnects, ~194s 504s).
  - **APIM-shaped response headers** with corp-magnitude values
    (`apim-request-id`, `x-request-id`, `x-ratelimit-*`, `request-context`).

Pattern the client side preserves:

    credential = DefaultAzureCredential()
    token_provider = get_bearer_token_provider(credential, "https://ai.azure.com/.default")
    llm = ChatOpenAI(
        model=<deployment>,
        base_url="http://localhost:8080",   # ← only thing that changes
        api_key=token_provider,
    )

The mimic:
  1. Receives POST /chat/completions with Authorization: Bearer <token>
  2. Sleeps the configured delay (front-door queueing simulation)
  3. Optionally rolls a configured failure (504 / disconnect / timeout / html_gateway / auth_error / connection)
  4. Forwards the SAME bearer token to Foundry — no re-auth, no token storage
  5. URL-rewrites to {foundry_endpoint}/openai/deployments/{model}/chat/completions?api-version=...
  6. Adds APIM-shaped response headers with corp-magnitude values
  7. Returns the Foundry response (so finish_reason, tokens, schema all real)

SELF-CONTAINED: this file has no dependency on apim-diag/corp_diag_lib.
Settings load from config.yaml + env vars + CLI in CLI > env > yaml > default
precedence. `--show-config` prints every value with its source.

Run examples:

    python apim_mimic.py                                    # uses yaml defaults
    python apim_mimic.py --load-mode heavy                  # 50-90s delay + 5% chaos
    MIMIC_LOAD_MODE=heavy python apim_mimic.py              # via env
    python apim_mimic.py --delay-min-ms 30000 --delay-max-ms 90000 \\
                         --failure-rate 0.1 --failure-mode random
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as _dt
import json
import logging
import os
import random
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

import uvicorn
import yaml
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse


logger = logging.getLogger("apim_mimic")


# ============================================================================
# Log paths, header redaction, log prefix formatting
# ============================================================================


@dataclasses.dataclass
class LogPaths:
    log_file: Path
    jsonl_file: Path
    bodies_dir: Path


def _resolve_log_paths(logs_dir: Path, *, date_str: str) -> LogPaths:
    """Compute canonical log artifact paths and ensure the dir exists.

    *date_str* is the calendar date used in filenames so a long-running mimic
    rolls naturally at midnight (no rotating-handler needed for the file we
    open per request batch).
    """
    logs_dir.mkdir(parents=True, exist_ok=True)
    return LogPaths(
        log_file=logs_dir / f"apim_mimic-{date_str}.log",
        jsonl_file=logs_dir / f"requests-{date_str}.jsonl",
        bodies_dir=logs_dir / "bodies",
    )


def _today_str() -> str:
    """Current local date as YYYY-MM-DD (used in log filenames)."""
    return _dt.date.today().isoformat()


def _now_iso() -> str:
    """Current UTC instant as ISO-8601 millisecond-precision Z."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _emit_request_trace(trace: dict[str, Any], jsonl_path: Path) -> None:
    """Append a single trace dict as a JSON line. Auto-flushed on close."""
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with open(jsonl_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(trace, ensure_ascii=False) + "\n")


def _redact_authorization(header_value: str | None) -> str:
    """Mask Authorization header values while keeping enough prefix to grep.

    For ``Bearer <token>`` we keep ``Bearer <first-3-chars>…`` so different
    tokens can still be distinguished in logs without exposing the secret.
    """
    if header_value is None:
        return "(no-auth)"
    if header_value.startswith("Bearer "):
        token = header_value[len("Bearer "):]
        prefix = token[:3]
        return f"Bearer {prefix}…[redacted {len(token)} chars]"
    return f"[redacted {len(header_value)} chars]"


def _format_log_prefix(*, request_id: str, apim_request_id: str | None) -> str:
    """Compact per-request prefix for console + log lines.

    Form: ``[req=<8> apim-id=<first8>..<last4>]`` so a CALL_METRIC's
    ``apim_request_id`` UUID grep-matches the mimic log line for the same call.
    """
    if not apim_request_id:
        apim_part = "apim-id=-"
    elif len(apim_request_id) <= 12:
        apim_part = f"apim-id={apim_request_id}"
    else:
        apim_part = f"apim-id={apim_request_id[:8]}..{apim_request_id[-4:]}"
    return f"[req={request_id} {apim_part}]"


# ============================================================================
# Runtime counters + shutdown summary
# ============================================================================


@dataclasses.dataclass
class RequestCounters:
    served: int = 0
    chaos_injected: int = 0
    foundry_errors: int = 0
    non_2xx_returned: int = 0


def _shutdown_summary_text(
    *,
    counters: RequestCounters,
    runtime_s: float,
    paths: "LogPaths",
) -> str:
    """Multi-line summary printed on SIGINT shutdown.

    Designed to give the operator the at-a-glance answer to "what did this
    mimic do during the session?" plus the paths to the artifacts they may
    want to grep / jq afterwards.
    """
    bar = "=" * 78
    return (
        "\n" + bar + "\n"
        + "apim_mimic — SHUTDOWN SUMMARY\n"
        + bar + "\n"
        + f"  runtime              : {runtime_s:.1f}s\n"
        + f"  requests served      : {counters.served}\n"
        + f"  chaos injected       : {counters.chaos_injected}\n"
        + f"  non-2xx returned     : {counters.non_2xx_returned}\n"
        + f"  foundry forward errs : {counters.foundry_errors}\n"
        + f"  log file             : {paths.log_file}\n"
        + f"  jsonl trace          : {paths.jsonl_file}\n"
        + f"  bodies dir           : {paths.bodies_dir}\n"
        + bar
    )


# ============================================================================
# Body capture writer (--capture-bodies flag)
# ============================================================================


_CONTENT_TYPE_EXT = {
    "application/json": ".json",
    "text/html":        ".html",
    "text/plain":       ".txt",
}


def _write_body_capture(
    *,
    bodies_dir: Path,
    request_id: str,
    kind: str,
    content: bytes,
    content_type: str,
) -> Path:
    """Write a single request/response body to disk for later inspection.

    *kind* is ``"in"`` for the inbound request body or ``"out"`` for the
    response body returned to the client. File extension is chosen from
    ``content_type`` (JSON/HTML/plain) with ``.bin`` as the catch-all so
    we never silently lose data.
    """
    bodies_dir.mkdir(parents=True, exist_ok=True)
    ext = _CONTENT_TYPE_EXT.get(content_type.split(";")[0].strip().lower(), ".bin")
    target = bodies_dir / f"{request_id}-{kind}{ext}"
    target.write_bytes(content)
    return target


# ============================================================================
# Request trace record builder (JSONL row)
# ============================================================================


def _build_request_trace(
    *,
    request_id: str,
    apim_request_id: str,
    client_request_id: str,
    method: str,
    path: str,
    deployment: str | None,
    body_kb_in: float,
    user_agent: str,
    front_door_delay_ms: int,
    chaos_mode: str | None,
    chaos_delay_s: float | None,
    foundry_status: int | None,
    foundry_body_size_out: int | None,
    final_status: int,
    elapsed_ms: int,
    error: str | None,
    ts_iso: str,
) -> dict[str, Any]:
    """Build one JSONL row describing a single request lifecycle.

    All fields are JSON-serializable primitives. The output of this is appended
    one-line-per-request to ``logs/requests-YYYY-MM-DD.jsonl`` for grep/jq.
    """
    return {
        "ts": ts_iso,
        "request_id": request_id,
        "apim_request_id": apim_request_id,
        "client_request_id": client_request_id,
        "method": method,
        "path": path,
        "deployment": deployment,
        "body_kb_in": body_kb_in,
        "user_agent": user_agent,
        "front_door_delay_ms": front_door_delay_ms,
        "chaos_mode": chaos_mode,
        "chaos_delay_s": chaos_delay_s,
        "foundry_status": foundry_status,
        "foundry_body_size_out": foundry_body_size_out,
        "final_status": final_status,
        "elapsed_ms": elapsed_ms,
        "error": error,
    }


_FAILURE_MODES = ("504", "html_gateway_504", "disconnect", "timeout", "auth_error", "connection", "random")
_LOAD_MODES = ("light", "moderate", "heavy", "severe")

# Source labels for the resolved-config printer:
_SRC_CLI = "cli"
_SRC_ENV = "env"
_SRC_YAML = "yaml"
_SRC_DEFAULT = "default"

DEFAULT_CONFIG_FILENAME = "config.yaml"


# ============================================================================
# Config dataclasses + loader + source tracking
# ============================================================================


@dataclasses.dataclass
class RateLimits:
    requests: int = 50000
    tokens: int = 5000000


@dataclasses.dataclass
class FailureBand:
    min_s: float
    max_s: float


@dataclasses.dataclass
class LoadPreset:
    delay_min_ms: int
    delay_max_ms: int
    failure_rate: float
    # Stage 6.4 — output-shape chaos: per-call probability of forcing
    # max_completion_tokens to a small value, causing finish_reason=length.
    # Tracks load-mode severity so "heavy" simulates Monday morning corp.
    truncation_rate: float = 0.0


def maybe_inject_truncation(
    body: dict,
    *,
    truncation_rate: float,
    forced_budget: int,
    rng: "random.Random",
) -> dict:
    """Probabilistically override ``max_completion_tokens`` to force truncation.

    Mutates ``body`` in place when injection fires. Returns a diagnostic dict
    with ``injected``, ``original_budget``, ``forced_budget`` — suitable for
    surfacing in response headers (x-mimic-truncation-*).

    Skipped cases:
      - rate=0.0 → never roll
      - body has no ``max_completion_tokens`` → can't override
      - forced_budget >= client's budget → no point (won't actually truncate)
    """
    diag = {"injected": False, "original_budget": None, "forced_budget": None}
    original = body.get("max_completion_tokens")
    if original is None or truncation_rate <= 0.0:
        return diag
    if forced_budget >= original:
        return diag
    if rng.random() >= truncation_rate:
        return diag
    body["max_completion_tokens"] = forced_budget
    diag["injected"] = True
    diag["original_budget"] = original
    diag["forced_budget"] = forced_budget
    return diag


@dataclasses.dataclass
class MimicConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    foundry_endpoint: str = "https://aoai-<your-foundry>.openai.azure.com"
    api_version: str = "2024-12-01-preview"
    load_mode: str | None = None
    delay_min_ms: int = 0
    delay_max_ms: int = 0
    failure_rate: float = 0.0
    failure_mode: str = "random"
    seed: int | None = None
    verbose: bool = False
    logs_dir: str = "logs"
    capture_bodies: bool = False
    # Stage 6.4 — output-shape chaos. On by default at 50%. Load-mode presets
    # scale this up/down (light=0.25, moderate=0.5, heavy=0.75, severe=0.9).
    # Set to 0.0 to disable (e.g., for clean-baseline runs).
    truncation_rate: float = 0.5
    truncation_budget: int = 256
    rate_limit: RateLimits = dataclasses.field(default_factory=RateLimits)
    failure_bands: dict[str, FailureBand] = dataclasses.field(default_factory=dict)
    load_presets: dict[str, LoadPreset] = dataclasses.field(default_factory=dict)
    sources: dict[str, str] = dataclasses.field(default_factory=dict)


# Per-field (dotted_path, env_var, default_value, type)
_CONFIG_SCHEMA: tuple[tuple[str, str | None, Any, type], ...] = (
    ("host",                  "MIMIC_HOST",                  "127.0.0.1", str),
    ("port",                  "MIMIC_PORT",                  8080,        int),
    ("foundry_endpoint",      "MIMIC_FOUNDRY_ENDPOINT",      "https://aoai-<your-foundry>.openai.azure.com", str),
    ("api_version",           "MIMIC_API_VERSION",           "2024-12-01-preview", str),
    ("load_mode",             "MIMIC_LOAD_MODE",             None,        str),
    ("delay_min_ms",          "MIMIC_DELAY_MIN_MS",          0,           int),
    ("delay_max_ms",          "MIMIC_DELAY_MAX_MS",          0,           int),
    ("failure_rate",          "MIMIC_FAILURE_RATE",          0.0,         float),
    ("failure_mode",          "MIMIC_FAILURE_MODE",          "random",    str),
    ("seed",                  "MIMIC_SEED",                  None,        int),
    ("verbose",               "MIMIC_VERBOSE",               False,       bool),
    ("logs_dir",              "MIMIC_LOGS_DIR",              "logs",      str),
    ("capture_bodies",        "MIMIC_CAPTURE_BODIES",        False,       bool),
    ("rate_limit.requests",   "MIMIC_RATELIMIT_REQUESTS",    50000,       int),
    ("rate_limit.tokens",     "MIMIC_RATELIMIT_TOKENS",      5000000,     int),
    # Stage 6.4 — output-shape chaos
    ("truncation_rate",       "MIMIC_TRUNCATION_RATE",       0.5,         float),
    ("truncation_budget",     "MIMIC_TRUNCATION_BUDGET",     256,         int),
)


def _coerce(value: Any, target_type: type) -> Any:
    if value is None:
        return None
    if target_type is bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if target_type is int:
        return int(value)
    if target_type is float:
        return float(value)
    return value


def _set_nested(obj: Any, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = obj
    for part in parts[:-1]:
        cur = getattr(cur, part) if dataclasses.is_dataclass(cur) else cur[part]
    last = parts[-1]
    if dataclasses.is_dataclass(cur):
        setattr(cur, last, value)
    else:
        cur[last] = value


def _get_nested(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if dataclasses.is_dataclass(cur):
            cur = getattr(cur, part)
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _find_default_yaml() -> Path | None:
    """Walk up from this file looking for config.yaml."""
    current = Path(__file__).resolve().parent
    for _ in range(10):
        candidate = current / DEFAULT_CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


_SENTINEL_MISSING = object()


def load_config(
    yaml_path: Path | None = None,
    *,
    cli_overrides: dict[str, Any] | None = None,
) -> MimicConfig:
    """Resolve config from CLI > env > yaml > default. Returns a MimicConfig
    with populated `sources` per field."""
    cli_overrides = cli_overrides or {}
    config = MimicConfig()

    yaml_data: dict[str, Any] = {}
    yaml_path = yaml_path or _find_default_yaml()
    if yaml_path and yaml_path.is_file():
        try:
            with open(yaml_path, encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f) or {}
        except Exception as exc:
            logger.warning("Failed to load %s: %s — using defaults", yaml_path, exc)
            yaml_data = {}

    for dotted, env_var, default_val, target_type in _CONFIG_SCHEMA:
        source = _SRC_DEFAULT
        value: Any = default_val

        cur: Any = yaml_data
        for part in dotted.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = _SENTINEL_MISSING
                break
        if cur is not _SENTINEL_MISSING:
            value = _coerce(cur, target_type) if cur is not None else None
            source = _SRC_YAML

        if env_var and env_var in os.environ:
            env_raw = os.environ[env_var]
            if env_raw != "":
                try:
                    value = _coerce(env_raw, target_type)
                    source = _SRC_ENV
                except (TypeError, ValueError):
                    logger.warning("env %s=%r could not be coerced to %s; ignoring",
                                   env_var, env_raw, target_type.__name__)

        if dotted in cli_overrides and cli_overrides[dotted] is not None:
            value = cli_overrides[dotted]
            source = _SRC_CLI

        _set_nested(config, dotted, value)
        config.sources[dotted] = source

    # Nested structures not in the flat schema:
    fb_yaml = yaml_data.get("failure_bands") or {}
    if fb_yaml:
        config.failure_bands = {
            k: FailureBand(min_s=float(v["min_s"]), max_s=float(v["max_s"]))
            for k, v in fb_yaml.items()
        }
        config.sources["failure_bands"] = _SRC_YAML
    else:
        config.failure_bands = {
            "504":              FailureBand(28.0, 32.0),
            "html_gateway_504": FailureBand(28.0, 35.0),
            "disconnect":       FailureBand(120.0, 150.0),
            "timeout":          FailureBand(180.0, 210.0),
        }
        config.sources["failure_bands"] = _SRC_DEFAULT

    lp_yaml = yaml_data.get("load_presets") or {}
    if lp_yaml:
        config.load_presets = {
            k: LoadPreset(
                delay_min_ms=int(v["delay_min_ms"]),
                delay_max_ms=int(v["delay_max_ms"]),
                failure_rate=float(v["failure_rate"]),
                truncation_rate=float(v.get("truncation_rate", 0.0)),
            )
            for k, v in lp_yaml.items()
        }
        config.sources["load_presets"] = _SRC_YAML
    else:
        config.load_presets = {
            # Stage 6.4: truncation_rate scales with load-mode severity.
            # Replicates corp's "Monday morning gpt-5.x is chatty + truncates often"
            # behavior. Set MIMIC_TRUNCATION_RATE explicitly to override.
            "light":    LoadPreset(0, 0, 0.0,           truncation_rate=0.25),
            "moderate": LoadPreset(20000, 60000, 0.02,  truncation_rate=0.5),
            "heavy":    LoadPreset(50000, 90000, 0.05,  truncation_rate=0.75),
            "severe":   LoadPreset(60000, 120000, 0.15, truncation_rate=0.9),
        }
        config.sources["load_presets"] = _SRC_DEFAULT

    return config


def print_resolved_config(config: MimicConfig) -> None:
    """Print every value with its resolved source (cli|env|yaml|default)."""
    bar = "=" * 78
    print(bar)
    print("APIM_MIMIC — RESOLVED CONFIG")
    print(bar)
    for dotted, _env, _default, _type in _CONFIG_SCHEMA:
        value = _get_nested(config, dotted)
        src = config.sources.get(dotted, _SRC_DEFAULT)
        print(f"  {dotted:32s} = {value!r:50s} [{src}]")
    print(f"  failure_bands                    = {config.failure_bands!r:50s} [{config.sources.get('failure_bands', _SRC_DEFAULT)}]")
    print(f"  load_presets                     = {config.load_presets!r:50s} [{config.sources.get('load_presets', _SRC_DEFAULT)}]")
    print(bar)


# ============================================================================
# Runtime state
# ============================================================================


class _State:
    config: MimicConfig
    rng: random.Random
    remaining_tokens: int = 0
    remaining_requests: int = 0
    last_token_refresh_ts: float = 0.0
    counters: RequestCounters
    log_paths: LogPaths
    started_at: float = 0.0


_state = _State()


def _init_state(config: MimicConfig) -> None:
    _state.config = config
    _state.rng = random.Random(config.seed) if config.seed is not None else random.Random()
    _state.remaining_tokens = config.rate_limit.tokens
    _state.remaining_requests = config.rate_limit.requests
    _state.last_token_refresh_ts = 0.0
    _state.counters = RequestCounters()
    # Resolve logs_dir relative to apim_mimic.py when not absolute.
    logs_dir_p = Path(config.logs_dir)
    if not logs_dir_p.is_absolute():
        logs_dir_p = (Path(__file__).resolve().parent / logs_dir_p).resolve()
    _state.log_paths = _resolve_log_paths(logs_dir_p, date_str=_today_str())
    _state.started_at = time.monotonic()


# ============================================================================
# FastAPI app
# ============================================================================


app = FastAPI(title="apim_mimic")


def _now() -> float:
    return time.monotonic()


def _effective_delay_range() -> tuple[int, int]:
    """Resolve effective (delay_min_ms, delay_max_ms) — preset if set, else direct."""
    c = _state.config
    if c.load_mode and c.load_mode in c.load_presets:
        preset = c.load_presets[c.load_mode]
        lo = c.delay_min_ms if c.delay_min_ms > 0 else preset.delay_min_ms
        hi = c.delay_max_ms if c.delay_max_ms > 0 else preset.delay_max_ms
        return lo, hi
    return c.delay_min_ms, c.delay_max_ms


def _effective_failure_rate() -> float:
    c = _state.config
    if c.load_mode and c.load_mode in c.load_presets and c.failure_rate <= 0:
        return c.load_presets[c.load_mode].failure_rate
    return c.failure_rate


def _sample_delay_ms() -> int:
    lo, hi = _effective_delay_range()
    if hi <= 0:
        return 0
    lo = max(0, lo)
    hi = max(lo, hi)
    return _state.rng.randint(lo, hi)


def _maybe_pick_failure_mode() -> str | None:
    rate = _effective_failure_rate()
    if rate <= 0 or _state.rng.random() >= rate:
        return None
    mode = _state.config.failure_mode
    if mode == "random":
        return _state.rng.choice(("504", "html_gateway_504", "disconnect", "timeout"))
    if mode not in _FAILURE_MODES:
        logger.warning("Unknown failure_mode=%r; using '504'", mode)
        return "504"
    return mode


def _refresh_rolling_remaining_tokens() -> None:
    """Approximate rolling-window behavior matching real corp APIM."""
    now = time.monotonic()
    if _state.last_token_refresh_ts == 0:
        _state.last_token_refresh_ts = now
        return
    elapsed = now - _state.last_token_refresh_ts
    if elapsed < 5.0:
        return
    limit = _state.config.rate_limit.tokens
    gap = limit - _state.remaining_tokens
    restore = int(gap * 0.01 * (elapsed / 5.0))
    _state.remaining_tokens = min(limit, _state.remaining_tokens + restore)
    _state.last_token_refresh_ts = now


def _corp_headers(*, status: int, apim_request_id: str) -> dict[str, str]:
    _refresh_rolling_remaining_tokens()
    rl = _state.config.rate_limit
    return {
        "apim-request-id": apim_request_id,
        "x-request-id": str(uuid.uuid4()),
        "x-ratelimit-limit-requests": str(rl.requests),
        "x-ratelimit-limit-tokens": str(rl.tokens),
        "x-ratelimit-remaining-requests": str(max(0, _state.remaining_requests - 1)),
        "x-ratelimit-remaining-tokens": str(_state.remaining_tokens),
        "request-context": "appId=cid-v1:apim_mimic",
        "x-mimic-injected-status": str(status),
    }


class _MimicDisconnectSignal(Exception):
    """Internal sentinel for the disconnect/connection chaos modes.

    The request handler catches this and returns a StreamingResponse whose
    body iterator raises immediately. Starlette/uvicorn translates the
    mid-stream raise into a wire-level connection close, so the client sees
    a real ``httpx.RemoteProtocolError`` (matching what corp APIM does on
    upstream disconnect) rather than the FastAPI default 500 page.
    """
    def __init__(self, delay_s: float):
        super().__init__(f"mimic disconnect after {delay_s:.2f}s sleep")
        self.delay_s = delay_s


def _build_disconnect_response(apim_request_id: str) -> StreamingResponse:
    """Return a streaming 200 response whose body iterator raises immediately,
    causing uvicorn to close the connection mid-stream (RemoteProtocolError on
    the client side)."""
    async def _abort_mid_stream():
        yield b''  # signal that headers are flushed
        raise RuntimeError("mimic-disconnect-mid-stream")  # uvicorn closes the conn

    headers = _corp_headers(status=200, apim_request_id=apim_request_id)
    headers["content-type"] = "application/json"
    return StreamingResponse(_abort_mid_stream(), status_code=200, headers=headers)


async def _inject_failure(mode: str, log_prefix: str) -> float:
    """Sleep then raise the chaos-injected error. Returns the slept duration
    (so the caller can record it in the trace)."""
    bands = _state.config.failure_bands
    band = bands.get(mode)
    if mode == "504":
        delay_s = _state.rng.uniform(band.min_s, band.max_s) if band else 30.0
        logger.warning("%s CHAOS 504 sleep=%.1fs", log_prefix, delay_s)
        await asyncio.sleep(delay_s)
        raise HTTPException(
            status_code=504,
            detail={"error": {"code": "504", "message": "Gateway Timeout (mimic-injected)"}},
        )
    if mode == "html_gateway_504":
        delay_s = _state.rng.uniform(band.min_s, band.max_s) if band else 32.0
        logger.warning("%s CHAOS html_gateway_504 sleep=%.1fs", log_prefix, delay_s)
        await asyncio.sleep(delay_s)
        html = (
            "<html><head><title>504 Gateway Timeout</title></head><body>"
            "<h1>504 Gateway Timeout</h1>"
            "<p>The proxy server did not receive a timely response from the upstream server.</p>"
            "<hr>Microsoft-Azure-Application-Gateway/v2</body></html>"
        )
        raise HTTPException(status_code=504, detail=html, headers={"content-type": "text/html"})
    if mode == "disconnect":
        delay_s = _state.rng.uniform(band.min_s, band.max_s) if band else 135.0
        logger.warning("%s CHAOS disconnect sleep=%.1fs", log_prefix, delay_s)
        await asyncio.sleep(delay_s)
        # MimicDisconnectSignal sentinel — caught by the handler and converted
        # to a StreamingResponse that aborts mid-stream (real wire-level close).
        # Raising a plain ConnectionError used to leak through Starlette's
        # default 500 handler with a full traceback in the mimic console.
        raise _MimicDisconnectSignal(delay_s)
    if mode == "timeout":
        delay_s = _state.rng.uniform(band.min_s, band.max_s) if band else 195.0
        logger.warning("%s CHAOS timeout sleep=%.1fs", log_prefix, delay_s)
        await asyncio.sleep(delay_s)
        raise HTTPException(status_code=504, detail="Upstream timeout (mimic-injected)")
    if mode == "auth_error":
        delay_s = _state.rng.uniform(0.05, 0.5)
        await asyncio.sleep(delay_s)
        logger.warning("%s CHAOS auth_error sleep=%.2fs", log_prefix, delay_s)
        raise HTTPException(status_code=401, detail="Unauthorized (mimic-injected)")
    if mode == "connection":
        delay_s = _state.rng.uniform(0.05, 1.0)
        await asyncio.sleep(delay_s)
        logger.warning("%s CHAOS connection sleep=%.2fs", log_prefix, delay_s)
        raise _MimicDisconnectSignal(delay_s)  # same shape as 'disconnect' — wire-level close
    raise ValueError(f"unknown failure mode: {mode!r}")


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    c = _state.config
    lo, hi = _effective_delay_range()
    return {
        "status": "ok",
        "config_source": "config.yaml + env + cli",
        "foundry_endpoint": c.foundry_endpoint,
        "api_version": c.api_version,
        "load_mode": c.load_mode,
        "delay_ms_effective_min": lo,
        "delay_ms_effective_max": hi,
        "failure_rate_effective": _effective_failure_rate(),
        "failure_mode": c.failure_mode,
        "rate_limit_requests": c.rate_limit.requests,
        "rate_limit_tokens": c.rate_limit.tokens,
        "remaining_requests": _state.remaining_requests,
        "remaining_tokens": _state.remaining_tokens,
    }


@app.post("/chat/completions")
async def chat_completions(request: Request) -> Response:
    req_id = uuid.uuid4().hex[:8]
    apim_request_id = str(uuid.uuid4())
    log_prefix = _format_log_prefix(request_id=req_id, apim_request_id=apim_request_id)
    t_start = _now()
    c = _state.config

    # Mutable trace state accumulated through the request lifecycle.
    trace_state: dict[str, Any] = {
        "request_id": req_id,
        "apim_request_id": apim_request_id,
        "client_request_id": request.headers.get("x-ms-client-request-id", "not-set"),
        "method": request.method,
        "path": str(request.url.path),
        "deployment": None,
        "body_kb_in": 0.0,
        "user_agent": request.headers.get("user-agent", "(unset)"),
        "front_door_delay_ms": 0,
        "chaos_mode": None,
        "chaos_delay_s": None,
        "foundry_status": None,
        "foundry_body_size_out": None,
        "final_status": 0,
        "elapsed_ms": 0,
        "error": None,
    }

    def _finalize_and_emit_trace() -> None:
        trace_state["elapsed_ms"] = int((_now() - t_start) * 1000)
        trace = _build_request_trace(ts_iso=_now_iso(), **trace_state)
        try:
            _emit_request_trace(trace, _state.log_paths.jsonl_file)
        except Exception as exc:  # last-ditch — never let logging break the handler
            logger.error("%s failed to emit JSONL trace: %s", log_prefix, exc)
        # Counters
        _state.counters.served += 1
        if trace_state["chaos_mode"]:
            _state.counters.chaos_injected += 1
        if trace_state["error"] and "foundry" in trace_state["error"].lower():
            _state.counters.foundry_errors += 1
        if trace_state["final_status"] >= 400:
            _state.counters.non_2xx_returned += 1

    try:
        auth_header = request.headers.get("authorization")
        if c.verbose:
            logger.debug("%s headers: auth=%s client-request-id=%s user-agent=%s content-length=%s",
                         log_prefix,
                         _redact_authorization(auth_header),
                         trace_state["client_request_id"],
                         trace_state["user_agent"],
                         request.headers.get("content-length", "(unset)"))

        if not auth_header:
            logger.warning("%s missing Authorization header", log_prefix)
            trace_state["final_status"] = 401
            trace_state["error"] = "missing Authorization header"
            raise HTTPException(status_code=401, detail="missing Authorization header")

        body_bytes = await request.body()
        try:
            body = json.loads(body_bytes)
        except json.JSONDecodeError as exc:
            trace_state["final_status"] = 400
            trace_state["error"] = f"invalid JSON body: {exc}"
            raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc}")

        deployment = body.get("model")
        if not deployment:
            trace_state["final_status"] = 400
            trace_state["error"] = "request body missing 'model' field"
            raise HTTPException(status_code=400, detail="request body missing 'model' field")

        trace_state["deployment"] = deployment

        # Stage 6.4: output-shape chaos — probabilistically force truncation
        # by lowering max_completion_tokens. Real Foundry returns real
        # finish_reason=length. Diagnostic state recorded in trace + headers.
        # Load-mode (if active) overrides the top-level truncation_rate.
        effective_truncation_rate = c.truncation_rate
        if c.load_mode and c.load_mode in c.load_presets:
            effective_truncation_rate = c.load_presets[c.load_mode].truncation_rate
        truncation_diag = maybe_inject_truncation(
            body,
            truncation_rate=effective_truncation_rate,
            forced_budget=c.truncation_budget,
            rng=_state.rng,
        )
        if truncation_diag["injected"]:
            # Body was mutated in place — re-serialize before forwarding.
            body_bytes = json.dumps(body).encode("utf-8")
            logger.info(
                "%s TRUNCATION-CHAOS injected: original_budget=%s forced_budget=%s",
                log_prefix, truncation_diag["original_budget"], truncation_diag["forced_budget"],
            )
            _state.counters.chaos_injected += 1

        trace_state["body_kb_in"] = round(len(body_bytes) / 1024, 1)

        # Body capture: IN
        if c.capture_bodies:
            try:
                _write_body_capture(
                    bodies_dir=_state.log_paths.bodies_dir,
                    request_id=req_id, kind="in",
                    content=body_bytes,
                    content_type=request.headers.get("content-type", "application/json"),
                )
            except Exception as exc:
                logger.warning("%s body capture (in) failed: %s", log_prefix, exc)

        logger.info("%s IN  POST /chat/completions model=%s body=%skB client-request-id=%s",
                    log_prefix, deployment, trace_state["body_kb_in"], trace_state["client_request_id"])

        # 1. Front-door delay
        delay_ms = _sample_delay_ms()
        trace_state["front_door_delay_ms"] = delay_ms
        if delay_ms > 0:
            logger.info("%s delay %.1fs", log_prefix, delay_ms / 1000.0)
            await asyncio.sleep(delay_ms / 1000.0)

        # 2. Maybe inject failure
        failure_mode = _maybe_pick_failure_mode()
        if failure_mode:
            trace_state["chaos_mode"] = failure_mode
            t_chaos = _now()
            try:
                await _inject_failure(failure_mode, log_prefix)
            except HTTPException as he:
                trace_state["chaos_delay_s"] = round(_now() - t_chaos, 3)
                trace_state["final_status"] = he.status_code
                trace_state["error"] = f"chaos-injected:{failure_mode}"
                logger.warning("%s OUT %dms %s (chaos: %s)",
                               log_prefix, int((_now() - t_start) * 1000),
                               he.status_code, failure_mode)
                headers = _corp_headers(status=he.status_code, apim_request_id=apim_request_id)
                content = he.detail
                if isinstance(content, dict):
                    out_resp = JSONResponse(status_code=he.status_code, content=content, headers=headers)
                else:
                    out_resp = Response(
                        status_code=he.status_code,
                        content=content if isinstance(content, (str, bytes)) else str(content),
                        headers={**headers, **(he.headers or {})},
                    )
                if c.capture_bodies:
                    try:
                        body_out = out_resp.body if isinstance(out_resp.body, (bytes, bytearray)) else \
                                   (content.encode() if isinstance(content, str) else json.dumps(content).encode())
                        _write_body_capture(
                            bodies_dir=_state.log_paths.bodies_dir,
                            request_id=req_id, kind="out",
                            content=bytes(body_out),
                            content_type=out_resp.headers.get("content-type", "application/json"),
                        )
                    except Exception as exc:
                        logger.warning("%s body capture (out, chaos) failed: %s", log_prefix, exc)
                return out_resp
            except _MimicDisconnectSignal as sig:
                trace_state["chaos_delay_s"] = round(sig.delay_s, 3)
                trace_state["final_status"] = 599  # synthetic — client-side will see disconnect
                trace_state["error"] = f"chaos-injected:{failure_mode} (wire-level close)"
                logger.warning("%s OUT %dms DISCONNECT (chaos: %s, wire-level)",
                               log_prefix, int((_now() - t_start) * 1000), failure_mode)
                # Real wire-level close: StreamingResponse whose iterator raises
                # mid-stream. Uvicorn translates this to a connection abort.
                return _build_disconnect_response(apim_request_id)

        # 3. Forward to Foundry directly (no APIM in the path)
        foundry_url = (
            f"{c.foundry_endpoint.rstrip('/')}"
            f"/openai/deployments/{deployment}/chat/completions"
            f"?api-version={c.api_version}"
        )
        fwd_headers = {"Authorization": auth_header, "Content-Type": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=15.0)) as client:
                foundry_resp = await client.post(foundry_url, headers=fwd_headers, content=body_bytes)
        except httpx.HTTPError as exc:
            trace_state["final_status"] = 502
            trace_state["error"] = f"FoundryError: {exc!r}"
            logger.error("%s OUT %dms 502 FOUNDRY-ERROR %s",
                         log_prefix, int((_now() - t_start) * 1000), exc)
            return JSONResponse(
                status_code=502,
                content={"error": {"code": "wrapper_backend_error", "message": str(exc)}},
                headers=_corp_headers(status=502, apim_request_id=apim_request_id),
            )

        trace_state["foundry_status"] = foundry_resp.status_code
        trace_state["foundry_body_size_out"] = len(foundry_resp.content)

        # 4. Update internal ratelimit accounting
        try:
            usage = foundry_resp.json().get("usage", {}) if foundry_resp.status_code == 200 else {}
            total_tokens = int(usage.get("total_tokens", 0))
            if total_tokens > 0:
                _state.remaining_tokens = max(0, _state.remaining_tokens - total_tokens)
        except Exception:
            pass

        # 5. Return Foundry's response with corp-shaped headers attached
        trace_state["final_status"] = foundry_resp.status_code
        logger.info("%s OUT %dms %s body=%sB",
                    log_prefix, int((_now() - t_start) * 1000),
                    foundry_resp.status_code, len(foundry_resp.content))
        out_headers = _corp_headers(status=foundry_resp.status_code, apim_request_id=apim_request_id)
        if "content-type" in foundry_resp.headers:
            out_headers["content-type"] = foundry_resp.headers["content-type"]

        # Stage 6.4: surface truncation-chaos diagnostics in response headers
        # so the client can correlate "this finish_reason=length was injected"
        # vs "this was a real model truncation".
        if truncation_diag["injected"]:
            out_headers["x-mimic-truncation-injected"] = "true"
            out_headers["x-mimic-truncation-original-budget"] = str(truncation_diag["original_budget"])
            out_headers["x-mimic-truncation-forced-budget"] = str(truncation_diag["forced_budget"])

        if c.capture_bodies:
            try:
                _write_body_capture(
                    bodies_dir=_state.log_paths.bodies_dir,
                    request_id=req_id, kind="out",
                    content=foundry_resp.content,
                    content_type=foundry_resp.headers.get("content-type", "application/json"),
                )
            except Exception as exc:
                logger.warning("%s body capture (out) failed: %s", log_prefix, exc)

        return Response(
            content=foundry_resp.content,
            status_code=foundry_resp.status_code,
            headers=out_headers,
        )
    finally:
        _finalize_and_emit_trace()


# ============================================================================
# CLI + bootstrap
# ============================================================================


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="apim_mimic.py",
        description=(
            "Local FastAPI service that mimics corp APIM behavior. "
            "Settings: CLI > env > config.yaml > defaults. "
            "Inspect resolved config with --show-config."
        ),
    )
    p.add_argument("--host", default=None, help="Bind host (overrides config host).")
    p.add_argument("--port", type=int, default=None, help="Bind port (overrides config port).")
    p.add_argument("--load-mode", type=str, default=None, choices=_LOAD_MODES,
                   help="Preset (light|moderate|heavy|severe) — sets delay range and failure rate.")
    p.add_argument("--delay-min-ms", type=int, default=None, help="Min front-door delay (ms).")
    p.add_argument("--delay-max-ms", type=int, default=None, help="Max front-door delay (ms).")
    p.add_argument("--failure-rate", type=float, default=None, help="Probability per call to inject failure [0..1].")
    p.add_argument("--failure-mode", type=str, default=None, choices=list(_FAILURE_MODES),
                   help="Which failure shape to inject when chaos fires.")
    p.add_argument("--foundry-endpoint", type=str, default=None, help="Backend Foundry endpoint.")
    p.add_argument("--api-version", type=str, default=None, help="Foundry API version.")
    p.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible chaos.")
    p.add_argument("--logs-dir", type=str, default=None,
                   help="Directory for .log + .jsonl + bodies artifacts (default: ./logs next to apim_mimic.py).")
    p.add_argument("--capture-bodies", action="store_true",
                   help="Dump each request/response body to logs/bodies/<req-id>-{in,out}.<ext> for replay (off by default — verbose, may contain prompt text).")
    # Stage 6.4 — output-shape chaos
    p.add_argument("--truncation-rate", type=float, default=None,
                   help="Per-call probability of forcing finish_reason=length by lowering "
                        "max_completion_tokens (default 0.5; auto-scaled by --load-mode). "
                        "Set 0 to disable for clean baseline.")
    p.add_argument("--truncation-budget", type=int, default=None,
                   help="Forced max_completion_tokens when truncation fires (default 256).")
    p.add_argument("-v", "--verbose", action="store_true", help="DEBUG-level logging.")
    p.add_argument("--show-config", action="store_true", help="Print resolved config + sources and exit.")
    return p.parse_args(argv)


def _cli_to_overrides(args: argparse.Namespace) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    if args.host is not None:
        overrides["host"] = args.host
    if args.port is not None:
        overrides["port"] = args.port
    if args.load_mode is not None:
        overrides["load_mode"] = args.load_mode
    if args.delay_min_ms is not None:
        overrides["delay_min_ms"] = args.delay_min_ms
    if args.delay_max_ms is not None:
        overrides["delay_max_ms"] = args.delay_max_ms
    if args.failure_rate is not None:
        overrides["failure_rate"] = args.failure_rate
    if args.failure_mode is not None:
        overrides["failure_mode"] = args.failure_mode
    if args.foundry_endpoint is not None:
        overrides["foundry_endpoint"] = args.foundry_endpoint
    if args.api_version is not None:
        overrides["api_version"] = args.api_version
    if args.seed is not None:
        overrides["seed"] = args.seed
    if args.logs_dir is not None:
        overrides["logs_dir"] = args.logs_dir
    if args.capture_bodies:
        overrides["capture_bodies"] = True
    if args.verbose:
        overrides["verbose"] = True
    if args.truncation_rate is not None:
        overrides["truncation_rate"] = args.truncation_rate
    if args.truncation_budget is not None:
        overrides["truncation_budget"] = args.truncation_budget
    return overrides


def _setup_logging(verbose: bool, *, log_file: Path | None = None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(logging.Formatter(fmt))
    root.addHandler(stream)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter(fmt))
        root.addHandler(fh)

    if not verbose:
        for noisy in ("httpx", "uvicorn.access"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = load_config(cli_overrides=_cli_to_overrides(args))

    if args.show_config:
        print_resolved_config(config)
        return 0

    _init_state(config)
    _setup_logging(config.verbose, log_file=_state.log_paths.log_file)

    lo, hi = _effective_delay_range()
    bar = "=" * 78
    logger.info(bar)
    logger.info("apim_mimic — STARTUP")
    logger.info(bar)
    logger.info("  foundry endpoint  : %s", config.foundry_endpoint)
    logger.info("  api version       : %s", config.api_version)
    logger.info("  delay window      : %d-%d ms", lo, hi)
    logger.info("  failure rate      : %.3f  (mode=%s)", _effective_failure_rate(), config.failure_mode)
    logger.info("  load mode         : %s", config.load_mode)
    logger.info("  seed              : %s", config.seed)
    logger.info("  log file          : %s", _state.log_paths.log_file)
    logger.info("  jsonl trace       : %s", _state.log_paths.jsonl_file)
    logger.info("  bodies dir        : %s%s",
                _state.log_paths.bodies_dir,
                "" if config.capture_bodies else "  (capture disabled — pass --capture-bodies)")
    logger.info("  listening on      : http://%s:%d", config.host, config.port)
    logger.info(bar)

    try:
        uvicorn.run(app, host=config.host, port=config.port,
                    log_level="warning" if not config.verbose else "info")
    finally:
        runtime_s = time.monotonic() - _state.started_at
        summary = _shutdown_summary_text(
            counters=_state.counters,
            runtime_s=runtime_s,
            paths=_state.log_paths,
        )
        # Print to stdout so it survives even if logger handlers are torn down.
        print(summary)
        # Mirror into the log file if it's still writable.
        try:
            with open(_state.log_paths.log_file, "a", encoding="utf-8") as f:
                f.write(summary + "\n")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
