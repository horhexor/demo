"""corp_diag_lib — single source of truth for corp diagnostic infrastructure.

Centralizes everything that was previously duplicated across diag_repro.py,
diag_repro_decomposer.py, and corp_mimic_wrapper.py:

  - Config dataclasses + load_config() + print_resolved_config() with source
    tracking (cli|env|yaml|default) so you can always answer "where did this
    value actually come from?"
  - Auth: get_credential() + build_azure_token_provider() +
    build_openai_compat_client() — the canonical pattern:

        credential = DefaultAzureCredential()
        token_provider = get_bearer_token_provider(
            credential, "https://ai.azure.com/.default",
        )
        llm = ChatOpenAI(
            model=<deployment>,
            base_url=<endpoint>,
            api_key=token_provider,
        )

  - Diagnostic data model: CallAttempt, CallMetric, MetricsWriter.
  - APIM correlation: thread-local + httpx hooks that inject
    x-ms-client-request-id outbound and capture apim-request-id,
    x-ratelimit-*, etc. inbound.
  - Error classification + transient detection (single classifier used by
    both retry policy and the histogram).
  - Token-acquisition chaos injection.
  - resilient_invoke + tenacity.
  - Logging setup (single log file per run; raw responses go file-only).

Show resolved config from the CLI:

    python -m corp_diag_lib --show-config
    python -m corp_diag_lib --show-config --profile-name corp-loaded
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import logging
import os
import random
import statistics
import sys
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

import httpx
import yaml
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger("corp_diag")
raw_log = logging.getLogger("corp_diag.raw")
batch_log = logging.getLogger("corp_diag.batching")

DEFAULT_CONFIG_FILENAME = "corp_diag_config.yaml"


# ============================================================================
# Section 1 — Config dataclasses + loader + source-tracked precedence
# ============================================================================


# Source labels for print_resolved_config:
_SRC_CLI = "cli"
_SRC_ENV = "env"
_SRC_YAML = "yaml"
_SRC_DEFAULT = "default"


@dataclasses.dataclass
class AuthConfig:
    endpoint: str = "https://<your-apim>.azure-api.net/openai-compat"
    deployment: str = "gpt-5-4"
    api_version: str = "2024-12-01-preview"
    api_surface: str = "openai-compat"
    credential: str = "DefaultAzureCredential"
    scope: str = "https://ai.azure.com/.default"


@dataclasses.dataclass
class LLMConfig:
    max_completion_tokens: int | None = 1024
    request_timeout_s: int = 300
    max_retries: int = 3
    retry_min_wait_s: int = 1
    retry_max_wait_s: int = 30
    # Stage 6.1 — Layer 2 dynamic token budget escalation
    escalation_factor: float = 2.0
    escalation_max_attempts: int = 4
    per_phase_initial_budget: int = 1024
    bridge_initial_budget: int = 2048
    polish_initial_budget: int = 1024


@dataclasses.dataclass
class ChaosConfig:
    token_chaos_rate: float = 0.0
    token_chaos_error: str = "random"
    token_chaos_seed: int | None = None


@dataclasses.dataclass
class MimicRateLimits:
    requests: int = 50000
    tokens: int = 5000000


@dataclasses.dataclass
class MimicFailureBand:
    min_s: float
    max_s: float


@dataclasses.dataclass
class MimicLoadPreset:
    delay_min_ms: int
    delay_max_ms: int
    failure_rate: float


@dataclasses.dataclass
class MimicConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    foundry_endpoint: str = "https://<your-foundry>.openai.azure.com"
    api_version: str = "2024-12-01-preview"
    load_mode: str | None = None
    delay_min_ms: int = 0
    delay_max_ms: int = 0
    failure_rate: float = 0.0
    failure_mode: str = "random"
    seed: int | None = None
    rate_limit: MimicRateLimits = dataclasses.field(default_factory=MimicRateLimits)
    failure_bands: dict[str, MimicFailureBand] = dataclasses.field(default_factory=dict)
    load_presets: dict[str, MimicLoadPreset] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class DiagConfig:
    verbose: bool = False
    outputs_root: str = "./outputs/diag"
    extract_batch_size: int = 1
    extract_concurrency: int = 8
    decomposer: str = "phase_aware_refined"
    no_portfolio_polish: bool = True
    no_per_trailhead_polish: bool = False
    max_concurrency: int = 12
    # Stage 5g — opt-in cross-run hardening for decomposer:
    decomposer_ledger_path: str | None = None
    decomposer_cache_root: str | None = None
    decomposer_run_id: str | None = None


@dataclasses.dataclass
class ProfileSelector:
    name: str = "corp"
    source: str = "yaml"  # "yaml" | "inline"
    yaml_path: str | None = None


@dataclasses.dataclass
class Config:
    profile: ProfileSelector = dataclasses.field(default_factory=ProfileSelector)
    auth: AuthConfig = dataclasses.field(default_factory=AuthConfig)
    llm: LLMConfig = dataclasses.field(default_factory=LLMConfig)
    chaos: ChaosConfig = dataclasses.field(default_factory=ChaosConfig)
    mimic: MimicConfig = dataclasses.field(default_factory=MimicConfig)
    diag: DiagConfig = dataclasses.field(default_factory=DiagConfig)
    # Per-field source map: dotted path → source label ("cli"|"env"|"yaml"|"default")
    sources: dict[str, str] = dataclasses.field(default_factory=dict)


# ----------------------------------------------------------------------------
# Source-tracking precedence machinery
# ----------------------------------------------------------------------------


def _coerce(value: Any, target_type: type) -> Any:
    """Coerce a raw string (from env) into the dataclass field type."""
    if value is None:
        return None
    if target_type is bool:
        if isinstance(value, bool):
            return value
        s = str(value).strip().lower()
        return s in ("1", "true", "yes", "on")
    if target_type is int:
        return int(value)
    if target_type is float:
        return float(value)
    return value


# Per-field config mapping: dotted_path → (env_var_name, default_value, type)
# This is the only place env var names live. Single map drives both load and
# print_resolved_config so they can't drift.
_CONFIG_SCHEMA: tuple[tuple[str, str | None, Any, type], ...] = (
    # profile
    ("profile.name",                    "PREDATOR_PROFILE",            "corp",        str),
    ("profile.source",                  "CORP_DIAG_PROFILE_SOURCE",    "yaml",        str),
    ("profile.yaml_path",               "LLM_PROFILES_PATH",           None,          str),
    # auth (only used when profile.source == "inline")
    ("auth.endpoint",                   "AZURE_OPENAI_ENDPOINT",       "https://<your-apim>.azure-api.net/openai-compat", str),
    ("auth.deployment",                 "AZURE_OPENAI_DEPLOYMENT",     "gpt-5-4",     str),
    ("auth.api_version",                "AZURE_OPENAI_API_VERSION",    "2024-12-01-preview", str),
    ("auth.api_surface",                "CORP_DIAG_API_SURFACE",       "openai-compat", str),
    ("auth.credential",                 "CORP_DIAG_CREDENTIAL",        "DefaultAzureCredential", str),
    ("auth.scope",                      "CORP_DIAG_SCOPE",             "https://ai.azure.com/.default", str),
    # llm
    ("llm.max_completion_tokens",       "WOLFPACK_MAX_COMPLETION_TOKENS", 1024,       int),
    ("llm.request_timeout_s",           "CORP_DIAG_REQUEST_TIMEOUT_S", 300,           int),
    ("llm.max_retries",                 "CORP_DIAG_MAX_RETRIES",       3,             int),
    ("llm.retry_min_wait_s",            "CORP_DIAG_RETRY_MIN_WAIT_S",  1,             int),
    ("llm.retry_max_wait_s",            "CORP_DIAG_RETRY_MAX_WAIT_S",  30,            int),
    # Stage 6.1 — Layer 2 dynamic token-budget escalation
    ("llm.escalation_factor",           "CORP_DIAG_ESCALATION_FACTOR", 2.0,           float),
    ("llm.escalation_max_attempts",     "CORP_DIAG_ESCALATION_MAX_ATTEMPTS", 4,       int),
    ("llm.per_phase_initial_budget",    "CORP_DIAG_PER_PHASE_INITIAL_BUDGET", 1024,   int),
    ("llm.bridge_initial_budget",       "CORP_DIAG_BRIDGE_INITIAL_BUDGET", 2048,      int),
    ("llm.polish_initial_budget",       "CORP_DIAG_POLISH_INITIAL_BUDGET", 1024,      int),
    # chaos
    ("chaos.token_chaos_rate",          "CORP_DIAG_TOKEN_CHAOS_RATE",  0.0,           float),
    ("chaos.token_chaos_error",         "CORP_DIAG_TOKEN_CHAOS_ERROR", "random",      str),
    ("chaos.token_chaos_seed",          "CORP_DIAG_TOKEN_CHAOS_SEED",  None,          int),
    # mimic
    ("mimic.host",                      "MIMIC_HOST",                  "127.0.0.1",   str),
    ("mimic.port",                      "MIMIC_PORT",                  8080,          int),
    ("mimic.foundry_endpoint",          "MIMIC_FOUNDRY_ENDPOINT",      "https://<your-foundry>.openai.azure.com", str),
    ("mimic.api_version",               "MIMIC_API_VERSION",           "2024-12-01-preview", str),
    ("mimic.load_mode",                 "MIMIC_LOAD_MODE",             None,          str),
    ("mimic.delay_min_ms",              "MIMIC_DELAY_MIN_MS",          0,             int),
    ("mimic.delay_max_ms",              "MIMIC_DELAY_MAX_MS",          0,             int),
    ("mimic.failure_rate",              "MIMIC_FAILURE_RATE",          0.0,           float),
    ("mimic.failure_mode",              "MIMIC_FAILURE_MODE",          "random",      str),
    ("mimic.seed",                      "MIMIC_SEED",                  None,          int),
    ("mimic.rate_limit.requests",       "MIMIC_RATELIMIT_REQUESTS",    50000,         int),
    ("mimic.rate_limit.tokens",         "MIMIC_RATELIMIT_TOKENS",      5000000,       int),
    # diag
    ("diag.verbose",                    "CORP_DIAG_VERBOSE",           False,         bool),
    ("diag.outputs_root",               "CORP_DIAG_OUTPUTS_ROOT",      "./outputs/diag", str),
    ("diag.extract_batch_size",         "CORP_DIAG_EXTRACT_BATCH_SIZE", 1,            int),
    ("diag.extract_concurrency",        "CORP_DIAG_EXTRACT_CONCURRENCY", 8,           int),
    ("diag.decomposer",                 "CORP_DIAG_DECOMPOSER",        "phase_aware_refined", str),
    ("diag.no_portfolio_polish",        "CORP_DIAG_NO_PORTFOLIO_POLISH", True,        bool),
    ("diag.no_per_trailhead_polish",    "CORP_DIAG_NO_PER_TRAILHEAD_POLISH", False,   bool),
    ("diag.max_concurrency",            "CORP_DIAG_MAX_CONCURRENCY",   12,            int),
    # Stage 5g — opt-in cross-run hardening for the decomposer phase
    ("diag.decomposer_ledger_path",     "CORP_DIAG_DECOMPOSER_LEDGER", None,          str),
    ("diag.decomposer_cache_root",      "CORP_DIAG_DECOMPOSER_CACHE",  None,          str),
    ("diag.decomposer_run_id",          "CORP_DIAG_DECOMPOSER_RUN_ID", None,          str),
)


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


def _set_nested(obj: Any, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = obj
    for part in parts[:-1]:
        if dataclasses.is_dataclass(cur):
            cur = getattr(cur, part)
        elif isinstance(cur, dict):
            cur = cur[part]
    last = parts[-1]
    if dataclasses.is_dataclass(cur):
        setattr(cur, last, value)
    elif isinstance(cur, dict):
        cur[last] = value


def _find_default_yaml() -> Path | None:
    """Walk up from this file to find corp_diag_config.yaml."""
    current = Path(__file__).resolve().parent
    for _ in range(10):
        candidate = current / DEFAULT_CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def load_config(
    yaml_path: Path | None = None,
    *,
    cli_overrides: dict[str, Any] | None = None,
) -> Config:
    """Resolve config from CLI > env > yaml > default and return a Config
    with a populated `sources` map for each field.

    Args:
        yaml_path: optional explicit path to corp_diag_config.yaml. If None,
            walks up from this file.
        cli_overrides: dict of dotted-path → value for CLI overrides. Only
            non-None values override yaml/env/default.
    """
    cli_overrides = cli_overrides or {}
    config = Config()

    # 1. Load yaml if present.
    yaml_data: dict[str, Any] = {}
    yaml_path = yaml_path or _find_default_yaml()
    if yaml_path and yaml_path.is_file():
        try:
            with open(yaml_path, encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f) or {}
        except Exception as exc:
            logger.warning("Failed to load %s: %s — using defaults", yaml_path, exc)
            yaml_data = {}

    # 2. For each schema field, resolve in CLI > env > yaml > default order.
    for dotted, env_var, default_val, target_type in _CONFIG_SCHEMA:
        source = _SRC_DEFAULT
        value: Any = default_val

        # yaml lookup
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

        # env lookup
        if env_var and env_var in os.environ:
            env_raw = os.environ[env_var]
            if env_raw != "":
                try:
                    value = _coerce(env_raw, target_type)
                    source = _SRC_ENV
                except (TypeError, ValueError):
                    logger.warning(
                        "env %s=%r could not be coerced to %s; ignoring",
                        env_var, env_raw, target_type.__name__,
                    )

        # cli lookup
        if dotted in cli_overrides and cli_overrides[dotted] is not None:
            value = cli_overrides[dotted]
            source = _SRC_CLI

        _set_nested(config, dotted, value)
        config.sources[dotted] = source

    # 3. Nested mimic structures not in the flat schema (failure_bands, load_presets):
    mimic_yaml = (yaml_data.get("mimic") or {}) if isinstance(yaml_data, dict) else {}
    fb_yaml = mimic_yaml.get("failure_bands") or {}
    if fb_yaml:
        config.mimic.failure_bands = {
            k: MimicFailureBand(min_s=float(v["min_s"]), max_s=float(v["max_s"]))
            for k, v in fb_yaml.items()
        }
        config.sources["mimic.failure_bands"] = _SRC_YAML
    else:
        config.mimic.failure_bands = {
            "504":              MimicFailureBand(28.0, 32.0),
            "html_gateway_504": MimicFailureBand(28.0, 35.0),
            "disconnect":       MimicFailureBand(120.0, 150.0),
            "timeout":          MimicFailureBand(180.0, 210.0),
        }
        config.sources["mimic.failure_bands"] = _SRC_DEFAULT

    lp_yaml = mimic_yaml.get("load_presets") or {}
    if lp_yaml:
        config.mimic.load_presets = {
            k: MimicLoadPreset(
                delay_min_ms=int(v["delay_min_ms"]),
                delay_max_ms=int(v["delay_max_ms"]),
                failure_rate=float(v["failure_rate"]),
            )
            for k, v in lp_yaml.items()
        }
        config.sources["mimic.load_presets"] = _SRC_YAML
    else:
        config.mimic.load_presets = {
            "light":    MimicLoadPreset(0, 0, 0.0),
            "moderate": MimicLoadPreset(20000, 60000, 0.02),
            "heavy":    MimicLoadPreset(50000, 90000, 0.05),
            "severe":   MimicLoadPreset(60000, 120000, 0.15),
        }
        config.sources["mimic.load_presets"] = _SRC_DEFAULT

    # 4. If profile.source == "yaml", overlay endpoint/deployment/etc. from
    # llm-profiles[.local].yaml so diag and wolfpack share the profile.
    if config.profile.source == "yaml":
        _apply_llm_profiles_yaml(config)

    return config


_SENTINEL_MISSING = object()


def _apply_llm_profiles_yaml(config: Config) -> None:
    """If profile.source == yaml, read the wolfpack llm-profiles.yaml and
    overlay its values into config.auth (with source = "yaml").

    Search order for the llm-profiles.yaml file:
      1. `config.profile.yaml_path` if set (from corp_diag_config.yaml or
         LLM_PROFILES_PATH env)
      2. Walk up from this file looking for `llm-profiles.yaml`
    """
    base: Path | None = None
    local: Path | None = None
    if config.profile.yaml_path:
        explicit = Path(config.profile.yaml_path)
        if explicit.is_file():
            base = explicit
            local_candidate = explicit.with_name("llm-profiles.local.yaml")
            if local_candidate.is_file():
                local = local_candidate
        else:
            logger.warning(
                "profile.yaml_path=%r is not a file; trying auto-discover.",
                config.profile.yaml_path,
            )
    if base is None:
        base, local = _find_llm_profiles()
    if not base:
        logger.warning(
            "profile.source=yaml but no llm-profiles.yaml found near %s; "
            "falling back to inline auth values from corp_diag_config.yaml. "
            "Set profile.yaml_path or LLM_PROFILES_PATH to point at the "
            "wolfpack llm-profiles.yaml if you want to share auth config.",
            Path(__file__).resolve().parent,
        )
        return
    with open(base, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if local is not None:
        with open(local, encoding="utf-8") as f:
            local_data = yaml.safe_load(f) or {}
        data = _deep_merge(data, local_data)
    profiles = data.get("profiles", {})
    profile_data = profiles.get(config.profile.name)
    if not profile_data:
        logger.warning(
            "profile.name=%r not in %s; known: %s. Falling back to inline auth.",
            config.profile.name, base, sorted(profiles),
        )
        return
    default_provider = profile_data.get("default_provider", "azure")
    cfg = (profile_data.get("providers", {}) or {}).get(default_provider, {})
    cred_args = dict(cfg.get("credential_args", {}) or {})
    # Apply overlay (env/cli still win because we only update where current is default).
    overlay_pairs: list[tuple[str, Any]] = [
        ("auth.endpoint",     cfg.get("default_endpoint")),
        ("auth.deployment",   cfg.get("default_deployment")),
        ("auth.api_version",  cfg.get("api_version")),
        ("auth.api_surface",  cfg.get("api_surface")),
        ("auth.credential",   cfg.get("credential")),
        ("auth.scope",        cred_args.get("scope")),
    ]
    for dotted, val in overlay_pairs:
        if val is None:
            continue
        current_source = config.sources.get(dotted, _SRC_DEFAULT)
        # Don't overwrite cli or env. Yaml-from-corp_diag_config and
        # yaml-from-llm-profiles are both "yaml" — llm-profiles wins.
        if current_source in (_SRC_CLI, _SRC_ENV):
            continue
        _set_nested(config, dotted, val)
        config.sources[dotted] = "yaml(llm-profiles)"


def _find_llm_profiles() -> tuple[Path | None, Path | None]:
    """Locate llm-profiles.yaml + optional .local sibling near this file."""
    env_path = os.environ.get("LLM_PROFILES_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            local = p.with_name("llm-profiles.local.yaml")
            return p, (local if local.is_file() else None)
        return None, None
    current = Path(__file__).resolve().parent
    for _ in range(10):
        candidate = current / "llm-profiles.yaml"
        if candidate.is_file():
            local = current / "llm-profiles.local.yaml"
            return candidate, (local if local.is_file() else None)
        if current.parent == current:
            break
        current = current.parent
    return None, None


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for k, v in override.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


def print_resolved_config(config: Config) -> None:
    """Print every config value with its source. The whole point of this lib."""
    bar = "=" * 78
    print(bar)
    print("CORP DIAG — RESOLVED CONFIG")
    print(bar)
    sections: dict[str, list[tuple[str, Any, str]]] = {}
    for dotted, _env, _default, _type in _CONFIG_SCHEMA:
        section = dotted.split(".")[0]
        value = _get_nested(config, dotted)
        src = config.sources.get(dotted, _SRC_DEFAULT)
        sections.setdefault(section, []).append((dotted, value, src))
    # Extra structures (failure_bands, load_presets):
    sections.setdefault("mimic", []).append(
        ("mimic.failure_bands", config.mimic.failure_bands,
         config.sources.get("mimic.failure_bands", _SRC_DEFAULT))
    )
    sections.setdefault("mimic", []).append(
        ("mimic.load_presets", config.mimic.load_presets,
         config.sources.get("mimic.load_presets", _SRC_DEFAULT))
    )
    for section in ("profile", "auth", "llm", "chaos", "mimic", "diag"):
        if section not in sections:
            continue
        print(f"\n[{section}]")
        for dotted, value, src in sections[section]:
            label = dotted[len(section) + 1:]
            print(f"  {label:36s} = {value!r:50s} [{src}]")
    print(bar)


# ============================================================================
# Section 2 — Auth: credential + token provider + ChatOpenAI client
# ============================================================================


def get_credential() -> DefaultAzureCredential:
    """The canonical corp credential. Assumes `az login` is active locally;
    in Azure-hosted deployments returns a different credential — out of scope
    for this lib."""
    return DefaultAzureCredential()


def build_azure_token_provider(scope: str) -> Callable[[], str]:
    """Wraps the credential as a bearer-token provider for the configured scope."""
    logger.info("Building DefaultAzureCredential (assumes `az login` is active)")
    credential = get_credential()
    logger.info("Token provider configured for scope=%s", scope)
    return get_bearer_token_provider(credential, scope)


# ----------------------------------------------------------------------------
# Token chaos injection — wraps the real token provider so a configurable
# fraction of token calls raise simulated auth failures.
# ----------------------------------------------------------------------------


_CHAOS_ERROR_TYPES = ("timeout", "auth_error", "connection", "random")


def make_chaotic_token_provider(
    real_provider: Callable[[], str],
    *,
    failure_rate: float,
    error_type: str,
    seed: int | None = None,
) -> Callable[[], str]:
    if error_type not in _CHAOS_ERROR_TYPES:
        raise ValueError(
            f"unknown token chaos error_type={error_type!r}; "
            f"expected one of {_CHAOS_ERROR_TYPES}"
        )
    rng = random.Random(seed) if seed is not None else random.Random()
    state = {"calls": 0, "fires": 0}
    lock = threading.Lock()

    def chaotic() -> str:
        with lock:
            state["calls"] += 1
            roll = rng.random()
            call_n = state["calls"]
            if roll < failure_rate:
                state["fires"] += 1
                fire_n = state["fires"]
                pick = error_type
                if pick == "random":
                    pick = rng.choice(("timeout", "auth_error", "connection"))
                if pick == "timeout":
                    raise TimeoutError(
                        f"CHAOS: simulated token retrieval timeout "
                        f"(call #{call_n}, fire #{fire_n}). "
                        "Operation timed out fetching token from "
                        "https://login.microsoftonline.com."
                    )
                if pick == "connection":
                    raise ConnectionError(
                        f"CHAOS: connection error to login.microsoftonline.com "
                        f"(call #{call_n}, fire #{fire_n}). "
                        "Server disconnected without sending a response."
                    )
                if pick == "auth_error":
                    from azure.core.exceptions import ClientAuthenticationError
                    raise ClientAuthenticationError(
                        f"CHAOS: AADSTS50105 simulated auth failure "
                        f"(call #{call_n}, fire #{fire_n}). The signed-in user "
                        "is not assigned to a role for the application."
                    )
        return real_provider()

    chaotic.__chaos_state__ = state  # type: ignore[attr-defined]
    return chaotic


# ----------------------------------------------------------------------------
# APIM header capture + outbound x-ms-client-request-id injection
# ----------------------------------------------------------------------------


# Stage 7.1 — APIM-header capture across threadpool boundaries.
#
# Earlier this was a threading.local. That broke for the decomposer's
# structured-output path: `with_structured_output(include_raw=True)` uses
# RunnableParallel, which dispatches the actual LLM call onto a
# ThreadPoolExecutor worker. The httpx hooks fire on the WORKER thread,
# populating that thread's local. The caller (reading on the main thread)
# saw NULL — so all decomposer CallMetrics had `apim_request_id`,
# `client_request_id`, ratelimit fields, etc., all NULL even though the
# headers were present in the HTTP response.
#
# Fix: contextvar holding a MUTABLE dict. langchain's executor uses
# `contextvars.copy_context().run()`, which snapshots the parent's
# contextvar values into the worker — so the worker sees the SAME dict
# reference. Mutations made by the worker hooks are visible to the parent
# through that shared dict. Concurrent parents have separate contextvars
# (since contextvars are context-scoped), so parallel per_phase calls
# don't contaminate each other.
import contextvars

_APIM_HEADERS_OF_INTEREST = (
    "apim-request-id",
    "x-request-id",
    "x-ms-client-request-id",
    "x-ratelimit-limit-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-remaining-tokens",
    "request-context",
    "date",
)


def _fresh_capture_box() -> dict[str, Any]:
    return {"client_request_id": None, "last_headers": None, "last_status": None}


# Default to a fresh box so callers can use the lib without explicitly
# resetting first. Each `reset_thread_apim_state()` swaps in a NEW box
# so any worker threads from prior calls (with stale refs) can't pollute
# the new box.
_apim_capture_var: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "apim_capture_box", default=_fresh_capture_box(),
)


def _diag_request_hook(request: httpx.Request) -> None:
    box = _apim_capture_var.get()
    cid = uuid.uuid4().hex
    request.headers["x-ms-client-request-id"] = cid
    box["client_request_id"] = cid
    box["last_headers"] = None
    box["last_status"] = None


def _diag_response_hook(response: httpx.Response) -> None:
    try:
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        captured = {h: headers_lower.get(h) for h in _APIM_HEADERS_OF_INTEREST}
    except Exception:
        captured = {}
    box = _apim_capture_var.get()
    box["last_headers"] = captured
    box["last_status"] = response.status_code


def take_last_apim_capture() -> dict[str, Any]:
    """Pop the latest contextvar-bound APIM capture into a flat dict suitable
    for the **apim splat in CallAttempt(...)."""
    box = _apim_capture_var.get()
    headers = box.get("last_headers") or {}
    cid = box.get("client_request_id")
    status = box.get("last_status")

    def _as_int(v: Any) -> int | None:
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    return {
        "client_request_id": cid,
        "http_status": status,
        "apim_request_id": headers.get("apim-request-id"),
        "x_request_id": headers.get("x-request-id"),
        "ratelimit_remaining_requests": _as_int(headers.get("x-ratelimit-remaining-requests")),
        "ratelimit_remaining_tokens": _as_int(headers.get("x-ratelimit-remaining-tokens")),
        "ratelimit_limit_requests": _as_int(headers.get("x-ratelimit-limit-requests")),
        "ratelimit_limit_tokens": _as_int(headers.get("x-ratelimit-limit-tokens")),
        "request_context": headers.get("request-context"),
        "apim_date": headers.get("date"),
    }


def reset_thread_apim_state() -> None:
    """Swap in a fresh capture box. Stale worker-thread references to the
    old box become harmless (they mutate the discarded box)."""
    _apim_capture_var.set(_fresh_capture_box())


def build_diag_http_client(timeout: int) -> httpx.Client:
    return httpx.Client(
        event_hooks={"request": [_diag_request_hook], "response": [_diag_response_hook]},
        timeout=httpx.Timeout(timeout, connect=15.0),
    )


# ----------------------------------------------------------------------------
# ChatOpenAI builder — the canonical corp pattern
# ----------------------------------------------------------------------------


def build_openai_compat_client(config: Config) -> ChatOpenAI:
    """Build the ChatOpenAI client using the canonical corp pattern, with
    the diagnostic HTTP client and optional token chaos wired in:

        credential = get_credential()
        token_provider = get_bearer_token_provider(credential, scope)
        llm = ChatOpenAI(model=<deployment>, base_url=<endpoint>, api_key=token_provider)
    """
    auth = config.auth
    llm_cfg = config.llm
    chaos = config.chaos

    if not auth.endpoint:
        raise ValueError("auth.endpoint is required")
    if not auth.deployment:
        raise ValueError("auth.deployment is required")

    token_provider = build_azure_token_provider(auth.scope)
    auth_label = "token_provider(DefaultAzureCredential)"
    if chaos.token_chaos_rate > 0:
        token_provider = make_chaotic_token_provider(
            token_provider,
            failure_rate=chaos.token_chaos_rate,
            error_type=chaos.token_chaos_error,
            seed=chaos.token_chaos_seed,
        )
        auth_label = (
            f"CHAOS-WRAPPED token_provider "
            f"(rate={chaos.token_chaos_rate}, error_type={chaos.token_chaos_error}, "
            f"seed={chaos.token_chaos_seed})"
        )
        logger.warning(
            "TOKEN CHAOS ENABLED: rate=%.3f error_type=%s seed=%s",
            chaos.token_chaos_rate, chaos.token_chaos_error, chaos.token_chaos_seed,
        )

    diag_http_client = build_diag_http_client(llm_cfg.request_timeout_s)

    kwargs: dict[str, Any] = {
        "model": auth.deployment,
        "base_url": auth.endpoint.rstrip("/"),
        "api_key": token_provider,
        "request_timeout": llm_cfg.request_timeout_s,
        "http_client": diag_http_client,
        # Force openai SDK's internal max_retries to 0 so tenacity is the sole
        # retry layer. Otherwise the SDK silently retries 504/disconnect/timeout
        # (default max_retries=2) below tenacity, swallowing chaos events before
        # they can be classified + recorded in CallMetric.attempts[].
        "max_retries": 0,
    }
    if llm_cfg.max_completion_tokens is not None:
        kwargs["max_completion_tokens"] = llm_cfg.max_completion_tokens
    if not auth.deployment.startswith(("o1", "o3", "gpt-5")):
        kwargs["temperature"] = 0

    logger.info(
        "ChatOpenAI init (corp openai-compat): base_url=%s | deployment=%s | "
        "auth=%s | timeout=%ds | max_completion_tokens=%s | "
        "diag http_client=ON (header capture + client_request_id injection)",
        auth.endpoint, auth.deployment, auth_label,
        llm_cfg.request_timeout_s, llm_cfg.max_completion_tokens,
    )
    return ChatOpenAI(**kwargs)


# ============================================================================
# Section 3 — Diagnostic data model
# ============================================================================


@dataclasses.dataclass
class CallAttempt:
    attempt_number: int
    started_at: str
    elapsed_s: float
    status: str  # "ok" | "transient_error" | "non_transient_error"
    error_class: str | None
    error_message: str | None
    client_request_id: str | None = None
    http_status: int | None = None
    apim_request_id: str | None = None
    x_request_id: str | None = None
    ratelimit_remaining_requests: int | None = None
    ratelimit_remaining_tokens: int | None = None
    ratelimit_limit_requests: int | None = None
    ratelimit_limit_tokens: int | None = None
    request_context: str | None = None
    apim_date: str | None = None


@dataclasses.dataclass
class CallMetric:
    """Per-call diagnostic record.

    Used by both the extraction diag (call_type = "extract_batch") and the
    decomposer diag (call_type = "per_phase" | "bridge" | "per_trailhead_polish").
    """
    call_type: str
    call_label: str
    started_at: str
    finished_at: str | None = None
    total_elapsed_s: float | None = None
    prompt_chars: int = 0
    response_chars: int | None = None
    n_attempts: int = 0
    attempts: list[CallAttempt] = dataclasses.field(default_factory=list)
    final_status: str = "pending"
    final_error: str | None = None
    finish_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    # Free-form per-call payload (e.g. n_windows, anchors for extraction;
    # phase, trailheads_produced for decomposer):
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class MetricsWriter:
    """Thread-safe in-memory aggregator + log-line emitter.

    write(metric) logs a single-line `CALL_METRIC {...}` JSON entry (which
    lands in both the console and the run logfile) and appends to an
    in-memory list used at end-of-run to build the summary. No separate
    output file is produced — everything is in the one log.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []

    def write(self, metric: CallMetric) -> None:
        row = metric.to_dict()
        with self._lock:
            self._records.append(row)
        logger.info("CALL_METRIC %s", json.dumps(row, separators=(",", ":")))

    def close(self) -> None:  # parity with prior API
        return

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)


def emit_call_metric(metric: CallMetric) -> None:
    """Emit one CALL_METRIC JSON line directly to the logger.

    Standalone helper so post-LLM-call code paths (extraction parse,
    continuation recovery) can attach late fields (finish_reason,
    payload.warnings, behaviors_produced) and then emit themselves rather
    than letting resilient_invoke emit a partial record. Mirrors
    ``wolfpack.llm_resilience.emit_call_metric``.
    """
    metric.n_attempts = len(metric.attempts)
    if metric.final_status == "pending":
        metric.final_status = "unknown"
    logger.info("CALL_METRIC %s", json.dumps(metric.to_dict(), separators=(",", ":")))


# Stage 5g.1 — content-derived keys (mirrors wolfpack/extraction_cache.py)


def compute_call_batch_key(
    input_data: Any,
    *,
    call_type: str,
    prompt_version: str,
    deployment: str,
    max_completion_tokens: int | None,
) -> str:
    fingerprint = {
        "input_data": input_data,
        "call_type": call_type,
        "prompt_version": prompt_version,
        "deployment": deployment,
        "max_completion_tokens": max_completion_tokens,
    }
    blob = json.dumps(fingerprint, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def compute_report_id(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


# Stage 5g.2 — StatusLedger (mirrors wolfpack/extraction_cache.py)

_OK_STATUSES = frozenset({"ok"})


class StatusLedger:
    """Append-only JSONL recording every batch attempt's outcome."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._ledger_lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> None:
        row = dict(record)
        row.setdefault(
            "ts",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )
        line = json.dumps(row, separators=(",", ":"), ensure_ascii=False)
        with self._ledger_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _iter_rows(self):
        if not self.path.is_file():
            return
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def latest_per_batch(self, report_id: str) -> dict[str, dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for row in self._iter_rows():
            if row.get("report_id") != report_id:
                continue
            bk = row.get("batch_key")
            if bk is None:
                continue
            latest[bk] = row
        return latest

    def pending_batches(self, report_id: str) -> set[str]:
        return {
            bk
            for bk, row in self.latest_per_batch(report_id).items()
            if row.get("status") not in _OK_STATUSES
        }


# Stage 5g.4 — per_phase cache (parsed-output flavor).
# Scope: per_phase outputs only. Bridge + polish stay always-fresh (mirrors
# wolfpack/trailheads/decomposer_cache.py rationale).


def read_cached_per_phase_parsed(
    *,
    cache_root: Path | str,
    report_id: str,
    batch_key: str,
    output_model: type,
) -> Any | None:
    cache_root = Path(cache_root)
    path = cache_root / report_id / f"{batch_key}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return output_model.model_validate(data)
    except Exception as exc:
        logger.warning("per_phase cache read failed for %s: %s", path, exc)
        return None


def write_cached_per_phase_parsed(
    *,
    cache_root: Path | str,
    report_id: str,
    batch_key: str,
    parsed: Any,
) -> None:
    cache_root = Path(cache_root)
    path = cache_root / report_id / f"{batch_key}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = parsed.model_dump(mode="json")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
        encoding="utf-8",
    )
    os.replace(tmp, path)


def cached_per_phase_dispatch(
    *,
    batch_key: str,
    report_id: str | None,
    cache_root: Path | str | None,
    output_model: type,
    invoke_fn,
) -> tuple[Any | None, str]:
    """Cache-aware wrapper around a per_phase invoke.

    Returns ``(result, source)`` where source is one of:
      - ``"cache"`` — cache hit; invoke_fn was NOT called
      - ``"fresh"`` — cache miss + invoke returned a non-None parsed output
        (cache was also written)
      - ``"failed"`` — invoke returned None (no cache write)

    When cache is disabled (``cache_root is None`` or ``report_id is None``),
    invoke_fn is always called and cache is never read/written.
    """
    cache_enabled = cache_root is not None and report_id is not None
    if cache_enabled:
        cached = read_cached_per_phase_parsed(
            cache_root=cache_root, report_id=report_id,
            batch_key=batch_key, output_model=output_model,
        )
        if cached is not None:
            return cached, "cache"

    result = invoke_fn()

    if cache_enabled and result is not None:
        write_cached_per_phase_parsed(
            cache_root=cache_root, report_id=report_id,
            batch_key=batch_key, parsed=result,
        )
    return result, ("fresh" if result is not None else "failed")


def write_decomposer_ledger_entry(
    *,
    ledger: "StatusLedger | None",
    report_id: str | None,
    run_id: str | None,
    call_type: str,
    batch_key: str,
    context_label: str,
    metric: "CallMetric",
) -> None:
    """Append a status-ledger row for one decomposer LLM call.

    No-op when ``ledger is None`` or ``report_id is None``. Mirrors
    wolfpack/extraction_cache.py:write_decomposer_ledger_entry.
    """
    if ledger is None or report_id is None:
        return
    status = metric.final_status or "unknown"
    error_class: str | None = None
    if metric.attempts:
        error_class = metric.attempts[-1].error_class
    behaviors_count = int(metric.payload.get("trailheads_produced", 0) or 0)
    ledger.append({
        "report_id": report_id,
        "batch_key": batch_key,
        "status": status,
        "error_class": error_class,
        "anchors": [context_label],
        "behaviors_count": behaviors_count,
        "run_id": run_id or "unknown",
        "call_type": call_type,
    })


# ============================================================================
# Stage 6.1 — Layer 2 resilience: dynamic token-budget escalation
# ============================================================================
#
# When gpt-5.x structured-output calls return finish_reason=length, the call
# is HTTP-clean but the parsed output is incomplete. Tenacity doesn't see this
# (it's a successful HTTP). The wrapper below detects truncation, doubles the
# budget, and retries the same prompt until success or max_attempts exhausted.
#
# Sits ABOVE resilient_invoke: each escalation level may itself trigger
# tenacity retries on transient HTTP errors. Two independent layers.


def invoke_with_token_escalation(
    *,
    invokable_factory,
    payload,
    is_truncated,
    initial_max_tokens: int,
    escalation_factor: float = 2.0,
    max_attempts: int = 4,
    config: Config,
    context: str,
    attempts: list[CallAttempt] | None = None,
    budget_journey_out: list[int] | None = None,
) -> tuple[Any, str]:
    """Escalate max_completion_tokens on truncation; retry until success or exhausted.

    Args:
      invokable_factory: callable(budget:int) -> invokable with .invoke(payload).
        Each escalation level builds a fresh invokable bound to the new budget.
      payload: same payload passed to resilient_invoke (typically messages list).
      is_truncated: callable(result) -> bool. Returns True if the result should
        trigger escalation. Standard implementation checks
        result.response_metadata.get("finish_reason") == "length".
      initial_max_tokens: starting budget for the first attempt.
      escalation_factor: budget multiplier per attempt (default 2.0 = doubling).
      max_attempts: cap on escalation levels (default 4 → 1024→2048→4096→8192).
      config: standard Config object (passes through to resilient_invoke).
      context: log label.
      attempts: optional list to append per-HTTP-call CallAttempt to.
      budget_journey_out: optional list to append [budget1, budget2, ...] to.
        Useful for CallMetric.payload.budget_attempts diagnostics.

    Returns:
      (result, status) where status is one of:
        "ok"                   — call succeeded, no truncation
        "truncation_exhausted" — all max_attempts truncated; returning last result

    Propagates exceptions from resilient_invoke (e.g., transient_exhausted).
    """
    budget = initial_max_tokens
    last_result: Any = None
    for attempt_n in range(max_attempts):
        if budget_journey_out is not None:
            budget_journey_out.append(budget)
        invokable = invokable_factory(budget)
        sub_context = f"{context}@budget={budget}"
        result = resilient_invoke(
            invokable, payload,
            context=sub_context,
            config=config,
            attempts=attempts,
        )
        last_result = result
        if not is_truncated(result):
            logger.info(
                "Layer 2 [%s] succeeded at budget=%d (escalation_step=%d/%d)",
                context, budget, attempt_n + 1, max_attempts,
            )
            return result, "ok"
        logger.warning(
            "Layer 2 [%s] truncated at budget=%d (step %d/%d); escalating",
            context, budget, attempt_n + 1, max_attempts,
        )
        budget = int(budget * escalation_factor)
    logger.warning(
        "Layer 2 [%s] exhausted %d escalation attempts; returning last truncated result",
        context, max_attempts,
    )
    return last_result, "truncation_exhausted"


def _salvage_truncated_json_array(text: str) -> tuple[list[dict], str]:
    """Try to extract the longest valid prefix from a truncated JSON array.

    Walks the string tracking brace/bracket depth and string state, finds
    the last position where we closed an object at depth=1 (one level
    inside the outer array), and tries ``json.loads(text[:pos] + "]")``.

    Returns ``(prefix_items, remaining_truncated_text)``. On any failure
    (no array found, unparseable salvage), returns ``([], text)``.

    Mirrors ``wolfpack/pipeline/deepagent_runtime.py:_salvage_truncated_json_array``.
    """
    array_start = text.find("[")
    if array_start < 0:
        return [], text

    depth = 0
    in_string = False
    escape = False
    last_safe_end = -1

    for i in range(array_start, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if in_string:
            if c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
            # depth == 1 means we just closed something one level inside the
            # outer `[`. That's a complete top-level item boundary.
            if depth == 1:
                last_safe_end = i + 1
            elif depth == 0:
                # We closed the outer array — the JSON was actually complete.
                try:
                    parsed = json.loads(text[array_start:i + 1])
                    if isinstance(parsed, list):
                        return parsed, ""
                except json.JSONDecodeError:
                    pass
                break

    if last_safe_end < 0:
        return [], text

    salvageable = text[array_start:last_safe_end] + "]"
    try:
        items = json.loads(salvageable)
    except json.JSONDecodeError:
        return [], text
    if not isinstance(items, list):
        return [], text

    remaining = text[last_safe_end:]
    return items, remaining


# ============================================================================
# Section 4 — Error classification + resilient_invoke
# ============================================================================


_ERROR_CLASS_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Order matters — most-specific first.
    ("local_winerror", ("winerror 10013", "winerror 10054", "winerror 10060", "winerror 10061")),
    ("transport_disconnect", (
        "server disconnected without sending",
        "remote disconnected",
        "remoteprotocolerror",
        "connection reset",
        "connection broken",
    )),
    ("gateway_504_html", ("application gateway", "<html")),
    ("http_504", ("504",)),
    ("http_503", ("503",)),
    ("http_502", ("502",)),
    ("http_500", ("500",)),
    ("rate_limit", ("rate limit", "429")),
    ("timeout", ("timeout", "timed out")),
    ("overloaded", ("overloaded", "capacity")),
    ("connection", ("connection error",)),
)


# Exception-class-name → classification. Takes precedence over substring patterns
# because openai SDK + azure-identity exceptions carry structured info that
# substring matching on str(exc) misses (e.g. InternalServerError has no "500"
# digit in its message). Synced from wolfpack/llm_resilience.py.
_EXCEPTION_TYPE_CLASSES: dict[str, str] = {
    # openai SDK 1.x / 2.x
    "InternalServerError":     "http_500",
    "BadGatewayError":         "http_502",
    "ServiceUnavailableError": "http_503",
    "GatewayTimeoutError":     "http_504",
    "RateLimitError":          "rate_limit",
    "APITimeoutError":         "timeout",
    "APIConnectionError":      "connection",
    # azure-identity / azure-core (token-acquisition chain)
    "CredentialUnavailableError": "token_acquisition_failed",
    "ClientAuthenticationError":  "token_acquisition_failed",
}


_TRANSIENT_CLASSES = {
    "transport_disconnect", "gateway_504_html",
    "http_500", "http_502", "http_503", "http_504",
    "rate_limit", "timeout", "overloaded", "connection",
    # Intermittent token-chain hiccups (DefaultAzureCredential flap, KV blip,
    # az-cli token cache refresh race) typically resolve on retry. Tenacity's
    # bounded budget gives up cleanly if persistent.
    "token_acquisition_failed",
}


def classify_error(exc: BaseException) -> str:
    """Bucket an exception into one of the 12 classes.

    Order:
      1. Exception class name (most specific, structured info from SDKs).
      2. Substring match against str(exc) (catches stringly-typed errors and
         exceptions whose message embeds the relevant token).
    """
    type_class = _EXCEPTION_TYPE_CLASSES.get(type(exc).__name__)
    if type_class:
        return type_class
    err = str(exc).lower()
    for cls, patterns in _ERROR_CLASS_PATTERNS:
        if any(p in err for p in patterns):
            return cls
    return "non_transient"


def is_transient_error(exc: BaseException) -> bool:
    """Same classifier as the histogram so retry policy and diagnostic
    taxonomy can never drift. local_winerror is explicitly NOT retried."""
    return classify_error(exc) in _TRANSIENT_CLASSES


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def resilient_invoke(
    invokable: Any,
    payload: Any,
    *,
    context: str,
    config: Config,
    attempts: list[CallAttempt] | None = None,
) -> Any:
    """tenacity-driven retry on transient errors.

    `invokable` is anything with .invoke(payload) — works for ChatOpenAI
    directly and for structured-output wrappers.
    Per-attempt APIM-header capture flows through the thread-local set by
    the build_diag_http_client hooks; reset before each attempt so chaos
    paths that never reached the network don't inherit prior captures.
    """
    llm_cfg = config.llm

    @retry(
        stop=stop_after_attempt(llm_cfg.max_retries),
        wait=wait_exponential(multiplier=1, min=llm_cfg.retry_min_wait_s, max=llm_cfg.retry_max_wait_s),
        retry=retry_if_exception(is_transient_error),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    def _invoke() -> Any:
        attempt_n = (len(attempts) + 1) if attempts is not None else 0
        started_at = iso_utc_now()
        reset_thread_apim_state()
        t_start = time.monotonic()
        logger.info("LLM invoke [%s] attempt=%d starting", context, attempt_n)
        try:
            result = invokable.invoke(payload)
            elapsed = time.monotonic() - t_start
            apim = take_last_apim_capture()
            logger.info(
                "LLM invoke [%s] attempt=%d OK in %.2fs (apim_request_id=%s "
                "client_request_id=%s remaining_tokens=%s)",
                context, attempt_n, elapsed,
                apim["apim_request_id"], apim["client_request_id"],
                apim["ratelimit_remaining_tokens"],
            )
            if attempts is not None:
                attempts.append(CallAttempt(
                    attempt_number=attempt_n,
                    started_at=started_at,
                    elapsed_s=round(elapsed, 3),
                    status="ok",
                    error_class=None,
                    error_message=None,
                    **apim,
                ))
            return result
        except Exception as e:
            elapsed = time.monotonic() - t_start
            transient = is_transient_error(e)
            err_class = classify_error(e)
            apim = take_last_apim_capture()
            logger.warning(
                "LLM invoke [%s] attempt=%d FAILED in %.2fs: %s [%s] "
                "(apim_request_id=%s client_request_id=%s http_status=%s): %s",
                context, attempt_n, elapsed, type(e).__name__, err_class,
                apim["apim_request_id"], apim["client_request_id"],
                apim["http_status"], str(e)[:300],
            )
            if attempts is not None:
                attempts.append(CallAttempt(
                    attempt_number=attempt_n,
                    started_at=started_at,
                    elapsed_s=round(elapsed, 3),
                    status="transient_error" if transient else "non_transient_error",
                    error_class=err_class,
                    error_message=str(e)[:500],
                    **apim,
                ))
            raise

    logger.info("resilient_invoke [%s] starting (max_retries=%d)", context, llm_cfg.max_retries)
    return _invoke()


# Response-metadata extraction — reused by both diags.

def extract_response_metadata(response: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "finish_reason": None, "prompt_tokens": None,
        "completion_tokens": None, "total_tokens": None,
    }
    meta = getattr(response, "response_metadata", None) or {}
    out["finish_reason"] = meta.get("finish_reason")
    token_usage = meta.get("token_usage") or {}
    out["prompt_tokens"] = token_usage.get("prompt_tokens")
    out["completion_tokens"] = token_usage.get("completion_tokens")
    out["total_tokens"] = token_usage.get("total_tokens")
    usage_md = getattr(response, "usage_metadata", None) or {}
    out["prompt_tokens"] = usage_md.get("input_tokens", out["prompt_tokens"])
    out["completion_tokens"] = usage_md.get("output_tokens", out["completion_tokens"])
    out["total_tokens"] = usage_md.get("total_tokens", out["total_tokens"])
    return out


# Wolfpack-named alias so ported continuation code drops in cleanly:
_extract_aimessage_metadata = extract_response_metadata


# ============================================================================
# Section 5 — Logging
# ============================================================================


def setup_logging(verbose: bool, log_file: Path) -> None:
    """Wire all logging into a single log file (plus a console mirror).

    The `corp_diag.raw` sub-logger writes ONLY to the file — used for bulky
    per-batch raw LLM responses so they're preserved without flooding the
    terminal during the run.
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter(fmt))
    root.addHandler(stdout_handler)
    file_handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(fmt))
    root.addHandler(file_handler)
    raw_log.handlers = [file_handler]
    raw_log.setLevel(logging.INFO)
    raw_log.propagate = False
    if not verbose:
        for noisy in ("httpx", "azure", "openai", "urllib3"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
    logger.info("Logging to %s (level=%s)", log_file, logging.getLevelName(level))


def make_log_file(outputs_root: Path, prefix: str = "corp_diag") -> Path:
    outputs_root.mkdir(parents=True, exist_ok=True)
    run_id = f"{iso_utc_now()}-{uuid.uuid4().hex[:8]}"
    return outputs_root / f"{prefix}_{run_id}.log"


# ============================================================================
# Section 6 — Summary helpers
# ============================================================================


def _percentiles(values: list[float], pcts: tuple[int, ...] = (50, 90, 95, 99)) -> dict[str, float]:
    if not values:
        return {f"p{p}": None for p in pcts}
    if len(values) == 1:
        return {f"p{p}": float(values[0]) for p in pcts}
    sorted_vs = sorted(values)
    out: dict[str, float] = {}
    n = len(sorted_vs)
    for p in pcts:
        rank = (p / 100.0) * (n - 1)
        lo = int(rank)
        hi = min(lo + 1, n - 1)
        frac = rank - lo
        out[f"p{p}"] = round(sorted_vs[lo] * (1 - frac) + sorted_vs[hi] * frac, 3)
    return out


def summarize_subset(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        return {"n_calls": 0}
    statuses = [r.get("final_status") for r in records]
    finish_reasons = [r.get("finish_reason") for r in records]
    latencies = [r.get("total_elapsed_s") for r in records if r.get("total_elapsed_s") is not None]
    completion_tokens = [r.get("completion_tokens") for r in records if r.get("completion_tokens") is not None]
    prompt_tokens = [r.get("prompt_tokens") for r in records if r.get("prompt_tokens") is not None]
    n_attempts_each = [r.get("n_attempts", 0) for r in records]
    error_class_hist: Counter[str] = Counter()
    transient_attempts = 0
    non_transient_attempts = 0
    ok_attempts = 0
    for r in records:
        for a in r.get("attempts") or []:
            ec = a.get("error_class")
            if ec:
                error_class_hist[ec] += 1
            if a.get("status") == "transient_error":
                transient_attempts += 1
            elif a.get("status") == "non_transient_error":
                non_transient_attempts += 1
            elif a.get("status") == "ok":
                ok_attempts += 1
    n_ok = sum(1 for s in statuses if s == "ok")
    return {
        "n_calls": len(records),
        "n_ok": n_ok,
        "n_failed": len(records) - n_ok,
        "success_rate": round(n_ok / len(records), 3),
        "final_status_breakdown": dict(Counter(statuses)),
        "finish_reason_breakdown": dict(Counter(finish_reasons)),
        "n_hit_token_cap": sum(1 for fr in finish_reasons if fr == "length"),
        "n_retried": sum(1 for n in n_attempts_each if n > 1),
        "attempt_counts_breakdown": dict(Counter(n_attempts_each)),
        "attempt_outcomes": {
            "ok": ok_attempts,
            "transient_error": transient_attempts,
            "non_transient_error": non_transient_attempts,
        },
        "error_class_histogram_across_attempts": dict(error_class_hist),
        "latency_s": {
            "min": round(min(latencies), 3) if latencies else None,
            "max": round(max(latencies), 3) if latencies else None,
            "mean": round(statistics.fmean(latencies), 3) if latencies else None,
            **_percentiles(latencies),
        },
        "completion_tokens": {
            "min": min(completion_tokens) if completion_tokens else None,
            "max": max(completion_tokens) if completion_tokens else None,
            "mean": round(statistics.fmean(completion_tokens), 1) if completion_tokens else None,
            **_percentiles(completion_tokens),
        },
        "prompt_tokens": {
            "min": min(prompt_tokens) if prompt_tokens else None,
            "max": max(prompt_tokens) if prompt_tokens else None,
            "mean": round(statistics.fmean(prompt_tokens), 1) if prompt_tokens else None,
            **_percentiles(prompt_tokens),
        },
    }


def summarize_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Top-level summary + breakdown by call_type."""
    if not records:
        return {"n_calls": 0, "by_call_type": {}}
    overall = summarize_subset(records)
    by_type: dict[str, dict[str, Any]] = {}
    for ct in sorted({r.get("call_type", "") for r in records if r.get("call_type")}):
        subset = [r for r in records if r.get("call_type") == ct]
        if subset:
            by_type[ct] = summarize_subset(subset)
    overall["by_call_type"] = by_type
    return overall


def print_summary(summary: dict[str, Any]) -> None:
    n = summary.get("n_calls", 0)
    if n == 0:
        logger.info("=" * 72)
        logger.info("DIAGNOSTIC SUMMARY: no calls recorded.")
        logger.info("=" * 72)
        return
    bar = "=" * 72

    def _print_subset(label: str, s: dict[str, Any]) -> None:
        nn = s.get("n_calls", 0)
        if nn == 0:
            return
        logger.info("-- %s (%d calls)", label, nn)
        logger.info("  ok=%d failed=%d success_rate=%.1f%%",
                    s["n_ok"], s["n_failed"], s["success_rate"] * 100)
        logger.info("  status:        %s", s["final_status_breakdown"])
        logger.info("  finish_reason: %s", s["finish_reason_breakdown"])
        logger.info("  hit_token_cap: %d (%.1f%%)",
                    s["n_hit_token_cap"], 100.0 * s["n_hit_token_cap"] / nn)
        logger.info("  retried:       %d (%.1f%%)",
                    s["n_retried"], 100.0 * s["n_retried"] / nn)
        logger.info("  attempt_count: %s", s["attempt_counts_breakdown"])
        logger.info("  per-attempt:   %s", s["attempt_outcomes"])
        if s["error_class_histogram_across_attempts"]:
            logger.info("  errors:        %s",
                        s["error_class_histogram_across_attempts"])
        lat = s["latency_s"]
        logger.info("  latency(s):    min=%s mean=%s p50=%s p90=%s p95=%s p99=%s max=%s",
                    lat["min"], lat["mean"], lat["p50"], lat["p90"],
                    lat["p95"], lat["p99"], lat["max"])
        ct = s["completion_tokens"]
        logger.info("  comp_tokens:   min=%s mean=%s p50=%s p90=%s p95=%s p99=%s max=%s",
                    ct["min"], ct["mean"], ct["p50"], ct["p90"],
                    ct["p95"], ct["p99"], ct["max"])
        pt = s["prompt_tokens"]
        logger.info("  prompt_tokens: min=%s mean=%s p50=%s p90=%s p95=%s p99=%s max=%s",
                    pt["min"], pt["mean"], pt["p50"], pt["p90"],
                    pt["p95"], pt["p99"], pt["max"])

    logger.info(bar)
    logger.info("DIAGNOSTIC SUMMARY")
    logger.info(bar)
    _print_subset("OVERALL", summary)
    by_type = summary.get("by_call_type", {})
    for call_type, sub in by_type.items():
        _print_subset(call_type.upper(), sub)
    logger.info(bar)


# ============================================================================
# Section 7 — `python -m corp_diag_lib --show-config`
# ============================================================================


def _cli_entry(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m corp_diag_lib",
        description="Inspect the centralized corp diag config.",
    )
    p.add_argument(
        "--show-config", action="store_true",
        help="Print every config value with its resolved source.",
    )
    p.add_argument(
        "--config-path", type=Path, default=None,
        help="Explicit path to corp_diag_config.yaml (default: auto-discover).",
    )
    p.add_argument(
        "--profile-name", type=str, default=None,
        help="Override profile.name (precedence: cli > env > yaml).",
    )
    args = p.parse_args(argv)

    cli_overrides: dict[str, Any] = {}
    if args.profile_name is not None:
        cli_overrides["profile.name"] = args.profile_name
    config = load_config(yaml_path=args.config_path, cli_overrides=cli_overrides)

    if args.show_config or True:  # show by default when invoked
        print_resolved_config(config)
    return 0


if __name__ == "__main__":
    sys.exit(_cli_entry())
