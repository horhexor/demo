"""diag_repro.py — corp extraction-phase diagnostic, thin orchestrator.

Imports everything from corp_diag_lib (auth, resilient_invoke, MetricsWriter,
CallMetric, APIM header capture, error classification, summary, logging,
config loading + source tracking, token chaos). This file owns ONLY the
extraction-specific logic:

  - AtomicBehaviorCandidate Pydantic schema (mirror of wolfpack/contracts.py)
  - Extraction system prompt + per-window template
  - Understand-output loader + context window builder
  - invoke_extraction_batch (build prompt → resilient_invoke → parse → validate)
  - Sequential + concurrent batch dispatch
  - CLI + main

All settings come from corp_diag_config.yaml (with env-var and CLI overrides).
Run `python -m corp_diag_lib --show-config` to see resolved values + sources.

Usage:

    python diag_repro.py \\
        --understand-output-path <path> \\
        --outputs-root outputs/extraction-runs/corp \\
        --llm-profile-name corp \\
        --extract-batch-size 1 --extract-concurrency 8 \\
        -v
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import textwrap
import time
import traceback
from pathlib import Path
from typing import Any, Literal

from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

import corp_diag_lib as lib

logger = logging.getLogger("corp_diag.extraction")
raw_log = logging.getLogger("corp_diag.raw")
batch_log = logging.getLogger("corp_diag.batching")


# ============================================================================
# Pydantic schemas (mirror of wolfpack/contracts.py — extraction subset)
# ============================================================================


class _AnchorEvidenceRef(BaseModel):
    stable_anchor: str = Field(..., min_length=1)
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    snippet: str = Field(..., min_length=1)
    linked_ttp_ids: list[str] = Field(default_factory=list)
    source_kind: str

    @field_validator("source_kind")
    @classmethod
    def _validate_source_kind(cls, v: str) -> str:
        if v not in ("understand_section", "raw_fallback"):
            raise ValueError(f"source_kind must be one of those two; got {v!r}")
        return v

    @model_validator(mode="after")
    def _validate_line_bounds(self) -> "_AnchorEvidenceRef":
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class _TelemetryRequirements(BaseModel):
    log_sources: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)


class _AtomicBehaviorCandidate(BaseModel):
    behavior_id: str = Field(..., pattern=r"^B[1-9]\d*$")
    claim: str = Field(..., min_length=1)
    evidence_refs: list[_AnchorEvidenceRef] = Field(default_factory=list)
    observables: list[str] = Field(default_factory=list)
    telemetry_requirements: _TelemetryRequirements
    confidence: float = Field(..., ge=0.0, le=1.0)
    source_agent: str = Field(..., min_length=1)


# Understand-output schemas:


class _UnderstandTTPHit(BaseModel):
    technique_id: str = Field(..., min_length=1)
    match_type: str = Field(default="")


class _UnderstandSection(BaseModel):
    stable_anchor: str = Field(..., min_length=1)
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    content: str = Field(..., min_length=1)
    section_type: str = Field(default="")
    ttp_hits: list[_UnderstandTTPHit] = Field(default_factory=list)


class _UnderstandEnvelope(BaseModel):
    report: dict


# ============================================================================
# Extraction prompts (verbatim from wolfpack/pipeline/deepagent_runtime.py)
# ============================================================================


_EXTRACTION_PREAMBLE = textwrap.dedent("""\
    You are an expert threat-intelligence analyst performing recall-first behavior extraction.

    Your task: extract ALL observable atomic threat behaviors from the report sections below.
    Even low-confidence behaviors should be included — downstream validation will filter.

    Output a JSON array (no surrounding text) where each element has these fields:
    - behavior_id: sequential IDs starting at "B1", "B2", etc.
    - claim: a concise description of the atomic behavior
    - evidence_refs: list of objects, each with:
        - stable_anchor: the anchor ID of the source section
        - line_start: starting line number
        - line_end: ending line number
        - snippet: the relevant text excerpt
        - linked_ttp_ids: list of associated MITRE ATT&CK technique IDs
        - source_kind: "understand_section"
    - observables: list of IOCs, file names, domains, IPs found in the text
    - telemetry_requirements: object with "log_sources" (list) and "required_fields" (list)
    - confidence: float 0.0-1.0 based on evidence strength
    - source_agent: "behavior_extractor"

    IMPORTANT: Extract ALL behaviors, even those with weak evidence. Do not skip anything.
""")


_WINDOW_TEMPLATE = textwrap.dedent("""\
    --- Context Window: {anchor} (lines {line_start}-{line_end}) ---
    TTP IDs: {ttp_ids}
    Snippet:
    {snippet}
""")


_MARKDOWN_FENCE_RE = re.compile(
    r"^\s*```(?:json)?\s*\n?(.*?)\n?\s*```\s*$",
    re.DOTALL,
)


def _strip_markdown_fences(text: str) -> str:
    m = _MARKDOWN_FENCE_RE.match(text)
    if m:
        return m.group(1).strip()
    return text.strip()


def _normalize_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        if parts:
            return "\n".join(parts)
        return "\n".join(str(block) for block in content)
    return str(content)


def build_extraction_prompt(context_windows: list[dict[str, Any]]) -> str:
    if not context_windows:
        raise ValueError("context_windows must not be empty")
    sections: list[str] = [_EXTRACTION_PREAMBLE]
    for w in context_windows:
        sections.append(_WINDOW_TEMPLATE.format(
            anchor=w["stable_anchor"],
            line_start=w["line_start"],
            line_end=w["line_end"],
            ttp_ids=", ".join(w.get("ttp_ids", [])),
            snippet=w["snippet"],
        ))
    return "\n".join(sections)


# ============================================================================
# Understand-output loader + context windows
# ============================================================================


def load_understand_sections(path: Path) -> list[_UnderstandSection]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"understand-output not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"understand-output is not valid JSON: {exc}") from exc
    env = _UnderstandEnvelope.model_validate(payload)
    raw_sections = env.report.get("sections", [])
    sections = [_UnderstandSection.model_validate(s) for s in raw_sections]
    logger.info("Loaded %d Understand sections from %s", len(sections), path)
    return sections


def build_context_windows(
    sections: list[_UnderstandSection],
    *,
    max_snippet_chars: int = 400,
) -> list[dict[str, Any]]:
    ordered = sorted(
        sections,
        key=lambda s: (s.line_start, s.line_end, s.stable_anchor),
    )
    def _norm(content: str) -> str:
        return re.sub(r"\s+", " ", content.strip().lower())
    seen: set[str] = set()
    windows: list[dict[str, Any]] = []
    for sec in ordered:
        h = _norm(sec.content)
        if h in seen:
            continue
        seen.add(h)
        ttp_ids = sorted({
            hit.technique_id for hit in sec.ttp_hits if hit.match_type != "tool"
        })
        windows.append({
            "stable_anchor": sec.stable_anchor,
            "line_start": sec.line_start,
            "line_end": sec.line_end,
            "snippet": sec.content[:max_snippet_chars],
            "ttp_ids": ttp_ids,
        })
    logger.info("Built %d context windows (deduped from %d sections)", len(windows), len(sections))
    return windows


# ============================================================================
# Extraction call + dispatch
# ============================================================================


def _build_continuation_prompt(
    context_windows: list[dict[str, Any]],
    prefix_items: list[dict[str, Any]],
) -> str:
    """Build the continuation prompt: original prompt + continuation request.

    The model needs the original context (the threat-report sections) to
    extract from, plus a clear instruction to start from where it left off
    and NOT repeat prefix behaviors. A short summary of each prefix
    behavior's claim helps the model see exactly what's done.

    Mirrors ``wolfpack/pipeline/deepagent_runtime.py:_build_continuation_prompt``.
    """
    original = build_extraction_prompt(context_windows)
    n = len(prefix_items)
    prefix_summary_lines = []
    for i, item in enumerate(prefix_items):
        bid = item.get("behavior_id") or f"B{i + 1}"
        claim = (item.get("claim") or "").replace("\n", " ").strip()
        if len(claim) > 80:
            claim = claim[:77] + "..."
        prefix_summary_lines.append(f"  {bid}: {claim}")
    prefix_summary = "\n".join(prefix_summary_lines) if prefix_summary_lines else "  (none)"

    continuation_block = textwrap.dedent(f"""\

        ---

        [CONTINUATION REQUEST]

        Your previous output for this task was truncated mid-emission.
        You already completed these behaviors:

        {prefix_summary}

        Continue extraction from B{n + 1} onward. Output ONLY the
        REMAINING behaviors as a JSON array using the same schema. Do NOT
        repeat behaviors B1 through B{n}. If you believe there are no more
        behaviors to extract from the report sections above, output an
        empty array: [].
        """)
    return original + continuation_block


def _invoke_continuation_for_extraction(
    llm: ChatOpenAI,
    context_windows: list[dict[str, Any]],
    prefix_items: list[dict[str, Any]],
    *,
    config: lib.Config,
    metrics_writer: lib.MetricsWriter,
    parent_label: str,
) -> tuple[list[dict[str, Any]], bool]:
    """Issue the continuation LLM call and return (items, ok_status).

    ``ok_status=True`` means the invoke + parse round-tripped cleanly,
    regardless of whether the resulting list is empty — an empty list with
    ``finish_reason=stop`` means the model legitimately said "no more
    behaviors to extract" and is a valid outcome.

    ``ok_status=False`` only when something *broke*: HTTP/transport failure,
    malformed JSON, bad response shape, or unsalvageable truncation. The
    caller uses this signal to set ``partial_recovery`` only when the
    continuation itself failed, not when it cleanly returned nothing.

    Mirrors ``wolfpack/pipeline/deepagent_runtime.py:_invoke_continuation_for_extraction``.
    """
    cont_metric = lib.CallMetric(
        call_type="extract_continuation",
        call_label=f"continuation_of_{parent_label}",
        started_at=lib.iso_utc_now(),
        payload={
            "n_prefix_items": len(prefix_items),
            "parent_label": parent_label,
        },
    )
    t_start = time.monotonic()
    prompt = _build_continuation_prompt(context_windows, prefix_items)
    cont_metric.prompt_chars = len(prompt)

    try:
        try:
            response = lib.resilient_invoke(
                llm,
                [HumanMessage(content=prompt)],
                context=f"extract_continuation_{parent_label}",
                config=config,
                attempts=cont_metric.attempts,
            )
        except Exception as exc:
            cont_metric.final_status = "exhausted" if lib.is_transient_error(exc) else "non_transient"
            cont_metric.final_error = f"{type(exc).__name__}: {str(exc)[:400]}"
            logger.warning(
                "[extract_continuation %s] invoke failed: %s",
                parent_label, exc,
            )
            return [], False

        rm = lib.extract_response_metadata(response)
        cont_metric.finish_reason = rm["finish_reason"]
        cont_metric.prompt_tokens = rm["prompt_tokens"]
        cont_metric.completion_tokens = rm["completion_tokens"]
        cont_metric.total_tokens = rm["total_tokens"]

        raw_content = getattr(response, "content", None)
        if raw_content is None:
            cont_metric.final_status = "schema_fail"
            cont_metric.final_error = "continuation response had no .content"
            return [], False

        text_content = _normalize_content(raw_content)
        cont_metric.response_chars = len(text_content)
        cleaned = _strip_markdown_fences(text_content)
        cont_truncated = (cont_metric.finish_reason == "length")

        # Parse + (optionally) salvage one more time without recursing
        try:
            parsed = json.loads(cleaned)
            if not isinstance(parsed, list):
                raise ValueError(f"expected JSON array, got {type(parsed).__name__}")
        except (json.JSONDecodeError, ValueError) as exc:
            if cont_truncated:
                salvaged, _ = lib._salvage_truncated_json_array(cleaned)
                if salvaged:
                    parsed = salvaged
                    cont_metric.payload["continuation_salvaged"] = True
                else:
                    cont_metric.final_status = "parse_fail"
                    cont_metric.final_error = f"continuation parse_fail + no salvage: {exc}"
                    return [], False
            else:
                cont_metric.final_status = "parse_fail"
                cont_metric.final_error = f"continuation parse_fail: {exc}"
                return [], False

        # Validate Pydantic on continuation items — be lenient (skip invalid
        # rather than raising), matching wolfpack's lenient continuation behavior.
        validated: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for idx, item in enumerate(parsed):
            try:
                cand = _AtomicBehaviorCandidate.model_validate(item)
            except ValidationError as exc:
                skipped.append({"idx": idx, "error": str(exc)[:200]})
                continue
            validated.append(cand.model_dump())

        cont_metric.payload["behaviors_validated"] = len(validated)
        if skipped:
            cont_metric.payload["skipped_invalid"] = skipped

        cont_metric.final_status = "ok" if validated or not parsed else "partial_recovery"
        logger.info(
            "[extract_continuation %s] recovered %d behaviors (%d skipped)",
            parent_label, len(validated), len(skipped),
        )
        # Invoke + parse succeeded — even an empty validated list is a clean
        # outcome (model legitimately said "no more behaviors").
        return validated, True

    finally:
        cont_metric.finished_at = lib.iso_utc_now()
        cont_metric.total_elapsed_s = round(time.monotonic() - t_start, 3)
        metrics_writer.write(cont_metric)


def invoke_extraction_batch(
    llm: ChatOpenAI,
    windows: list[dict[str, Any]],
    *,
    batch_idx: int,
    n_batches: int,
    metrics_writer: lib.MetricsWriter,
    config: lib.Config,
) -> list[dict[str, Any]]:
    metric = lib.CallMetric(
        call_type="extract_batch",
        call_label=f"batch_{batch_idx + 1}_of_{n_batches}",
        started_at=lib.iso_utc_now(),
        payload={
            "n_windows": len(windows),
            "anchors": [w.get("stable_anchor", "?") for w in windows],
        },
    )
    t_start = time.monotonic()
    prompt = build_extraction_prompt(windows)
    metric.prompt_chars = len(prompt)

    try:
        try:
            response = lib.resilient_invoke(
                llm,
                [HumanMessage(content=prompt)],
                context=f"extract_batch_{batch_idx + 1}_of_{n_batches}",
                config=config,
                attempts=metric.attempts,
            )
        except Exception as exc:
            metric.final_status = "exhausted" if lib.is_transient_error(exc) else "non_transient"
            metric.final_error = f"{type(exc).__name__}: {str(exc)[:400]}"
            raise

        rm = lib.extract_response_metadata(response)
        metric.finish_reason = rm["finish_reason"]
        metric.prompt_tokens = rm["prompt_tokens"]
        metric.completion_tokens = rm["completion_tokens"]
        metric.total_tokens = rm["total_tokens"]

        raw_content = getattr(response, "content", None)
        if raw_content is None:
            metric.final_status = "blank"
            metric.final_error = f"LLM response had no .content (type={type(response).__name__})"
            raise RuntimeError(metric.final_error)

        text_content = _normalize_content(raw_content)
        metric.response_chars = len(text_content)
        raw_log.info(
            "RAW_RESPONSE_BEGIN batch=%d/%d chars=%d finish_reason=%s completion_tokens=%s",
            batch_idx + 1, n_batches, len(text_content), metric.finish_reason,
            metric.completion_tokens,
        )
        raw_log.info("%s", text_content)
        raw_log.info("RAW_RESPONSE_END batch=%d/%d", batch_idx + 1, n_batches)
        batch_log.info(
            "Batch %d/%d response: %d chars, finish_reason=%s, completion_tokens=%s",
            batch_idx + 1, n_batches, len(text_content),
            metric.finish_reason, metric.completion_tokens,
        )

        cleaned = _strip_markdown_fences(text_content)
        if not cleaned:
            metric.final_status = "blank"
            metric.final_error = "stripped content is empty"
            raise RuntimeError(f"Batch {batch_idx + 1}: LLM returned empty content")

        used_salvage = False
        truncated = (metric.finish_reason == "length")

        try:
            parsed = json.loads(cleaned)
            if not isinstance(parsed, list):
                raise ValueError(f"expected JSON array, got {type(parsed).__name__}")
        except (json.JSONDecodeError, ValueError) as exc:
            if truncated:
                # Truncated response — try to salvage the longest valid prefix
                # and fire a continuation for the missing tail.
                prefix_items, _remaining = lib._salvage_truncated_json_array(cleaned)
                if prefix_items:
                    used_salvage = True
                    metric.payload["continuation_fired"] = True
                    metric.payload["behaviors_from_prefix"] = len(prefix_items)
                    logger.info(
                        "Batch %d/%d truncated at finish_reason=length; "
                        "salvaged %d prefix behaviors, issuing continuation",
                        batch_idx + 1, n_batches, len(prefix_items),
                    )
                    continuation_items, continuation_ok = _invoke_continuation_for_extraction(
                        llm,
                        context_windows=windows,
                        prefix_items=prefix_items,
                        config=config,
                        metrics_writer=metrics_writer,
                        parent_label=f"batch_{batch_idx + 1}_of_{n_batches}",
                    )
                    metric.payload["behaviors_from_continuation"] = len(continuation_items)
                    metric.payload["continuation_succeeded"] = continuation_ok
                    parsed = prefix_items + continuation_items
                    if not continuation_ok:
                        # Continuation invoke itself failed — partial_recovery
                        # with just the prefix preserved.
                        metric.final_status = "partial_recovery"
                        metric.final_error = "continuation invoke failed"
                else:
                    metric.final_status = "parse_fail"
                    metric.final_error = f"truncated + no salvageable prefix: {exc}"
                    raise RuntimeError(metric.final_error) from exc
            else:
                metric.final_status = "parse_fail"
                metric.final_error = f"JSONDecodeError: {exc}"
                raise RuntimeError(f"Batch {batch_idx + 1}: failed to parse JSON: {exc}") from exc

        validated: list[dict[str, Any]] = []
        schema_failures: list[dict[str, Any]] = []
        for idx, item in enumerate(parsed):
            try:
                cand = _AtomicBehaviorCandidate.model_validate(item)
            except ValidationError as exc:
                if used_salvage:
                    # Lenient on salvage path — record failed item but keep going.
                    schema_failures.append({"idx": idx, "error": str(exc)[:200]})
                    continue
                metric.final_status = "schema_fail"
                metric.final_error = f"item {idx}: {exc}"
                raise RuntimeError(metric.final_error) from exc
            validated.append(cand.model_dump())

        metric.payload["behaviors_extracted"] = len(validated)
        if schema_failures:
            metric.payload["schema_failures_skipped"] = schema_failures
        # final_status: pending = no recovery path touched it = clean ok.
        # If continuation ran and failed, final_status was already set above.
        if metric.final_status == "pending":
            metric.final_status = "ok"
        return validated

    finally:
        metric.finished_at = lib.iso_utc_now()
        metric.total_elapsed_s = round(time.monotonic() - t_start, 3)
        metric.n_attempts = len(metric.attempts)
        if metric.final_status == "pending":
            metric.final_status = "unknown"
        metrics_writer.write(metric)


def sequential_extract(
    llm: ChatOpenAI,
    windows: list[dict[str, Any]],
    *,
    batch_size: int,
    metrics_writer: lib.MetricsWriter,
    config: lib.Config,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    n_total = len(windows)
    bsize = batch_size if batch_size > 0 else max(n_total, 1)
    n_batches = (n_total + bsize - 1) // bsize
    batch_log.info(
        "Sequential extraction: %d windows / batch_size=%d -> %d LLM calls",
        n_total, bsize, n_batches,
    )
    merged: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for batch_idx in range(n_batches):
        start = batch_idx * bsize
        chunk = windows[start: start + bsize]
        anchors = [w.get("stable_anchor", "?") for w in chunk]
        batch_log.info(
            "Batch %d/%d START: windows[%d:%d] size=%d %s",
            batch_idx + 1, n_batches, start, start + len(chunk), len(chunk), anchors,
        )
        try:
            chunk_results = invoke_extraction_batch(
                llm, chunk,
                batch_idx=batch_idx, n_batches=n_batches,
                metrics_writer=metrics_writer, config=config,
            )
        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {str(exc)[:300]}"
            batch_log.warning("Batch %d/%d FAIL: %s", batch_idx + 1, n_batches, err_msg)
            failures.append({"batch_index": batch_idx, "anchors": anchors, "error": err_msg})
            continue
        for local_idx, item in enumerate(chunk_results):
            item["behavior_id"] = f"B{len(merged) + local_idx + 1}"
        merged.extend(chunk_results)
        batch_log.info(
            "Batch %d/%d OK: %d behaviors (running total: %d)",
            batch_idx + 1, n_batches, len(chunk_results), len(merged),
        )
    return merged, failures


def concurrent_extract(
    llm: ChatOpenAI,
    windows: list[dict[str, Any]],
    *,
    batch_size: int,
    concurrency: int,
    metrics_writer: lib.MetricsWriter,
    config: lib.Config,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    n_total = len(windows)
    bsize = batch_size if batch_size > 0 else 1
    n_batches = (n_total + bsize - 1) // bsize
    batch_log.info(
        "Concurrent extraction: %d windows / batch_size=%d / concurrency=%d -> %d LLM calls",
        n_total, bsize, concurrency, n_batches,
    )
    batches: list[tuple[int, list[dict[str, Any]]]] = []
    for batch_idx in range(n_batches):
        start = batch_idx * bsize
        batches.append((batch_idx, windows[start: start + bsize]))
    sem = asyncio.Semaphore(concurrency)
    failures: list[dict[str, Any]] = []

    async def _one_batch(batch_idx: int, chunk: list[dict[str, Any]]) -> tuple[int, list[dict[str, Any]]]:
        async with sem:
            anchors = [w.get("stable_anchor", "?") for w in chunk]
            batch_log.info(
                "Batch %d/%d START: %d windows %s",
                batch_idx + 1, n_batches, len(chunk), anchors,
            )
            try:
                result = await asyncio.to_thread(
                    invoke_extraction_batch,
                    llm, chunk,
                    batch_idx=batch_idx, n_batches=n_batches,
                    metrics_writer=metrics_writer, config=config,
                )
                batch_log.info(
                    "Batch %d/%d OK: %d behaviors", batch_idx + 1, n_batches, len(result),
                )
                return batch_idx, result
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {str(exc)[:300]}"
                batch_log.warning("Batch %d/%d FAIL: %s", batch_idx + 1, n_batches, err_msg)
                failures.append({"batch_index": batch_idx, "anchors": anchors, "error": err_msg})
                return batch_idx, []

    async def _run_all() -> list[tuple[int, list[dict[str, Any]]]]:
        return await asyncio.gather(*(_one_batch(idx, chunk) for idx, chunk in batches))

    results = asyncio.run(_run_all())
    results.sort(key=lambda pair: pair[0])
    merged: list[dict[str, Any]] = []
    for _, chunk_results in results:
        for item in chunk_results:
            item["behavior_id"] = f"B{len(merged) + 1}"
            merged.append(item)
    if failures:
        batch_log.warning(
            "Concurrent extraction completed with %d/%d failed batches",
            len(failures), n_batches,
        )
    return merged, failures


def extract(
    llm: ChatOpenAI,
    windows: list[dict[str, Any]],
    *,
    batch_size: int | None,
    concurrency: int | None,
    metrics_writer: lib.MetricsWriter,
    config: lib.Config,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if concurrency and concurrency > 1:
        return concurrent_extract(
            llm, windows,
            batch_size=(batch_size or 1), concurrency=concurrency,
            metrics_writer=metrics_writer, config=config,
        )
    if batch_size and batch_size > 0:
        return sequential_extract(
            llm, windows, batch_size=batch_size,
            metrics_writer=metrics_writer, config=config,
        )
    # Single call (one prompt for all windows).
    batch_log.info("Single-call extraction: %d windows in one LLM call", len(windows))
    try:
        merged = invoke_extraction_batch(
            llm, windows,
            batch_idx=0, n_batches=1,
            metrics_writer=metrics_writer, config=config,
        )
        for idx, item in enumerate(merged):
            item["behavior_id"] = f"B{idx + 1}"
        return merged, []
    except Exception as exc:
        return [], [{
            "batch_index": 0,
            "anchors": [w.get("stable_anchor", "?") for w in windows],
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
        }]


# ============================================================================
# CLI + main
# ============================================================================


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="diag_repro.py",
        description=(
            "Corp extraction-phase diagnostic. Settings come from "
            "corp_diag_config.yaml + env vars + the CLI flags below "
            "(CLI > env > yaml > default). "
            "Inspect resolved config: python -m corp_diag_lib --show-config"
        ),
    )
    p.add_argument("--reports-dir", type=Path, default=None,
                   help="Accepted for parity with wolfpack CLI; unused in diag.")
    p.add_argument("--understand-output-path", type=Path, required=True,
                   help="Path to understand-output.json (required).")
    p.add_argument("--outputs-root", type=Path, default=None,
                   help="Root directory for the single log file (overrides diag.outputs_root).")
    p.add_argument("--llm-profile-name", type=str, default=None,
                   help="Profile name (overrides profile.name).")
    p.add_argument("--extract-batch-size", type=int, default=None,
                   help="Windows per LLM call (overrides diag.extract_batch_size).")
    p.add_argument("--extract-concurrency", type=int, default=None,
                   help="Max concurrent batches (overrides diag.extract_concurrency).")
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
                   help="Print resolved config and exit (don't run extraction).")
    return p.parse_args(argv)


def _cli_to_overrides(args: argparse.Namespace) -> dict[str, Any]:
    """Map CLI args to dotted-path overrides for lib.load_config."""
    overrides: dict[str, Any] = {}
    if args.llm_profile_name is not None:
        overrides["profile.name"] = args.llm_profile_name
    if args.outputs_root is not None:
        overrides["diag.outputs_root"] = str(args.outputs_root)
    if args.extract_batch_size is not None:
        overrides["diag.extract_batch_size"] = args.extract_batch_size
    if args.extract_concurrency is not None:
        overrides["diag.extract_concurrency"] = args.extract_concurrency
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
    log_file = lib.make_log_file(outputs_root, prefix="diag_repro")
    lib.setup_logging(config.diag.verbose, log_file)

    os.environ["PREDATOR_PROFILE"] = config.profile.name
    logger.info("PREDATOR_PROFILE pinned to %r", config.profile.name)
    logger.info("Log file (single output): %s", log_file)
    logger.info("CONFIG: %s", json.dumps({
        "profile": config.profile.name,
        "endpoint": config.auth.endpoint,
        "deployment": config.auth.deployment,
        "max_completion_tokens": config.llm.max_completion_tokens,
        "batch_size": config.diag.extract_batch_size,
        "concurrency": config.diag.extract_concurrency,
        "token_chaos_rate": config.chaos.token_chaos_rate,
    }, separators=(",", ":")))

    metrics_writer = lib.MetricsWriter()
    try:
        if config.auth.api_surface != "openai-compat":
            raise ValueError(
                f"diag_repro is corp-path only: api_surface={config.auth.api_surface!r}"
            )

        llm = lib.build_openai_compat_client(config)
        sections = load_understand_sections(args.understand_output_path)
        windows = build_context_windows(sections)
        if not windows:
            raise ValueError("No context windows built — understand-output is empty?")

        t0 = time.monotonic()
        behaviors, failures = extract(
            llm, windows,
            batch_size=config.diag.extract_batch_size,
            concurrency=config.diag.extract_concurrency,
            metrics_writer=metrics_writer, config=config,
        )
        elapsed_s = round(time.monotonic() - t0, 2)
        logger.info(
            "DONE. behaviors=%d failed_batches=%d elapsed=%.2fs",
            len(behaviors), len(failures), elapsed_s,
        )
        summary = lib.summarize_metrics(metrics_writer.records())
        lib.print_summary(summary)
        return 0 if not failures else 2

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
