#!/usr/bin/env python3
"""Extract baseline guidance from ATHF/LOCK Markdown documents.

The tool is intentionally LLM-first but evidence-grounded:

1. It parses LOCK files, sections, line numbers, query blocks, telemetry names,
   baseline-relevant behavior categories, gaps, detections, and private observables.
2. If enabled, an Azure-identity-backed ChatOpenAI client proposes richer
   structured insights per document through the local APIM mimic or CORP APIM.
3. All outputs retain source files, line spans, and deterministic evidence so an
   analyst can audit recommendations before promoting them into a knowledge base.

The default mode is offline deterministic extraction. Use ``--llm azure-apim``
when the APIM mimic or approved corporate APIM endpoint is available.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


LOCK_SECTION_NAMES = ("LEARN", "OBSERVE", "CHECK", "KEEP")
DEFAULT_ENV_FILE = Path(__file__).with_name("lock-kb-insights.env")

MDE_TABLES = (
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceImageLoadEvents",
    "DeviceRegistryEvents",
    "DeviceEvents",
    "DeviceLogonEvents",
    "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities",
    "CloudAppEvents",
    "CloudProcessEvents",
    "EmailEvents",
    "UrlClickEvents",
    "AlertEvidence",
    "ExposureGraphEdges",
    "OfficeActivity",
    "AuditLogs",
    "SigninLogs",
    "IdentityLogonEvents",
    "IdentityDirectoryEvents",
)

SOURCE_TERMS = (
    *MDE_TABLES,
    "Splunk",
    "SPL",
    "KQL",
    "Microsoft Defender XDR",
    "Defender XDR",
    "Palo",
    "PAN",
    "pan:traffic",
    "pan:threat",
    "TACACS",
    "ISE",
    "vCenter",
    "VPXD",
    "VMware",
    "WSUS",
    "ADCS",
    "IronPort",
    "Cisco ESA",
    "GitHub",
)

BASELINE_TAXONOMY: dict[str, dict[str, Any]] = {
    "process_lineage": {
        "name": "Process lineage and command-line baseline",
        "keywords": [
            "DeviceProcessEvents",
            "ProcessCommandLine",
            "InitiatingProcess",
            "parent process",
            "process chain",
            "cmd.exe",
            "powershell",
            "pwsh",
            "node.exe",
            "python.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "lolbin",
        ],
        "primary_sources": ["DeviceProcessEvents"],
    },
    "network_egress": {
        "name": "Process-aware network egress baseline",
        "keywords": [
            "DeviceNetworkEvents",
            "RemoteUrl",
            "RemoteIP",
            "ConnectionSuccess",
            "bytes_out",
            "bytes_in",
            "POST",
            "curl",
            "wget",
            "proxy",
            "firewall",
            "PAN",
            "Palo",
            "C2",
            "exfil",
            "egress",
        ],
        "primary_sources": ["DeviceNetworkEvents", "proxy", "firewall", "PAN"],
    },
    "file_staging": {
        "name": "File staging and writable-path baseline",
        "keywords": [
            "DeviceFileEvents",
            "FileCreated",
            "FileModified",
            "FileDeleted",
            "FolderPath",
            "AppData",
            "ProgramData",
            "Temp",
            "Public",
            ".lnk",
            ".vbs",
            ".ps1",
            ".js",
            ".dll",
            ".dat",
            "archive",
            "shortcut",
        ],
        "primary_sources": ["DeviceFileEvents"],
    },
    "developer_package_tooling": {
        "name": "Developer and package tooling baseline",
        "keywords": [
            "npm",
            "yarn",
            "pnpm",
            "bun",
            "node",
            "package",
            ".npmrc",
            "GitHub runner",
            "trufflehog",
            "AzureCLI",
            "VS Code",
            "Code.exe",
            "Jupyter",
            "Conda",
            "Python",
        ],
        "primary_sources": ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents"],
    },
    "messaging_exfil": {
        "name": "Messaging and collaboration exfil baseline",
        "keywords": [
            "Telegram",
            "Discord",
            "t.me",
            "api.telegram.org",
            "screenclip",
            "SnippingTool",
            "bytes_out",
            "upload",
            "messaging",
            "collaboration",
        ],
        "primary_sources": ["DeviceNetworkEvents", "proxy", "firewall"],
    },
    "shadow_ai": {
        "name": "Shadow AI and API usage baseline",
        "keywords": [
            "Shadow AI",
            "OpenAI",
            "Anthropic",
            "Claude",
            "Gemini",
            "generativelanguage",
            "AI API",
            "PowerToys",
            "ms.ai.framework",
            "AutoGen",
            "Docker",
            "vpnkit",
        ],
        "primary_sources": ["DeviceNetworkEvents", "proxy", "firewall"],
    },
    "vulnerability_exposure": {
        "name": "Vulnerability exposure and product inventory baseline",
        "keywords": [
            "DeviceTvmSoftwareInventory",
            "DeviceTvmSoftwareVulnerabilities",
            "CVE",
            "vulnerability",
            "version",
            "inventory",
            "patch",
            "remediation",
            "exposure",
            "KEV",
        ],
        "primary_sources": [
            "DeviceTvmSoftwareInventory",
            "DeviceTvmSoftwareVulnerabilities",
            "CMDB",
        ],
    },
    "identity_admin": {
        "name": "Identity, authentication, and admin baseline",
        "keywords": [
            "SigninLogs",
            "IdentityLogonEvents",
            "logon",
            "MFA",
            "authentication",
            "service account",
            "ADFS",
            "TACACS",
            "ISE",
            "nltest",
            "dsquery",
            "cmdkey",
            "credential",
        ],
        "primary_sources": ["SigninLogs", "IdentityLogonEvents", "OfficeActivity", "TACACS", "ISE"],
    },
    "cloud_saas_audit": {
        "name": "Cloud, SaaS, and source-control audit baseline",
        "keywords": [
            "CloudAppEvents",
            "CloudProcessEvents",
            "OfficeActivity",
            "GitHub",
            "AWS",
            "Azure",
            "M365",
            "Graph",
            "repo",
            "mailbox",
            "service principal",
            "enterprise application",
        ],
        "primary_sources": ["CloudAppEvents", "OfficeActivity", "CloudProcessEvents"],
    },
    "email_web_delivery": {
        "name": "Email and web-delivery baseline",
        "keywords": [
            "EmailEvents",
            "IronPort",
            "Cisco ESA",
            "attachment",
            "phish",
            "Teams Call",
            "sender",
            "recipient",
            "email",
        ],
        "primary_sources": ["EmailEvents", "IronPort", "proxy"],
    },
    "security_simulation": {
        "name": "Security simulation and BAS baseline",
        "keywords": [
            "Picus",
            "simulation",
            "SOAR",
            "BAS",
            "adversary emulation",
            "false positive",
            "FP",
        ],
        "primary_sources": ["DeviceProcessEvents", "DeviceFileEvents", "AlertEvidence"],
    },
    "vmware_virtualization": {
        "name": "VMware and virtualization administration baseline",
        "keywords": [
            "VMware",
            "vCenter",
            "VMRC",
            "VPXD",
            ".vmx",
            ".vmdk",
            "clone",
            "VM cloning",
            "ESXi",
            "vSphere",
        ],
        "primary_sources": ["vmware:esx", "DeviceFileEvents", "DeviceProcessEvents"],
    },
    "network_device_ot": {
        "name": "Network device, SD-WAN, and OT/PLC baseline",
        "keywords": [
            "Cisco",
            "SD-WAN",
            "PLC",
            "Rockwell",
            "Allen-Bradley",
            "industrial",
            "TACACS",
            "ISE",
            "syslog",
            "vManage",
        ],
        "primary_sources": ["network device", "syslog", "TACACS", "ISE", "OT"],
    },
}

PRIVATE_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "url": re.compile(r"\b(?:hxxps?|https?)://[^\s)>'\"]+"),
    "windows_path": re.compile(r"\b[A-Za-z]:\\[^\n\r`|]+"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "ticket_or_work_item": re.compile(r"(?<![A-Za-z0-9])#?\d{7}(?![A-Za-z0-9])"),
}


@dataclass
class Evidence:
    source_file: str
    line_start: int
    line_end: int
    section: str
    kind: str
    value: str
    text: str


@dataclass
class LockDocument:
    path: Path
    relpath: str
    text: str
    lines: list[str]
    frontmatter: dict[str, str]
    sections: dict[str, tuple[int, int]]
    headings: list[tuple[int, int, str]]
    query_blocks: list[dict[str, Any]]
    manifest: dict[str, str] = field(default_factory=dict)
    telemetry_counts: Counter[str] = field(default_factory=Counter)
    behavior_scores: Counter[str] = field(default_factory=Counter)
    evidence: list[Evidence] = field(default_factory=list)


class RunLogger:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path).expanduser().resolve() if path else None
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, message: str) -> None:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S %z')} | {message}"
        with self._lock:
            print(line, file=sys.stderr, flush=True)
            if self.path:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")


class Heartbeat:
    def __init__(self, logger: RunLogger, label: str, interval_seconds: int, started: float) -> None:
        self.logger = logger
        self.label = label
        self.interval_seconds = interval_seconds
        self.started = started
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "Heartbeat":
        if self.interval_seconds > 0:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            elapsed = time.time() - self.started
            self.logger.log(f"{self.label} still waiting; elapsed={elapsed:.1f}s")


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text

    raw = text[4:end].strip()
    body = text[end + 4 :].lstrip("\n")
    metadata: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip() or ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip().strip('"').strip("'")
        metadata[key.strip()] = value
    return metadata, body


def parse_headings(lines: list[str]) -> list[tuple[int, int, str]]:
    headings: list[tuple[int, int, str]] = []
    for idx, line in enumerate(lines, start=1):
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if match:
            headings.append((idx, len(match.group(1)), match.group(2).strip()))
    return headings


def parse_sections(lines: list[str], headings: list[tuple[int, int, str]]) -> dict[str, tuple[int, int]]:
    sections: dict[str, tuple[int, int]] = {}
    level2 = [(line_no, title.upper().strip()) for line_no, level, title in headings if level == 2]
    for pos, (line_no, title) in enumerate(level2):
        normalized = re.sub(r"[^A-Z]", "", title)
        for name in LOCK_SECTION_NAMES:
            if normalized.startswith(name):
                next_line = level2[pos + 1][0] if pos + 1 < len(level2) else len(lines) + 1
                sections[name] = (line_no, next_line - 1)
                break
    return sections


def parse_query_blocks(lines: list[str]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    in_block = False
    start = 0
    language = ""
    content: list[str] = []
    for idx, line in enumerate(lines, start=1):
        if line.startswith("```"):
            if not in_block:
                in_block = True
                start = idx
                language = line.strip("`").strip()
                content = []
            else:
                blocks.append(
                    {
                        "line_start": start,
                        "line_end": idx,
                        "language": language,
                        "text": "\n".join(content),
                    }
                )
                in_block = False
        elif in_block:
            content.append(line)
    return blocks


def section_for_line(doc: LockDocument, line_no: int) -> str:
    for name, (start, end) in doc.sections.items():
        if start <= line_no <= end:
            return name
    return "UNKNOWN"


def load_grouped_manifest(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    if not path.exists():
        raise SystemExit(f"Grouped manifest does not exist: {path}")

    by_key: dict[str, dict[str, str]] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            keys = [
                row.get("doc_id", ""),
                row.get("sequence", ""),
                Path(row.get("combined_md", "")).name,
                row.get("combined_md", ""),
            ]
            for key in keys:
                if key:
                    by_key[key] = row
    return by_key


def manifest_for_doc(frontmatter: dict[str, str], path: Path, manifest_index: dict[str, dict[str, str]]) -> dict[str, str]:
    if not manifest_index:
        return {}
    candidates = [
        frontmatter.get("work_item", ""),
        frontmatter.get("sequence", ""),
        Path(frontmatter.get("source_file", "")).name,
        frontmatter.get("source_file", "").removeprefix("../"),
        path.name.replace(".lock.md", ".md"),
    ]
    for candidate in candidates:
        if candidate in manifest_index:
            return manifest_index[candidate]
    return {}


def read_lock_documents(input_dir: Path, manifest_index: dict[str, dict[str, str]] | None = None) -> list[LockDocument]:
    paths = sorted(input_dir.glob("*.lock.md"))
    if not paths:
        paths = sorted(input_dir.glob("*.md"))

    docs: list[LockDocument] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        frontmatter, _ = parse_frontmatter(text)
        manifest = manifest_for_doc(frontmatter, path, manifest_index or {})
        lines = text.splitlines()
        headings = parse_headings(lines)
        sections = parse_sections(lines, headings)
        query_blocks = parse_query_blocks(lines)
        docs.append(
            LockDocument(
                path=path,
                relpath=path.name,
                text=text,
                lines=lines,
                frontmatter=frontmatter,
                sections=sections,
                headings=headings,
                query_blocks=query_blocks,
                manifest=manifest,
            )
        )
    return docs


def add_evidence(doc: LockDocument, line_no: int, kind: str, value: str, text: str) -> None:
    doc.evidence.append(
        Evidence(
            source_file=doc.relpath,
            line_start=line_no,
            line_end=line_no,
            section=section_for_line(doc, line_no),
            kind=kind,
            value=value,
            text=text.strip(),
        )
    )


def deterministic_extract(doc: LockDocument) -> None:
    table_re = re.compile(r"\b(" + "|".join(re.escape(t) for t in MDE_TABLES) + r")\b")
    index_re = re.compile(r"\bindex\s*=\s*[\"']?([A-Za-z0-9_:-]+)")
    sourcetype_re = re.compile(r"\bsourcetype\s*(?:=|IN)\s*[\"']?([A-Za-z0-9_:\-]+)")

    for idx, line in enumerate(doc.lines, start=1):
        for table in table_re.findall(line):
            doc.telemetry_counts[table] += 1
            add_evidence(doc, idx, "telemetry_table", table, line)
        for match in index_re.finditer(line):
            value = f"index={match.group(1)}"
            doc.telemetry_counts[value] += 1
            add_evidence(doc, idx, "splunk_index", value, line)
        for match in sourcetype_re.finditer(line):
            value = f"sourcetype={match.group(1)}"
            doc.telemetry_counts[value] += 1
            add_evidence(doc, idx, "sourcetype", value, line)
        for term in SOURCE_TERMS:
            if term not in MDE_TABLES and keyword_count(line, term):
                doc.telemetry_counts[term] += 1
                add_evidence(doc, idx, "telemetry_term", term, line)
        for pattern_name, pattern in PRIVATE_PATTERNS.items():
            for match in pattern.finditer(line):
                add_evidence(doc, idx, f"private_{pattern_name}", match.group(0), line)

    for category, config in BASELINE_TAXONOMY.items():
        score = 0
        for keyword in config["keywords"]:
            score += keyword_count(doc.text, keyword)
        if score:
            doc.behavior_scores[category] = score


def keyword_count(text: str, keyword: str) -> int:
    """Count keyword matches without substring inflation.

    Short tokens such as ``ISE`` must not match inside words like
    ``compromise``. Multi-word and punctuation-bearing values are still matched
    as phrases.
    """

    escaped = re.escape(keyword)
    if re.fullmatch(r"[A-Za-z0-9_]+", keyword):
        pattern = rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])"
    else:
        pattern = escaped
    return len(re.findall(pattern, text, flags=re.IGNORECASE))


def top_evidence(doc: LockDocument, kinds: set[str] | None = None, limit: int = 40) -> list[Evidence]:
    selected = [
        ev
        for ev in doc.evidence
        if kinds is None or ev.kind in kinds or any(ev.kind.startswith(kind) for kind in kinds)
    ]
    # Prefer LOCK sections and terse source lines.
    section_rank = {"KEEP": 0, "CHECK": 1, "OBSERVE": 2, "LEARN": 3, "UNKNOWN": 4}
    selected.sort(key=lambda ev: (section_rank.get(ev.section, 5), ev.line_start, len(ev.text)))
    deduped: list[Evidence] = []
    seen: set[tuple[str, int, str, str]] = set()
    for ev in selected:
        key = (ev.source_file, ev.line_start, ev.kind, ev.value)
        if key not in seen:
            deduped.append(ev)
            seen.add(key)
        if len(deduped) >= limit:
            break
    return deduped


def section_excerpt(doc: LockDocument, section: str, max_chars: int) -> str:
    if section not in doc.sections:
        return ""
    start, end = doc.sections[section]
    raw_lines = doc.lines[start - 1 : end]
    numbered = [f"{start + i}: {line}" for i, line in enumerate(raw_lines)]
    text = "\n".join(numbered)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]"


def build_llm_excerpt(doc: LockDocument, max_chars: int = 18000) -> str:
    parts: list[str] = []
    title = doc.frontmatter.get("title") or next((h[2] for h in doc.headings if h[1] == 1), doc.relpath)
    parts.append(f"FILE: {doc.relpath}")
    parts.append(f"TITLE: {title}")
    if doc.frontmatter:
        parts.append("FRONTMATTER:\n" + json.dumps(doc.frontmatter, indent=2, sort_keys=True))

    for section in LOCK_SECTION_NAMES:
        excerpt = section_excerpt(doc, section, max_chars=4500 if section == "KEEP" else 3000)
        if excerpt:
            parts.append(f"\nSECTION {section} WITH LINE NUMBERS:\n{excerpt}")

    evidence = top_evidence(doc, kinds={"telemetry_", "splunk_", "sourcetype", "private_"}, limit=35)
    if evidence:
        parts.append("\nDETERMINISTIC MATCHES:")
        for ev in evidence:
            parts.append(
                f"{ev.line_start}: [{ev.section}] {ev.kind}={ev.value} :: {ev.text[:280]}"
            )

    excerpt = "\n\n".join(parts)
    if len(excerpt) > max_chars:
        return excerpt[:max_chars] + "\n...[truncated]"
    return excerpt


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=True, indent=2, sort_keys=True)


def load_env_file(path: Path | str, *, override: bool = False) -> dict[str, str]:
    """Load simple KEY=VALUE settings from an env file.

    This intentionally supports only shell-like assignment lines, optional
    ``export ``, blank lines, comments, and matching single/double quotes.
    Existing environment values win unless ``override`` is true.
    """

    env_path = Path(path).expanduser().resolve()
    if not env_path.exists():
        raise SystemExit(f"Env file does not exist: {env_path}")

    loaded: dict[str, str] = {}
    for line_no, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise SystemExit(f"Invalid env line {env_path}:{line_no}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise SystemExit(f"Invalid env key {env_path}:{line_no}: {key!r}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        loaded[key] = value
        if override or key not in os.environ:
            os.environ[key] = value
    return loaded


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a float, got {raw!r}") from exc


def _load_env_for_args(argv: list[str] | None) -> str:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--env-file", default=os.environ.get("LOCK_KB_ENV_FILE", ""))
    pre_args, _ = pre_parser.parse_known_args(argv)
    if pre_args.env_file:
        load_env_file(pre_args.env_file, override=True)
        return str(Path(pre_args.env_file).expanduser().resolve())
    if DEFAULT_ENV_FILE.exists():
        load_env_file(DEFAULT_ENV_FILE)
        return str(DEFAULT_ENV_FILE)
    return ""


def parse_json_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise


def build_llm_prompt(doc: LockDocument, excerpt: str) -> list[dict[str, str]]:
    schema = {
        "document_summary": "short summary of what the hunt teaches future baselining",
        "baseline_candidates": [
            {
                "category": "one of the provided categories or a concise new category",
                "name": "baseline name",
                "rationale": "why this baseline is needed",
                "normal_context": "what normal can look like",
                "suspicious_when": "what makes it suspicious",
                "telemetry_sources": ["tables, indexes, log families"],
                "useful_fields": ["fields to baseline"],
                "starter_questions": ["questions analysts should answer"],
                "source_line_refs": [123, 124],
                "confidence": "low|medium|high",
                "needs_human_review": True,
            }
        ],
        "behavior_patterns": [
            {
                "pattern": "behavior chain or analytic idea",
                "source_line_refs": [123],
                "promotion_guidance": "how to safely reuse it",
            }
        ],
        "benign_patterns": [
            {
                "pattern": "benign or false positive pattern",
                "suspicious_only_when": "conditions that increase concern",
                "source_line_refs": [123],
            }
        ],
        "telemetry_gaps": [
            {
                "gap": "gap or caveat",
                "impact": "why it matters",
                "source_line_refs": [123],
            }
        ],
        "detection_candidates": [
            {
                "name": "detection or analytic name",
                "status": "historical|proposal|candidate|created|unknown",
                "source_line_refs": [123],
            }
        ],
        "private_observables": [
            {
                "observable_type": "host|user|ip|url|ticket|path|other",
                "guidance": "why it should stay case-bound",
                "source_line_refs": [123],
            }
        ],
    }

    categories = {k: v["name"] for k, v in BASELINE_TAXONOMY.items()}
    system = (
        "You extract knowledge-base and baseline-building guidance from ATHF LOCK "
        "threat-hunt documents. Be precise, conservative, and source-grounded. "
        "Do not invent facts. Prefer behavior-level lessons over exact indicators. "
        "Every item must cite line numbers from the provided excerpt. If evidence is "
        "weak or case-specific, set needs_human_review=true or explain promotion guidance."
    )
    user = (
        "Analyze this LOCK document and return STRICT JSON only.\n\n"
        f"Allowed baseline categories:\n{json_dumps(categories)}\n\n"
        f"Output schema example:\n{json_dumps(schema)}\n\n"
        "Rules:\n"
        "- Focus on what baselines the enterprise should build for future hunts.\n"
        "- Capture post-compromise telemetry patterns, benign context, gaps, and detections.\n"
        "- Do not promote exact users, hosts, IPs, tickets, URLs, or internal paths as universal knowledge.\n"
        "- Use source_line_refs with line numbers visible in the excerpt.\n"
        "- Return JSON only; no Markdown.\n\n"
        f"LOCK document excerpt:\n{excerpt}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def call_azure_apim_chatopenai(
    messages: list[dict[str, str]],
    *,
    base_url: str,
    model: str,
    azure_scope: str,
    timeout: int,
    temperature: float,
) -> dict[str, Any]:
    """Call APIM-shaped chat completions using Azure Identity bearer auth.

    Imports are lazy so deterministic mode stays stdlib-only and usable in
    environments that do not have Azure/LangChain packages installed.
    """

    try:
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise RuntimeError(
            "--llm azure-apim requires azure-identity and langchain-openai. "
            "Install them in the environment running this script."
        ) from exc

    credential = DefaultAzureCredential()
    token_provider = get_bearer_token_provider(
        credential,
        azure_scope,
    )

    kwargs: dict[str, Any] = {
        "model": model,
        "base_url": base_url.rstrip("/"),
        "api_key": token_provider,
        "request_timeout": timeout,
        "max_retries": 0,
    }
    if not model.startswith(("o1", "o3", "gpt-5")):
        kwargs["temperature"] = temperature

    llm = ChatOpenAI(**kwargs).bind(response_format={"type": "json_object"})

    role_map = {"system": "system", "user": "human", "assistant": "ai"}
    lc_messages = [(role_map.get(msg["role"], msg["role"]), msg["content"]) for msg in messages]
    response = llm.invoke(lc_messages)
    content = getattr(response, "content", response)
    if isinstance(content, list):
        text_parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                text_parts.append(part)
            elif isinstance(part, dict) and "text" in part:
                text_parts.append(str(part["text"]))
            else:
                text_parts.append(str(part))
        content = "".join(text_parts)
    return parse_json_response(str(content))


def line_ref_status(doc: LockDocument, refs: Any) -> tuple[str, list[int]]:
    if not isinstance(refs, list):
        return "missing", []
    valid: list[int] = []
    invalid = False
    for ref in refs:
        if isinstance(ref, int):
            line_no = ref
        elif isinstance(ref, str) and ref.isdigit():
            line_no = int(ref)
        else:
            invalid = True
            continue
        if 1 <= line_no <= len(doc.lines):
            valid.append(line_no)
        else:
            invalid = True
    if valid and not invalid:
        return "grounded", valid
    if valid:
        return "partially_grounded", valid
    return "missing", []


def enrich_llm_result(doc: LockDocument, result: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(result)
    for key in (
        "baseline_candidates",
        "behavior_patterns",
        "benign_patterns",
        "telemetry_gaps",
        "detection_candidates",
        "private_observables",
    ):
        items = enriched.get(key)
        if not isinstance(items, list):
            enriched[key] = []
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            status, valid_refs = line_ref_status(doc, item.get("source_line_refs"))
            item["grounding_status"] = status
            item["valid_source_line_refs"] = valid_refs
            item["source_file"] = doc.relpath
            if valid_refs:
                snippets = []
                for line_no in valid_refs[:5]:
                    snippets.append(
                        {
                            "line": line_no,
                            "text": doc.lines[line_no - 1].strip()[:500],
                        }
                    )
                item["source_snippets"] = snippets
            else:
                item["needs_human_review"] = True
    return enriched


def empty_llm_error_result(doc: LockDocument, error: str) -> dict[str, Any]:
    return {
        "source_file": doc.relpath,
        "document_summary": "",
        "baseline_candidates": [],
        "behavior_patterns": [],
        "benign_patterns": [],
        "telemetry_gaps": [],
        "detection_candidates": [],
        "private_observables": [],
        "_llm_error": error,
    }


def llm_analyze_documents(
    args: argparse.Namespace,
    docs: list[LockDocument],
    *,
    logger: RunLogger | None = None,
) -> list[dict[str, Any]]:
    if args.llm == "none":
        return []

    if not args.llm_model:
        raise SystemExit("--llm-model is required when --llm is not 'none'")

    logger = logger or RunLogger()
    results: list[dict[str, Any]] = []
    for i, doc in enumerate(docs, start=1):
        excerpt = build_llm_excerpt(doc, max_chars=args.max_excerpt_chars)
        messages = build_llm_prompt(doc, excerpt)
        doc_started = time.time()
        label = f"LLM {i}/{len(docs)} {doc.relpath}"
        logger.log(
            f"{label} start; model={args.llm_model}; base_url={args.llm_base_url}; "
            f"excerpt_chars={len(excerpt)}"
        )
        attempts: list[dict[str, Any]] = []
        enriched: dict[str, Any] | None = None
        max_attempts = max(1, int(args.llm_max_attempts))
        for attempt in range(1, max_attempts + 1):
            attempt_started = time.time()
            attempt_label = f"{label} attempt {attempt}/{max_attempts}"
            if max_attempts > 1:
                logger.log(f"{attempt_label} start")
            try:
                with Heartbeat(logger, attempt_label, int(args.heartbeat_seconds), attempt_started):
                    result = call_azure_apim_chatopenai(
                        messages,
                        base_url=args.llm_base_url,
                        model=args.llm_model,
                        azure_scope=args.azure_scope,
                        timeout=args.llm_timeout,
                        temperature=args.llm_temperature,
                    )
                enriched = enrich_llm_result(doc, result)
                enriched["_llm_error"] = None
                attempts.append(
                    {
                        "attempt": attempt,
                        "elapsed_seconds": round(time.time() - attempt_started, 3),
                        "error": None,
                    }
                )
                candidate_count = len(enriched.get("baseline_candidates", []) or [])
                logger.log(
                    f"{attempt_label} complete; elapsed={time.time() - attempt_started:.1f}s; "
                    f"baseline_candidates={candidate_count}"
                )
                break
            except Exception as exc:
                error = str(exc)
                attempts.append(
                    {
                        "attempt": attempt,
                        "elapsed_seconds": round(time.time() - attempt_started, 3),
                        "error": error,
                    }
                )
                logger.log(f"{attempt_label} error; elapsed={time.time() - attempt_started:.1f}s; error={error}")
                if attempt < max_attempts:
                    sleep_seconds = max(0, int(args.llm_retry_sleep_seconds))
                    logger.log(f"{attempt_label} retrying after {sleep_seconds}s")
                    if sleep_seconds:
                        time.sleep(sleep_seconds)
                else:
                    enriched = empty_llm_error_result(doc, error)
        assert enriched is not None
        if enriched.get("_llm_error"):
            logger.log(f"{label} failed; elapsed={time.time() - doc_started:.1f}s")
        else:
            logger.log(f"{label} complete; elapsed={time.time() - doc_started:.1f}s")
        enriched["_attempts"] = attempts
        enriched["_source_file"] = doc.relpath
        enriched["_elapsed_seconds"] = round(time.time() - doc_started, 3)
        results.append(enriched)
    return results


def load_prior_llm_results(path: Path | str) -> dict[str, dict[str, Any]]:
    prior_path = Path(path).expanduser().resolve()
    if prior_path.is_dir():
        prior_path = prior_path / "llm_doc_insights.jsonl"
    if not prior_path.exists():
        raise SystemExit(f"Prior LLM results do not exist: {prior_path}")

    rows: dict[str, dict[str, Any]] = {}
    for line_no, line in enumerate(prior_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        source_file = str(row.get("_source_file") or row.get("source_file") or "")
        if not source_file:
            raise SystemExit(f"Prior LLM result missing source file at {prior_path}:{line_no}")
        rows[source_file] = row
    return rows


def docs_for_failed_llm_retry(
    docs: list[LockDocument],
    prior_results: dict[str, dict[str, Any]],
) -> list[LockDocument]:
    retry_docs: list[LockDocument] = []
    for doc in docs:
        prior = prior_results.get(doc.relpath)
        if prior is None or prior.get("_llm_error"):
            retry_docs.append(doc)
    return retry_docs


def merge_llm_results(
    docs: list[LockDocument],
    prior_results: dict[str, dict[str, Any]],
    retry_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    retry_by_file = {
        str(row.get("_source_file") or row.get("source_file") or ""): row
        for row in retry_results
    }
    merged: list[dict[str, Any]] = []
    for doc in docs:
        if doc.relpath in retry_by_file:
            merged.append(retry_by_file[doc.relpath])
        elif doc.relpath in prior_results:
            merged.append(prior_results[doc.relpath])
        else:
            merged.append(empty_llm_error_result(doc, "missing prior and retry LLM result"))
    return merged


def deterministic_baseline_candidates(docs: list[LockDocument]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for doc in docs:
        for category, score in doc.behavior_scores.most_common():
            if score < 3:
                continue
            config = BASELINE_TAXONOMY[category]
            evidence = top_evidence(doc, limit=8)
            rows.append(
                {
                    "source": "deterministic",
                    "source_file": doc.relpath,
                    "work_item": doc.frontmatter.get("work_item", ""),
                    "title": doc.frontmatter.get("title", ""),
                    "category": category,
                    "baseline_name": config["name"],
                    "rationale": (
                        f"Matched {score} category keywords in this LOCK document; "
                        f"primary expected sources: {', '.join(config['primary_sources'])}."
                    ),
                    "telemetry_sources": ";".join(config["primary_sources"]),
                    "score": score,
                    "needs_human_review": "true",
                    "source_refs": ";".join(
                        f"{ev.source_file}:{ev.line_start}" for ev in evidence[:5]
                    ),
                }
            )
    return rows


def flatten_llm_items(llm_results: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in llm_results:
        source_file = result.get("_source_file") or result.get("source_file", "")
        for item in result.get(key, []) or []:
            if not isinstance(item, dict):
                continue
            row = {"source_file": source_file}
            row.update(item)
            row["source_line_refs"] = ";".join(str(x) for x in item.get("valid_source_line_refs", []))
            row["source_snippets"] = " || ".join(
                f"L{s.get('line')}: {s.get('text')}" for s in item.get("source_snippets", [])
            )
            rows.append(row)
    return rows


def aggregate_roadmap(
    docs: list[LockDocument],
    deterministic_rows: list[dict[str, Any]],
    llm_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    category_docs: dict[str, set[str]] = defaultdict(set)
    category_score: Counter[str] = Counter()
    category_sources: dict[str, set[str]] = defaultdict(set)
    llm_support: Counter[str] = Counter()

    for row in deterministic_rows:
        category = row["category"]
        category_docs[category].add(row["source_file"])
        category_score[category] += int(row["score"])
        for source in row["telemetry_sources"].split(";"):
            if source:
                category_sources[category].add(source)

    for item in flatten_llm_items(llm_results, "baseline_candidates"):
        raw_category = str(item.get("category", "")).strip()
        category = raw_category if raw_category in BASELINE_TAXONOMY else slug_category(raw_category)
        if not category:
            continue
        category_docs[category].add(item.get("source_file", ""))
        llm_support[category] += 1
        for source in item.get("telemetry_sources", []) or []:
            category_sources[category].add(str(source))

    rows: list[dict[str, Any]] = []
    all_categories = sorted(set(category_docs) | set(BASELINE_TAXONOMY))
    for category in all_categories:
        if category in BASELINE_TAXONOMY:
            name = BASELINE_TAXONOMY[category]["name"]
        else:
            name = category.replace("_", " ").title()
        docs_count = len(category_docs.get(category, set()))
        deterministic_score = category_score.get(category, 0)
        llm_count = llm_support.get(category, 0)
        priority = docs_count * 10 + min(deterministic_score, 200) + llm_count * 12
        if docs_count == 0 and deterministic_score == 0 and llm_count == 0:
            continue
        rows.append(
            {
                "category": category,
                "baseline_name": name,
                "priority_score": priority,
                "supporting_doc_count": docs_count,
                "deterministic_keyword_score": deterministic_score,
                "llm_candidate_count": llm_count,
                "primary_sources": ";".join(sorted(category_sources.get(category, set()))),
                "supporting_docs": ";".join(sorted(category_docs.get(category, set()))),
            }
        )
    rows.sort(key=lambda row: (-int(row["priority_score"]), row["baseline_name"]))
    return rows


def slug_category(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
        fieldnames = keys or ["empty"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            safe_row = {
                key: json.dumps(value, ensure_ascii=True) if isinstance(value, (list, dict)) else value
                for key, value in row.items()
            }
            writer.writerow(safe_row)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def corpus_inventory_rows(docs: list[LockDocument]) -> list[dict[str, Any]]:
    rows = []
    for doc in docs:
        rows.append(
            {
                "source_file": doc.relpath,
                "work_item": doc.frontmatter.get("work_item", ""),
                "title": doc.frontmatter.get("title", ""),
                "record_type": doc.frontmatter.get("record_type", ""),
                "source_pages": doc.frontmatter.get("source_pages", ""),
                "manifest_sequence": doc.manifest.get("sequence", ""),
                "manifest_doc_id": doc.manifest.get("doc_id", ""),
                "manifest_page_count": doc.manifest.get("page_count", ""),
                "manifest_first_page_index": doc.manifest.get("first_page_index", ""),
                "manifest_last_page_index": doc.manifest.get("last_page_index", ""),
                "manifest_combined_md": doc.manifest.get("combined_md", ""),
                "manifest_source_image_count": len(
                    [x for x in doc.manifest.get("source_images", "").split(";") if x]
                ),
                "conversion_confidence": doc.frontmatter.get("conversion_confidence", ""),
                "needs_human_review": doc.frontmatter.get("needs_human_review", ""),
                "line_count": len(doc.lines),
                "query_block_count": len(doc.query_blocks),
                "sections_present": ";".join(name for name in LOCK_SECTION_NAMES if name in doc.sections),
            }
        )
    return rows


def manifest_join_rows(docs: list[LockDocument]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for doc in docs:
        rows.append(
            {
                "lock_file": doc.relpath,
                "work_item": doc.frontmatter.get("work_item", ""),
                "lock_source_file": doc.frontmatter.get("source_file", ""),
                "lock_source_pages": doc.frontmatter.get("source_pages", ""),
                "manifest_matched": "true" if doc.manifest else "false",
                "manifest_sequence": doc.manifest.get("sequence", ""),
                "manifest_doc_id": doc.manifest.get("doc_id", ""),
                "manifest_title": doc.manifest.get("title", ""),
                "manifest_page_count": doc.manifest.get("page_count", ""),
                "manifest_first_page_index": doc.manifest.get("first_page_index", ""),
                "manifest_last_page_index": doc.manifest.get("last_page_index", ""),
                "manifest_first_capture_key": doc.manifest.get("first_capture_key", ""),
                "manifest_last_capture_key": doc.manifest.get("last_capture_key", ""),
                "manifest_combined_md": doc.manifest.get("combined_md", ""),
                "manifest_source_images": doc.manifest.get("source_images", ""),
                "manifest_source_qwen_md": doc.manifest.get("source_qwen_md", ""),
            }
        )
    return rows


def telemetry_matrix_rows(docs: list[LockDocument]) -> tuple[list[dict[str, Any]], list[str]]:
    keys = sorted({key for doc in docs for key in doc.telemetry_counts})
    fieldnames = ["source_file", "work_item", "title", *keys]
    rows: list[dict[str, Any]] = []
    for doc in docs:
        row = {
            "source_file": doc.relpath,
            "work_item": doc.frontmatter.get("work_item", ""),
            "title": doc.frontmatter.get("title", ""),
        }
        for key in keys:
            row[key] = doc.telemetry_counts.get(key, 0)
        rows.append(row)
    return rows, fieldnames


def behavior_matrix_rows(docs: list[LockDocument]) -> tuple[list[dict[str, Any]], list[str]]:
    keys = list(BASELINE_TAXONOMY)
    fieldnames = ["source_file", "work_item", "title", *keys]
    rows: list[dict[str, Any]] = []
    for doc in docs:
        row = {
            "source_file": doc.relpath,
            "work_item": doc.frontmatter.get("work_item", ""),
            "title": doc.frontmatter.get("title", ""),
        }
        for key in keys:
            row[key] = doc.behavior_scores.get(key, 0)
        rows.append(row)
    return rows, fieldnames


def source_evidence_rows(docs: list[LockDocument]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for doc in docs:
        for ev in doc.evidence:
            rows.append(
                {
                    "source_file": ev.source_file,
                    "line_start": ev.line_start,
                    "line_end": ev.line_end,
                    "section": ev.section,
                    "kind": ev.kind,
                    "value": ev.value,
                    "text": ev.text,
                }
            )
    return rows


def private_observable_rows(docs: list[LockDocument], llm_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for doc in docs:
        seen: set[tuple[str, str, int]] = set()
        for ev in doc.evidence:
            if not ev.kind.startswith("private_"):
                continue
            key = (ev.kind, ev.value, ev.line_start)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "source": "deterministic",
                    "source_file": ev.source_file,
                    "line": ev.line_start,
                    "section": ev.section,
                    "observable_type": ev.kind.replace("private_", ""),
                    "observable": ev.value,
                    "guidance": "Keep case-bound unless reviewed and explicitly promoted.",
                    "source_text": ev.text,
                }
            )
    for item in flatten_llm_items(llm_results, "private_observables"):
        item["source"] = "llm"
        rows.append(item)
    return rows


def markdown_table(rows: list[dict[str, Any]], columns: list[str], limit: int | None = None) -> str:
    selected = rows[:limit] if limit else rows
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    for row in selected:
        values = []
        for col in columns:
            value = str(row.get(col, ""))
            value = value.replace("|", "\\|").replace("\n", " ")
            values.append(value)
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def write_roadmap_markdown(path: Path, roadmap: list[dict[str, Any]], docs: list[LockDocument]) -> None:
    lines = [
        "# LOCK KB Baseline Roadmap",
        "",
        "This report ranks baseline needs extracted from LOCK Markdown documents.",
        "Scores combine deterministic keyword/telemetry evidence and optional LLM-supported candidates.",
        "",
        f"- LOCK documents analyzed: `{len(docs)}`",
        f"- Generated at: `{time.strftime('%Y-%m-%d %H:%M:%S %z')}`",
        "",
        "## Ranked Baselines",
        "",
        markdown_table(
            roadmap,
            [
                "priority_score",
                "baseline_name",
                "supporting_doc_count",
                "llm_candidate_count",
                "primary_sources",
            ],
        ),
        "",
        "## Baseline Guidance",
        "",
    ]
    for row in roadmap:
        lines.extend(
            [
                f"### {row['baseline_name']}",
                "",
                f"- Category: `{row['category']}`",
                f"- Priority score: `{row['priority_score']}`",
                f"- Supporting docs: `{row['supporting_doc_count']}`",
                f"- Primary sources: `{row['primary_sources'] or 'needs review'}`",
                f"- Source docs: `{row['supporting_docs']}`",
                "",
                "Recommended KB entry shape:",
                "",
                "```markdown",
                "- Behavior:",
                "- Normal context:",
                "- Suspicious only when:",
                "- Primary tables/indexes:",
                "- Useful fields:",
                "- Starter query or aggregate:",
                "- Known gaps:",
                "- Source LOCK docs:",
                "- Review status:",
                "```",
                "",
            ]
        )
    write_text(path, "\n".join(lines).rstrip() + "\n")


def write_kb_candidates_markdown(
    path: Path,
    deterministic_rows: list[dict[str, Any]],
    llm_results: list[dict[str, Any]],
) -> None:
    lines = [
        "# KB Promotion Candidates",
        "",
        "These are candidate lessons and baseline entries. They are not approved KB content.",
        "",
        "## LLM Baseline Candidates",
        "",
    ]
    llm_rows = flatten_llm_items(llm_results, "baseline_candidates")
    if llm_rows:
        for item in llm_rows:
            lines.extend(
                [
                    f"### {item.get('name') or item.get('category') or 'Unnamed Candidate'}",
                    "",
                    f"- Source: `{item.get('source_file', '')}`",
                    f"- Category: `{item.get('category', '')}`",
                    f"- Grounding: `{item.get('grounding_status', '')}`",
                    f"- Confidence: `{item.get('confidence', '')}`",
                    f"- Needs review: `{item.get('needs_human_review', True)}`",
                    f"- Rationale: {item.get('rationale', '')}",
                    f"- Normal context: {item.get('normal_context', '')}",
                    f"- Suspicious when: {item.get('suspicious_when', '')}",
                    f"- Telemetry sources: `{item.get('telemetry_sources', '')}`",
                    f"- Source refs: `{item.get('source_line_refs', '')}`",
                    "",
                ]
            )
    else:
        lines.append("No LLM candidates were generated. Run with `--llm azure-apim` to enable this section.")
        lines.append("")

    lines.extend(["## Deterministic Baseline Candidates", ""])
    for row in deterministic_rows[:200]:
        lines.extend(
            [
                f"### {row['baseline_name']}",
                "",
                f"- Source: `{row['source_file']}`",
                f"- Category: `{row['category']}`",
                f"- Score: `{row['score']}`",
                f"- Rationale: {row['rationale']}",
                f"- Source refs: `{row['source_refs']}`",
                "",
            ]
        )
    write_text(path, "\n".join(lines).rstrip() + "\n")


OPERATOR_CATEGORY_GUIDANCE: dict[str, dict[str, str]] = {
    "process_lineage": {
        "first_action": "Map process telemetry, then aggregate parent -> child -> command shape by host, user, and peer group.",
        "starter": (
            "Build a 60-90 day table grouped by parent process, child process, normalized command line, "
            "host count, user count, first seen, last seen, daily p50, and daily p95. Review rare or first-seen combinations."
        ),
        "fields": "Timestamp;DeviceName;AccountName;InitiatingProcessFileName;InitiatingProcessCommandLine;FileName;ProcessCommandLine;FolderPath;SHA256;Signer",
    },
    "network_egress": {
        "first_action": "Map endpoint, proxy, DNS, and firewall egress sources, then preserve process context wherever possible.",
        "starter": (
            "Build a 60-90 day aggregate by process, parent process, destination domain, remote IP, URL category, "
            "host count, user count, bytes out, connection count, first seen, and last seen. Review new process-to-domain pairs."
        ),
        "fields": "Timestamp;DeviceName;AccountName;InitiatingProcessFileName;InitiatingProcessCommandLine;RemoteUrl;RemoteIP;RemotePort;Action;BytesOut",
    },
    "file_staging": {
        "first_action": "Map file creation and modification telemetry for temp, cache, public, downloads, package-cache, and user-writable paths.",
        "starter": (
            "Build a 60-90 day aggregate by folder pattern, file extension, initiating process, signer, hash prevalence, "
            "host count, user count, first seen, and execution follow-on within 15 minutes."
        ),
        "fields": "Timestamp;DeviceName;AccountName;FolderPath;FileName;SHA256;ActionType;InitiatingProcessFileName;InitiatingProcessCommandLine",
    },
    "vulnerability_exposure": {
        "first_action": "Map software inventory, vulnerability scanner, CMDB, and external exposure sources before writing hunt logic.",
        "starter": (
            "Build an asset-product-CVE table with product version, vulnerable version, internet exposure, owner, business criticality, "
            "last seen, patch status, and whether exploit telemetry exists."
        ),
        "fields": "DeviceName;ProductName;ProductVersion;CVE;Severity;InternetExposure;AssetOwner;BusinessUnit;LastSeen;PatchStatus",
    },
    "identity_admin": {
        "first_action": "Map sign-in, admin audit, remote access, service account, and privileged session logs.",
        "starter": (
            "Build aggregates for admin actions, remote logons, service-account use, authentication failures, new device/user combinations, "
            "and rare privilege paths by peer group."
        ),
        "fields": "Timestamp;AccountName;DeviceName;LogonType;IPAddress;UserAgent;AppDisplayName;Operation;Result;Role;PrivilegedFlag",
    },
    "developer_package_tooling": {
        "first_action": "Inventory developer hosts, build systems, package managers, CI runners, approved repositories, and package caches.",
        "starter": (
            "Build aggregates for package manager parent/child processes, install-time network egress, cache writes, package names, "
            "repository context, host role, and user role."
        ),
        "fields": "Timestamp;DeviceName;AccountName;HostRole;PackageManager;InitiatingProcessCommandLine;ProcessCommandLine;RemoteUrl;FolderPath;PackageName",
    },
    "messaging_exfil": {
        "first_action": "Map messaging/collaboration domains and clients, then compare browser/client traffic against scripted or rare process traffic.",
        "starter": (
            "Build aggregates by messaging service, process, user, host, domain, connection cadence, bytes out, and approved business context. "
            "Review non-browser or periodic traffic first."
        ),
        "fields": "Timestamp;DeviceName;AccountName;InitiatingProcessFileName;RemoteUrl;RemoteIP;ConnectionCount;BytesOut;Tenant;Geo",
    },
    "cloud_saas_audit": {
        "first_action": "Map SaaS audit, cloud app, source-control, service-principal, and tenant activity logs.",
        "starter": (
            "Build aggregates by user, app, tenant, repo/resource, operation, IP, user agent, first seen, last seen, and peer group. "
            "Review new app/resource combinations and unusual external tenants."
        ),
        "fields": "Timestamp;UserId;AppDisplayName;Operation;ResourceId;Repository;IPAddress;UserAgent;TenantId;ResultStatus",
    },
}


def list_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    if ";" in text:
        return [part.strip() for part in text.split(";") if part.strip()]
    return [text]


def compact_join(values: list[str], *, limit: int = 8) -> str:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = value.strip()
        if not value or value.lower() in seen:
            continue
        deduped.append(value)
        seen.add(value.lower())
    if len(deduped) > limit:
        return "; ".join(deduped[:limit]) + f"; and {len(deduped) - limit} more"
    return "; ".join(deduped)


def llm_baseline_candidates_by_category(llm_results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in flatten_llm_items(llm_results, "baseline_candidates"):
        raw_category = str(item.get("category", "")).strip()
        category = raw_category if raw_category in BASELINE_TAXONOMY else slug_category(raw_category)
        if category:
            by_category[category].append(item)

    def rank(item: dict[str, Any]) -> tuple[int, int, int]:
        confidence_rank = {"high": 0, "medium": 1, "low": 2}
        grounding_rank = {"grounded": 0, "partially_grounded": 1, "missing": 2}
        return (
            1 if item.get("needs_human_review") else 0,
            confidence_rank.get(str(item.get("confidence", "")).lower(), 3),
            grounding_rank.get(str(item.get("grounding_status", "")).lower(), 3),
        )

    for items in by_category.values():
        items.sort(key=rank)
    return by_category


def category_guidance(category: str) -> dict[str, str]:
    if category in OPERATOR_CATEGORY_GUIDANCE:
        return OPERATOR_CATEGORY_GUIDANCE[category]
    taxonomy = BASELINE_TAXONOMY.get(category, {})
    return {
        "first_action": "Map the required telemetry, build 60-90 day aggregates, then review rare and first-seen behavior before promotion.",
        "starter": "Build a 60-90 day aggregate with counts, distinct hosts, distinct users, first seen, last seen, peer group, and sample evidence.",
        "fields": ";".join(taxonomy.get("primary_sources", [])) or "Timestamp;Host;User;Action;Source;Destination;CommandLine",
    }


def kb_example_lines(row: dict[str, Any], candidate: dict[str, Any] | None, index: int) -> list[str]:
    category = str(row.get("category", ""))
    guidance = category_guidance(category)
    taxonomy = BASELINE_TAXONOMY.get(category, {})
    name = (
        str(candidate.get("name")) if candidate and candidate.get("name") else str(row.get("baseline_name", "Baseline"))
    )
    behavior = (
        str(candidate.get("rationale"))
        if candidate and candidate.get("rationale")
        else f"Baseline {row.get('baseline_name', 'this behavior family')} across the environment before creating detections."
    )
    normal_context = (
        str(candidate.get("normal_context"))
        if candidate and candidate.get("normal_context")
        else "To be determined from CORP 60-90 day baseline, host roles, user roles, and approved business workflows."
    )
    suspicious_when = (
        str(candidate.get("suspicious_when"))
        if candidate and candidate.get("suspicious_when")
        else "Rare, first-seen, high-volume, or peer-group-inconsistent behavior appears with corroborating process, file, network, or identity evidence."
    )
    telemetry_sources = list_value(candidate.get("telemetry_sources") if candidate else None)
    if not telemetry_sources:
        telemetry_sources = list_value(row.get("primary_sources")) or list(taxonomy.get("primary_sources", []))
    useful_fields = list_value(candidate.get("useful_fields") if candidate else None)
    if not useful_fields:
        useful_fields = list_value(guidance["fields"])
    source_docs = list_value(row.get("supporting_docs"))
    if candidate and candidate.get("source_file"):
        source_docs = [str(candidate.get("source_file"))]
    source_refs = list_value(candidate.get("source_line_refs") if candidate else None)
    known_gap = "Validate table names, field names, retention, and process/network correlation in CORP before using this as detection logic."

    return [
        f"### KB Draft {index}: {name}",
        "",
        f"- Behavior: {behavior}",
        f"- Normal context: {normal_context}",
        f"- Suspicious only when: {suspicious_when}",
        f"- Primary tables/indexes: {compact_join(telemetry_sources) or 'Map CORP telemetry sources first.'}",
        f"- Useful fields: {compact_join(useful_fields, limit=12) or 'Map CORP fields first.'}",
        f"- Starter query or aggregate: {guidance['starter']}",
        f"- Known gaps: {known_gap}",
        f"- Source LOCK docs: {compact_join(source_docs, limit=5) or 'Needs source review.'}",
        f"- Source refs: {compact_join(source_refs, limit=12) if source_refs else 'See source LOCK docs.'}",
        "- Review status: Draft. Do not promote until CORP data confirms normal context and analyst review labels top anomalies.",
        "",
    ]


def write_start_here_markdown(
    path: Path,
    summary: dict[str, Any],
    roadmap: list[dict[str, Any]],
    llm_results: list[dict[str, Any]],
    docs: list[LockDocument],
) -> None:
    errors = [row for row in llm_results if row.get("_llm_error")]
    candidate_by_category = llm_baseline_candidates_by_category(llm_results)
    top_rows = roadmap[:8]
    lines = [
        "# LOCK KB Operator Action Plan",
        "",
        "This is the only file you should read first.",
        "",
        "The other outputs are supporting evidence, CSV exports, and debug/audit artifacts. "
        "Use this report to decide what to do next in CORP.",
        "",
        "## Bottom Line",
        "",
        "Do not start with detections. Start by building reusable environment baselines, then promote reviewed baseline lessons into KB entries.",
        "",
        f"- LOCK documents analyzed: `{summary.get('doc_count', len(docs))}`",
        f"- LLM mode: `{summary.get('llm_mode', '')}`",
        f"- LLM results: `{summary.get('llm_result_count', len(llm_results))}`",
        f"- LLM errors: `{len(errors)}`",
        f"- Baseline candidates: `{summary.get('baseline_candidate_count', '')}`",
        f"- Generated at: `{time.strftime('%Y-%m-%d %H:%M:%S %z')}`",
        "",
        "## What To Do Next",
        "",
        "1. Pick the first baseline family from the build order below.",
        "2. Map the real CORP tables, indexes, field names, owners, and retention for that family.",
        "3. Pull 60-90 days of historical telemetry for bootstrap baselining.",
        "4. Normalize entity fields: timestamp, host, user, parent process, child process, command line, path, destination, and action.",
        "5. Compute counts, distinct hosts, distinct users, first seen, last seen, daily p50, daily p95, and peer-group prevalence.",
        "6. Review rare, first-seen, and peer-group-inconsistent rows with an analyst.",
        "7. Label reviewed rows as approved normal, suspicious pattern, needs more data, or not useful.",
        "8. Promote only reviewed lessons into KB entries using the examples below.",
        "9. Convert high-confidence KB entries into hunts or detections only after false-positive review.",
        "10. Refresh aggregates weekly and rebaseline quarterly, or after major telemetry/platform changes.",
        "",
        "## Baseline Build Order",
        "",
        markdown_table(
            [
                {
                    "rank": i,
                    "baseline": row.get("baseline_name", ""),
                    "docs": row.get("supporting_doc_count", ""),
                    "llm": row.get("llm_candidate_count", ""),
                    "first_action": category_guidance(str(row.get("category", "")))["first_action"],
                }
                for i, row in enumerate(top_rows, start=1)
            ],
            ["rank", "baseline", "docs", "llm", "first_action"],
        ),
        "",
        "## Statistical Process",
        "",
        "- Bootstrap window: 60-90 days for initial normal context.",
        "- Refresh: daily or weekly incremental aggregates.",
        "- Rebaseline: quarterly rolling 90 or 180 day rebuild.",
        "- Peer groups: compare hosts and users by role, business unit, platform, and workload instead of one global baseline.",
        "- Rarity: track global prevalence, peer-group prevalence, host/user first seen, and new parent-child or process-destination pairs.",
        "- Robust thresholds: use median, p95/p99, IQR, and MAD before simple standard deviation.",
        "- Sequence review: correlate process -> file -> network -> identity events in 5, 15, and 60 minute windows.",
        "- Cadence review: use inter-arrival time and coefficient of variation for beacon-like or automated behavior.",
        "- Promotion metric: review top anomalies and record analyst labels before turning anything into production detection logic.",
        "",
        "## KB Entry Examples",
        "",
        "These are draft KB shapes generated from the current run. They are not approved until CORP data validates them.",
        "",
    ]

    for i, row in enumerate(top_rows[:5], start=1):
        category = str(row.get("category", ""))
        candidate = candidate_by_category.get(category, [None])[0]
        lines.extend(kb_example_lines(row, candidate, i))

    lines.extend(
        [
            "## How To Use The Other Files",
            "",
            "- `START_HERE.md`: primary operator report. Read this first.",
            "- `baseline_roadmap.md`: ranked baseline families and supporting docs.",
            "- `kb_promotion_candidates.md`: raw candidate KB lessons; useful after you pick a baseline family.",
            "- `baseline_candidates.csv`: structured backlog for tracking and importing into another system.",
            "- `telemetry_matrix.csv`: telemetry/table hints by source document.",
            "- `telemetry_gaps.csv`: known data limitations to discuss with platform/data owners.",
            "- `detection_candidates.csv`: possible hunt/detection ideas; do not implement before baselining.",
            "- `llm_doc_insights.jsonl`, `source_evidence.jsonl`, `run_summary.json`, `lock_kb_insights.log`: debug/audit artifact set.",
            "",
            "## CORP Run Reminder",
            "",
            "After the 63-document CORP run finishes, open only this file first:",
            "",
            "```bash",
            "open \"$OUTPUT_DIR/START_HERE.md\"",
            "```",
            "",
            "If any LLM documents fail, rerun with `--retry-failed-from <prior-output-dir>` and then read the new `START_HERE.md`.",
        ]
    )
    write_text(path, "\n".join(lines).rstrip() + "\n")


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    input_dir = Path(args.input_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = Path(args.log_file).expanduser().resolve() if args.log_file else output_dir / "lock_kb_insights.log"
    logger = RunLogger(log_file)
    logger.log("Starting LOCK KB insight extraction")
    logger.log(f"Input dir: {input_dir}")
    logger.log(f"Output dir: {output_dir}")
    logger.log(f"LLM mode: {args.llm}")
    if args.llm != "none":
        logger.log(
            f"LLM config: base_url={args.llm_base_url}; model={args.llm_model}; "
            f"timeout={args.llm_timeout}s; heartbeat={args.heartbeat_seconds}s; "
            f"max_attempts={args.llm_max_attempts}"
        )
    if args.retry_failed_from:
        logger.log(f"Retry failed from: {args.retry_failed_from}")
    if not input_dir.exists():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    manifest_path = Path(args.grouped_manifest).expanduser().resolve() if args.grouped_manifest else None
    manifest_index = load_grouped_manifest(manifest_path)
    if manifest_path:
        logger.log(f"Grouped manifest: {manifest_path}")
    docs = read_lock_documents(input_dir, manifest_index)
    if not docs:
        raise SystemExit(f"No Markdown files found in {input_dir}")
    logger.log(f"Loaded {len(docs)} LOCK documents")

    logger.log("Starting deterministic extraction")
    for doc in docs:
        deterministic_extract(doc)
    logger.log("Deterministic extraction complete")

    if args.retry_failed_from:
        if args.llm == "none":
            raise SystemExit("--retry-failed-from requires --llm azure-apim")
        prior_results = load_prior_llm_results(args.retry_failed_from)
        retry_docs = docs_for_failed_llm_retry(docs, prior_results)
        logger.log(
            f"Loaded {len(prior_results)} prior LLM results; "
            f"retrying {len(retry_docs)} failed/missing documents"
        )
        retry_results = llm_analyze_documents(args, retry_docs, logger=logger)
        llm_results = merge_llm_results(docs, prior_results, retry_results)
    else:
        llm_results = llm_analyze_documents(args, docs, logger=logger)
    if args.llm != "none":
        errors = [row for row in llm_results if row.get("_llm_error")]
        logger.log(f"LLM extraction complete; results={len(llm_results)}; errors={len(errors)}")
    deterministic_rows = deterministic_baseline_candidates(docs)
    roadmap = aggregate_roadmap(docs, deterministic_rows, llm_results)
    logger.log(
        f"Aggregation complete; baseline_candidates="
        f"{len(deterministic_rows) + len(flatten_llm_items(llm_results, 'baseline_candidates'))}; "
        f"roadmap_items={len(roadmap)}"
    )

    write_csv(output_dir / "corpus_inventory.csv", corpus_inventory_rows(docs))
    write_csv(output_dir / "source_manifest_join.csv", manifest_join_rows(docs))
    telemetry_rows, telemetry_fields = telemetry_matrix_rows(docs)
    write_csv(output_dir / "telemetry_matrix.csv", telemetry_rows, telemetry_fields)
    behavior_rows, behavior_fields = behavior_matrix_rows(docs)
    write_csv(output_dir / "behavior_matrix.csv", behavior_rows, behavior_fields)
    write_csv(output_dir / "baseline_candidates.csv", deterministic_rows + flatten_llm_items(llm_results, "baseline_candidates"))
    write_csv(output_dir / "detection_candidates.csv", flatten_llm_items(llm_results, "detection_candidates"))
    write_csv(output_dir / "telemetry_gaps.csv", flatten_llm_items(llm_results, "telemetry_gaps"))
    write_csv(output_dir / "private_observables.csv", private_observable_rows(docs, llm_results))
    write_csv(output_dir / "baseline_roadmap.csv", roadmap)
    write_jsonl(output_dir / "source_evidence.jsonl", source_evidence_rows(docs))
    write_jsonl(output_dir / "llm_doc_insights.jsonl", llm_results)
    write_roadmap_markdown(output_dir / "baseline_roadmap.md", roadmap, docs)
    write_kb_candidates_markdown(output_dir / "kb_promotion_candidates.md", deterministic_rows, llm_results)

    summary = {
        "input_dir": str(input_dir),
        "grouped_manifest": str(manifest_path) if manifest_path else "",
        "output_dir": str(output_dir),
        "env_file": args.env_file,
        "log_file": str(log_file),
        "primary_output": "START_HERE.md",
        "doc_count": len(docs),
        "llm_mode": args.llm,
        "llm_result_count": len(llm_results),
        "baseline_candidate_count": len(deterministic_rows) + len(flatten_llm_items(llm_results, "baseline_candidates")),
        "roadmap_count": len(roadmap),
        "top_roadmap": roadmap[:10],
        "outputs": [
            "START_HERE.md",
            "corpus_inventory.csv",
            "source_manifest_join.csv",
            "telemetry_matrix.csv",
            "behavior_matrix.csv",
            "baseline_candidates.csv",
            "baseline_roadmap.csv",
            "baseline_roadmap.md",
            "kb_promotion_candidates.md",
            "source_evidence.jsonl",
            "llm_doc_insights.jsonl",
            "detection_candidates.csv",
            "telemetry_gaps.csv",
            "private_observables.csv",
            "run_summary.json",
            "lock_kb_insights.log",
        ],
    }
    write_start_here_markdown(output_dir / "START_HERE.md", summary, roadmap, llm_results, docs)
    write_text(output_dir / "run_summary.json", json_dumps(summary) + "\n")
    logger.log(f"Wrote outputs to: {output_dir}")
    logger.log(f"Primary operator report: {output_dir / 'START_HERE.md'}")
    logger.log("LOCK KB insight extraction finished")
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    loaded_env_file = _load_env_for_args(argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        default=loaded_env_file,
        help=(
            "Optional env file with LOCK_KB_* settings. Defaults to "
            "LOCK_KB_ENV_FILE or lock-kb-insights.env next to this script when present."
        ),
    )
    parser.add_argument("--input-dir", required=True, help="Directory containing LOCK Markdown files.")
    parser.add_argument(
        "--grouped-manifest",
        help=(
            "Optional grouped/manifest.csv from md_to_lock.py input. "
            "Adds original grouped document, page range, image, and OCR provenance."
        ),
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write analysis outputs.")
    parser.add_argument(
        "--llm",
        choices=["none", "azure-apim"],
        default=os.environ.get("LOCK_KB_LLM_MODE", "none"),
        help="LLM mode. Default is deterministic-only. Env: LOCK_KB_LLM_MODE.",
    )
    parser.add_argument(
        "--llm-base-url",
        default=os.environ.get("LOCK_KB_LLM_BASE_URL", "http://127.0.0.1:8080"),
        help=(
            "APIM-shaped ChatOpenAI base URL, without /chat/completions. "
            "Use a local apim-mimic URL for local testing or the CORP APIM /v1 URL in corp. "
            "Env: LOCK_KB_LLM_BASE_URL."
        ),
    )
    parser.add_argument(
        "--llm-model",
        default=os.environ.get("LOCK_KB_LLM_MODEL", "gpt-5.4"),
        help="Resolved deployment/model name. Defaults to gpt-5.4. Env: LOCK_KB_LLM_MODEL.",
    )
    parser.add_argument(
        "--azure-scope",
        default=os.environ.get("LOCK_KB_AZURE_SCOPE", "https://ai.azure.com/.default"),
        help="Azure bearer token scope used by DefaultAzureCredential. Env: LOCK_KB_AZURE_SCOPE.",
    )
    parser.add_argument(
        "--llm-timeout",
        type=int,
        default=_env_int("LOCK_KB_LLM_TIMEOUT", 120),
        help="LLM request timeout in seconds. Env: LOCK_KB_LLM_TIMEOUT.",
    )
    parser.add_argument(
        "--llm-temperature",
        type=float,
        default=_env_float("LOCK_KB_LLM_TEMPERATURE", 0.1),
        help="LLM temperature for non-gpt-5/o-series models. Env: LOCK_KB_LLM_TEMPERATURE.",
    )
    parser.add_argument(
        "--max-excerpt-chars",
        type=int,
        default=_env_int("LOCK_KB_MAX_EXCERPT_CHARS", 18000),
        help="Maximum characters sent to the LLM per document. Env: LOCK_KB_MAX_EXCERPT_CHARS.",
    )
    parser.add_argument(
        "--log-file",
        default=os.environ.get("LOCK_KB_LOG_FILE", ""),
        help=(
            "Path for mirrored run logs. Defaults to lock_kb_insights.log in output dir. "
            "Env: LOCK_KB_LOG_FILE."
        ),
    )
    parser.add_argument(
        "--heartbeat-seconds",
        type=int,
        default=_env_int("LOCK_KB_HEARTBEAT_SECONDS", 30),
        help="Seconds between in-flight LLM heartbeat log lines. Set 0 to disable. Env: LOCK_KB_HEARTBEAT_SECONDS.",
    )
    parser.add_argument(
        "--llm-max-attempts",
        type=int,
        default=_env_int("LOCK_KB_LLM_MAX_ATTEMPTS", 2),
        help="Maximum attempts per LLM document before recording an error. Env: LOCK_KB_LLM_MAX_ATTEMPTS.",
    )
    parser.add_argument(
        "--llm-retry-sleep-seconds",
        type=int,
        default=_env_int("LOCK_KB_LLM_RETRY_SLEEP_SECONDS", 5),
        help="Seconds to sleep between per-document LLM attempts. Env: LOCK_KB_LLM_RETRY_SLEEP_SECONDS.",
    )
    parser.add_argument(
        "--retry-failed-from",
        default=os.environ.get("LOCK_KB_RETRY_FAILED_FROM", ""),
        help=(
            "Prior output directory or llm_doc_insights.jsonl. Reuses successful rows "
            "and reruns only failed or missing documents. Env: LOCK_KB_RETRY_FAILED_FROM."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = analyze(args)
    print(f"Analyzed {summary['doc_count']} LOCK documents.")
    print(f"Wrote outputs to: {summary['output_dir']}")
    print(f"Primary report: {Path(summary['output_dir']) / summary['primary_output']}")
    print("Top baseline roadmap:")
    for row in summary["top_roadmap"][:8]:
        print(
            f"  - {row['baseline_name']} "
            f"(score={row['priority_score']}, docs={row['supporting_doc_count']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
