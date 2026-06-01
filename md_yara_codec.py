from __future__ import annotations

import base64
import io
import json
import re
import secrets
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PAYLOAD_FORMAT = "md-yara-v1"
AAD = b"md-yara-v1"
DEFAULT_CHUNK_SIZE = 3800
MIN_ITERATIONS = 100_000
DEFAULT_ITERATIONS = 600_000


def normalize_rule_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", value.strip())
    value = re.sub(r"_+", "_", value).strip("_")
    if not value:
        value = "markdown_payload"
    if not re.match(r"[A-Za-z_]", value):
        value = f"payload_{value}"
    return value


def _yara_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _zip_info(arcname: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    return info


def zip_markdown_input(input_path: Path) -> bytes:
    if input_path.is_file():
        if input_path.suffix.lower() != ".md":
            raise ValueError(f"Expected a .md file, got: {input_path}")
        entries = [(input_path.name, input_path)]
    elif input_path.is_dir():
        entries = []
        for candidate in sorted(input_path.rglob("*")):
            if candidate.is_symlink() or not candidate.is_file() or candidate.suffix.lower() != ".md":
                continue
            arcname = candidate.relative_to(input_path).as_posix()
            safe_zip_member_path(arcname)
            entries.append((arcname, candidate))
        if not entries:
            raise ValueError(f"No Markdown files found under directory: {input_path}")
    else:
        raise FileNotFoundError(f"Markdown input does not exist: {input_path}")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for arcname, path in entries:
            archive.writestr(_zip_info(arcname), path.read_bytes())
    return buffer.getvalue()


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if iterations < MIN_ITERATIONS:
        raise ValueError(f"PBKDF2 iterations must be at least {MIN_ITERATIONS}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_zip(zip_bytes: bytes, *, password: str, iterations: int) -> dict[str, Any]:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt, iterations)
    ciphertext = AESGCM(key).encrypt(nonce, zip_bytes, AAD)
    return {
        "ciphertext": ciphertext,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
    }


def decrypt_zip(
    ciphertext: bytes,
    *,
    password: str,
    salt_b64: str,
    nonce_b64: str,
    iterations: int,
) -> bytes:
    salt = base64.b64decode(salt_b64, validate=True)
    nonce = base64.b64decode(nonce_b64, validate=True)
    key = derive_key(password, salt, iterations)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as exc:
        raise ValueError("Unable to decrypt payload; password, iterations, or YARA metadata may be wrong") from exc


def chunk_text(text: str, chunk_size: int) -> list[str]:
    if chunk_size < 32:
        raise ValueError("chunk_size must be at least 32")
    return [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)] or [""]


def markdown_to_yara_text(
    markdown_path: Path | str,
    *,
    password: str,
    rule_name: str,
    chunk_size: int,
    iterations: int,
) -> str:
    source = Path(markdown_path).expanduser().resolve()
    rule = normalize_rule_name(rule_name or source.stem)
    zip_bytes = zip_markdown_input(source)
    encrypted = encrypt_zip(zip_bytes, password=password, iterations=iterations)
    ciphertext = encrypted["ciphertext"]
    payload_b64 = base64.b64encode(ciphertext).decode("ascii")
    chunks = chunk_text(payload_b64, chunk_size)

    lines = [
        f"rule {rule}",
        "{",
        "  meta:",
        f"    salt_b64 = {_yara_quote(encrypted['salt_b64'])}",
        f"    nonce_b64 = {_yara_quote(encrypted['nonce_b64'])}",
    ]

    lines.extend(["  strings:"])
    for index, chunk in enumerate(chunks):
        lines.append(f"    $payload_{index:04d} = {_yara_quote(chunk)}")

    lines.extend(
        [
            "  condition:",
            "    all of ($payload_*)",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _unquote_yara_string(value: str) -> str:
    return json.loads(value)


def parse_yara_payload(yara_text: str) -> tuple[dict[str, Any], str]:
    meta: dict[str, Any] = {}
    meta_re = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"(?:\\.|[^\"])*\"|\d+|true|false)\s*$")
    payload_re = re.compile(r"^\s*\$payload_(\d{4,})\s*=\s*(\"(?:\\.|[^\"])*\")\s*$")
    chunks: dict[int, str] = {}

    for line in yara_text.splitlines():
        meta_match = meta_re.match(line)
        if meta_match:
            key, raw_value = meta_match.groups()
            if raw_value.startswith('"'):
                meta[key] = _unquote_yara_string(raw_value)
            elif raw_value in {"true", "false"}:
                meta[key] = raw_value == "true"
            else:
                meta[key] = int(raw_value)
            continue

        payload_match = payload_re.match(line)
        if payload_match:
            index = int(payload_match.group(1))
            chunks[index] = _unquote_yara_string(payload_match.group(2))

    if "salt_b64" not in meta or "nonce_b64" not in meta:
        raise ValueError("YARA metadata must include salt_b64 and nonce_b64")
    if not chunks:
        raise ValueError("YARA file does not contain payload chunks")
    ordered_indexes = sorted(chunks)
    if ordered_indexes != list(range(ordered_indexes[-1] + 1)):
        raise ValueError("YARA payload chunks are missing or out of sequence")

    return meta, "".join(chunks[index] for index in ordered_indexes)


def safe_zip_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.name:
        raise ValueError(f"Unsafe zip member path: {name}")
    for part in path.parts:
        if part in {"", ".", ".."}:
            raise ValueError(f"Unsafe zip member path: {name}")
    return path


def markdown_entries_from_zip_bytes(zip_bytes: bytes) -> list[tuple[PurePosixPath, bytes]]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        if not names:
            raise ValueError("Expected encrypted zip to contain at least one Markdown file")
        entries: list[tuple[PurePosixPath, bytes]] = []
        for name in sorted(names):
            member_path = safe_zip_member_path(name)
            if member_path.suffix.lower() != ".md":
                raise ValueError(f"Encrypted zip member is not a Markdown file: {name}")
            entries.append((member_path, archive.read(name)))
        return entries


def yara_file_to_markdown(
    yara_path: Path | str,
    output_path: Path | str,
    *,
    password: str,
    iterations: int = DEFAULT_ITERATIONS,
    overwrite: bool = False,
) -> Path:
    source = Path(yara_path).expanduser().resolve()
    destination = Path(output_path).expanduser().resolve()
    meta, payload_b64 = parse_yara_payload(source.read_text(encoding="utf-8"))
    ciphertext = base64.b64decode(payload_b64, validate=True)
    zip_bytes = decrypt_zip(
        ciphertext,
        password=password,
        salt_b64=str(meta["salt_b64"]),
        nonce_b64=str(meta["nonce_b64"]),
        iterations=iterations,
    )
    entries = markdown_entries_from_zip_bytes(zip_bytes)
    if len(entries) == 1 and destination.suffix.lower() == ".md":
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing Markdown file: {destination}")
        destination.write_bytes(entries[0][1])
        return destination

    if destination.suffix.lower() == ".md":
        raise ValueError("Folder payloads must be recovered to an output directory, not a .md file")

    for member_path, markdown_bytes in entries:
        target = destination.joinpath(*member_path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing Markdown file: {target}")
        target.write_bytes(markdown_bytes)
    return destination
