#!/usr/bin/env python
"""Compress, encrypt, base64-encode, and embed Markdown file(s) in YARA."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from md_yara_codec import DEFAULT_CHUNK_SIZE, DEFAULT_ITERATIONS, markdown_to_yara_text, normalize_rule_name


def prompt_new_password() -> str:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise ValueError("Passwords do not match")
    if not password:
        raise ValueError("Password cannot be empty")
    return password


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("markdown_input", help="Input .md file or directory of .md files to package.")
    parser.add_argument("yara_file", help="Output YARA file to write.")
    parser.add_argument(
        "--rule-name",
        default="",
        help="YARA rule name. Defaults to a sanitized name derived from the input path.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Base64 characters per YARA string. Default: {DEFAULT_CHUNK_SIZE}.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iterations. Default: {DEFAULT_ITERATIONS}.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output YARA file if it already exists.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source = Path(args.markdown_input).expanduser().resolve()
    destination = Path(args.yara_file).expanduser().resolve()
    if destination.exists() and not args.force:
        print(f"Refusing to overwrite existing file: {destination}", file=sys.stderr)
        return 2

    try:
        password = prompt_new_password()
        rule_name = args.rule_name or normalize_rule_name(source.stem)
        yara_text = markdown_to_yara_text(
            source,
            password=password,
            rule_name=rule_name,
            chunk_size=args.chunk_size,
            iterations=args.iterations,
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(yara_text, encoding="utf-8")
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote encrypted YARA payload: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
