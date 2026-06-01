#!/usr/bin/env python
"""Recover a Markdown file from an encrypted base64 payload embedded in YARA."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from md_yara_codec import DEFAULT_ITERATIONS, yara_file_to_markdown


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("yara_file", help="Input YARA file containing an md-yara-v1 payload.")
    parser.add_argument(
        "output",
        help=(
            "Output .md path for a single-file payload, or output directory for "
            "a folder/multi-file payload."
        ),
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=(
            "PBKDF2 iterations used when the YARA was created. "
            f"Default: {DEFAULT_ITERATIONS}."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite recovered Markdown file if it already exists.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        password = getpass.getpass("Password: ")
        output_path = yara_file_to_markdown(
            Path(args.yara_file).expanduser().resolve(),
            Path(args.output).expanduser().resolve(),
            password=password,
            iterations=args.iterations,
            overwrite=args.force,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Recovered Markdown file: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
