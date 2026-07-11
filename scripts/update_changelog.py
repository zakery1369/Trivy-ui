#!/usr/bin/env python3
"""Insert one tagged release into CHANGELOG.md using a Markdown template."""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--changelog", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--date", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--commit", required=True)
    return parser.parse_args()


def markdown_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("`", "\\`").strip()


def main() -> None:
    args = parse_args()
    changelog = args.changelog.read_text(encoding="utf-8")
    release_heading = f"## [{args.tag}]"
    if release_heading in changelog:
        print(f"{args.tag} is already present; no update needed.")
        return

    marker = "## Releases\n"
    if marker not in changelog:
        raise SystemExit("CHANGELOG.md must contain a '## Releases' heading")

    entry = args.template.read_text(encoding="utf-8")
    replacements = {
        "{{TAG}}": markdown_text(args.tag),
        "{{DATE}}": markdown_text(args.date),
        "{{DESCRIPTION}}": markdown_text(args.description),
        "{{COMMIT}}": markdown_text(args.commit),
    }
    for placeholder, value in replacements.items():
        entry = entry.replace(placeholder, value)

    insertion_point = changelog.index(marker) + len(marker)
    updated = changelog[:insertion_point] + "\n" + entry.rstrip() + "\n" + changelog[insertion_point:]
    args.changelog.write_text(updated, encoding="utf-8")
    print(f"Added {args.tag} to {args.changelog}.")


if __name__ == "__main__":
    main()
