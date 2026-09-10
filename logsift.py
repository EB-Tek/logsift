#!/usr/bin/env python3
"""logsift — collapse a noisy log file into the handful of things actually happening.

A 200,000-line log usually contains about twenty distinct events repeated with
different IDs, IPs and timestamps. Reading it line by line is hopeless; grepping
for "error" gives you 40,000 hits of the same error.

logsift masks the variable parts of every line to produce a *template*, groups
identical templates, and reports the patterns by frequency. What took an hour of
scrolling becomes a twenty-row table.

    ./logsift.py /var/log/system.log
    ./logsift.py app.log --top 5 --level error
    cat app.log | ./logsift.py --json

No dependencies — standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Iterable

__version__ = "1.0.0"

# Order matters: the more specific a pattern is, the earlier it must run.
# UUIDs contain hex runs, and timestamps contain numbers, so masking numbers
# first would shred both before they were ever recognised.
_MASKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TIMESTAMP>"),
    (re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"), "<TIMESTAMP>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<MAC>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"), "<EMAIL>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HASH>"),
    (re.compile(r"(?<=[\s=:])/(?:[\w.-]+/)+[\w.-]*"), "<PATH>"),
    # Trailing units must be consumed with the number. "61504ms" would otherwise
    # never match \b\d+\b (the "m" is a word char), leaving every duration,
    # size and percentage as its own unique pattern.
    (re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?:ms|us|ns|[smhd]|[KMGTP]i?B|%)?(?![\w.])"), "<NUM>"),
]

_LEVELS = {
    "emerg": "error", "alert": "error", "crit": "error", "critical": "error",
    "err": "error", "error": "error", "fatal": "error", "fail": "error",
    "failed": "error", "failure": "error",
    "warn": "warn", "warning": "warn",
    "notice": "info", "info": "info", "debug": "debug", "trace": "debug",
}
_LEVEL_RE = re.compile(r"\b(" + "|".join(sorted(_LEVELS, key=len, reverse=True)) + r")\b", re.I)


def templatize(line: str) -> str:
    """Reduce a log line to its shape by masking the parts that vary per event."""
    out = line.strip()
    for pattern, token in _MASKS:
        out = pattern.sub(token, out)
    # collapse whitespace so identical shapes are not split by spacing
    return re.sub(r"\s+", " ", out).strip()


def detect_level(line: str) -> str:
    """Best-effort severity from the line's own wording."""
    match = _LEVEL_RE.search(line)
    return _LEVELS.get(match.group(1).lower(), "info") if match else "info"


@dataclass
class Pattern:
    template: str
    count: int = 0
    level: str = "info"
    first_line: int = 0
    last_line: int = 0
    sample: str = ""

    def as_dict(self) -> dict:
        return {
            "template": self.template,
            "count": self.count,
            "level": self.level,
            "first_line": self.first_line,
            "last_line": self.last_line,
            "sample": self.sample,
        }


def sift(lines: Iterable[str], level_filter: str | None = None) -> tuple[list[Pattern], int]:
    """Group lines by template. Returns (patterns sorted by count desc, total scanned)."""
    groups: dict[str, Pattern] = {}
    total = 0
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        total += 1
        level = detect_level(raw)
        if level_filter and level != level_filter:
            continue
        key = templatize(raw)
        if not key:
            continue
        pattern = groups.get(key)
        if pattern is None:
            pattern = Pattern(template=key, level=level, first_line=number, sample=raw.strip())
            groups[key] = pattern
        pattern.count += 1
        pattern.last_line = number
        # an error seen at any severity should surface as an error
        if _severity(level) > _severity(pattern.level):
            pattern.level = level
    ordered = sorted(groups.values(), key=lambda p: (-p.count, p.first_line))
    return ordered, total


def _severity(level: str) -> int:
    return {"debug": 0, "info": 1, "warn": 2, "error": 3}.get(level, 1)


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def render_table(patterns: list[Pattern], total: int, shown: int, width: int = 88) -> str:
    if not patterns:
        return "No matching log lines."
    unique = len(patterns)
    counted = sum(p.count for p in patterns)
    out = [
        f"Scanned {total:,} lines — {counted:,} matched, {unique:,} distinct patterns.",
        "",
        f"{'COUNT':>7}  {'LEVEL':<5}  {'LINES':<15}  PATTERN",
        f"{'-'*7}  {'-'*5}  {'-'*15}  {'-'*(width-33)}",
    ]
    for p in patterns[:shown]:
        span = f"{p.first_line}-{p.last_line}" if p.first_line != p.last_line else str(p.first_line)
        out.append(f"{p.count:>7,}  {p.level:<5}  {span:<15}  {_truncate(p.template, width-33)}")
    if unique > shown:
        out.append(f"{'':>7}  {'':<5}  {'':<15}  … {unique - shown:,} more patterns")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="logsift",
        description="Collapse a noisy log into its distinct patterns, ranked by frequency.",
    )
    ap.add_argument("logfile", nargs="?", help="log file to read (defaults to stdin)")
    ap.add_argument("-n", "--top", type=int, default=20, help="patterns to show (default 20)")
    ap.add_argument("-l", "--level", choices=["error", "warn", "info", "debug"],
                    help="only include lines at this severity")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument("-V", "--version", action="version", version=f"logsift {__version__}")
    args = ap.parse_args(argv)

    try:
        if args.logfile:
            with open(args.logfile, "r", errors="replace") as fh:
                patterns, total = sift(fh, args.level)
        else:
            if sys.stdin.isatty():
                ap.error("no logfile given and nothing piped in")
            patterns, total = sift(sys.stdin, args.level)
    except FileNotFoundError:
        print(f"logsift: no such file: {args.logfile}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"logsift: permission denied: {args.logfile}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(
            {"scanned": total, "distinct": len(patterns),
             "patterns": [p.as_dict() for p in patterns[: args.top]]},
            indent=2,
        ))
    else:
        print(render_table(patterns, total, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
