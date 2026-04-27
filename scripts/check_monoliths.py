#!/usr/bin/env python3
"""Fail CI when source files grow into unreviewable monoliths."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LIMITS: dict[str, int] = {
    ".py": 900,
    ".ts": 800,
    ".tsx": 800,
    ".mo": 1000,
}

IGNORED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    ".dfx",
    "__pycache__",
}

ALLOWLIST = ROOT / ".monolith-allowlist"


def load_allowlist() -> set[str]:
    if not ALLOWLIST.exists():
        return set()
    return {
        line.strip().replace("\\", "/")
        for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def is_ignored(path: Path) -> bool:
    return any(part in IGNORED_PARTS for part in path.parts)


def line_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8").splitlines())
    except UnicodeDecodeError:
        return 0


def main() -> int:
    allowlist = load_allowlist()
    violations: list[str] = []

    for path in ROOT.rglob("*"):
        if not path.is_file() or is_ignored(path):
            continue
        limit = LIMITS.get(path.suffix)
        if limit is None:
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel in allowlist:
            continue
        count = line_count(path)
        if count > limit:
            violations.append(f"{rel}: {count} lines > {limit} limit")

    if violations:
        print("Monolith check failed:")
        for violation in violations:
            print(f"- {violation}")
        print("Add a justified exception to .monolith-allowlist only when unavoidable.")
        return 1

    print("Monolith check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
