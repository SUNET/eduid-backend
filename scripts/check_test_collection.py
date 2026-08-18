#!/usr/bin/env python3
"""Fail if a test class defines test methods but pytest would not collect it.

Our test base classes are plain classes, not ``unittest.TestCase`` subclasses (see
``MongoTestCase`` in ``src/eduid/userdb/testing/__init__.py``). That means pytest's
unittest plugin does not collect them, and collection falls back entirely to matching
class names against the ``python_classes`` patterns in ``pyproject.toml``.

A class whose name matches none of those patterns is skipped *silently* - no error, no
warning, no skip - and the suite still reports success. Commit 282315153 dropped
``unittest.TestCase`` from ``MongoTestCase`` and took 92 test methods out of collection
that way; nobody noticed for months. This check exists so that cannot recur.

Note it is deliberately not a "does this file collect zero tests" check: two of the
seven affected files collected tests from other classes and looked perfectly healthy
while still hiding dead ones.
"""

from __future__ import annotations

import ast
import fnmatch
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
TEST_ROOT = REPO_ROOT / "src"
TEST_FILE_GLOB = "test_*.py"

# Base classes are expected not to be collected: they hold shared helpers and are run
# via their subclasses. Only names that would otherwise be reported go here.
ALLOWED_UNCOLLECTED: frozenset[str] = frozenset()


def python_classes_patterns() -> list[str]:
    """Read ``python_classes`` from pyproject.toml so this check cannot drift from it."""
    with PYPROJECT.open("rb") as fp:
        config = tomllib.load(fp)
    ini_options = config.get("tool", {}).get("pytest", {}).get("ini_options", {})
    patterns = ini_options.get("python_classes")
    if patterns is None:
        # pytest's own default when the setting is absent.
        return ["Test*"]
    if isinstance(patterns, str):
        return patterns.split()
    return list(patterns)


def is_collected(class_name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(class_name, pattern) for pattern in patterns)


def test_methods(node: ast.ClassDef) -> list[str]:
    return [
        child.name
        for child in node.body
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) and child.name.startswith("test")
    ]


def find_uncollected(patterns: list[str]) -> list[tuple[Path, str, int, list[str]]]:
    findings: list[tuple[Path, str, int, list[str]]] = []
    for path in sorted(TEST_ROOT.rglob(TEST_FILE_GLOB)):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            print(f"{path}: could not parse ({exc})", file=sys.stderr)
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name in ALLOWED_UNCOLLECTED or is_collected(node.name, patterns):
                continue
            methods = test_methods(node)
            if methods:
                findings.append((path.relative_to(REPO_ROOT), node.name, node.lineno, methods))
    return findings


def main() -> int:
    patterns = python_classes_patterns()
    findings = find_uncollected(patterns)
    if not findings:
        return 0

    dead_methods = sum(len(methods) for _, _, _, methods in findings)
    print(
        f"error: {len(findings)} test class(es) with {dead_methods} test method(s) will not be collected by pytest.",
        file=sys.stderr,
    )
    print(f"None of their names match python_classes = {patterns}\n", file=sys.stderr)
    for path, class_name, lineno, methods in findings:
        print(f"  {path}:{lineno}: class {class_name} ({len(methods)} test methods)", file=sys.stderr)
    print(
        "\nRename the class so it matches one of the patterns above (the repo convention is a"
        "\n'Test' prefix), or add it to ALLOWED_UNCOLLECTED in this script if it is a base class"
        "\nthat is genuinely meant to run only via its subclasses.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
