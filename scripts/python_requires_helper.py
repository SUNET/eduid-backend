#!/usr/bin/env python3

"""
Bootstrap helper for deriving a concrete Python minor from requires-python.

This script exists so the Makefile can stay small while the Python-version
derivation logic lives in one place. It supports one input form:

- a ``pyproject.toml`` path via ``minor-from-pyproject``

Behavior summary:

- load ``requires-python`` from ``[project]`` in ``pyproject.toml``
- parse the specifier with ``packaging``
- derive a concrete Python minor release for provisioning when needed

The helper intentionally requires Python 3.11 or newer so bootstrap can rely
on the stdlib tomllib parser while still running independently of the target
project interpreter.

"""

import re
import sys
from functools import lru_cache
from typing import TYPE_CHECKING, Callable, Dict, List, Tuple, Type, cast

if TYPE_CHECKING:
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version

COMMAND_ARGC = 3
PROBE_TIMEOUT_SECONDS = 5
MINOR_TOKEN_RE = re.compile(r"(\d+)\.(\d+)")
MINOR_SERIES_SEARCH_LIMIT = 24


@lru_cache(maxsize=1)
def _load_packaging() -> "Tuple[Type[SpecifierSet], Type[Version]]":
    # Cache the packaging imports so the lookup runs only once.
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
    except ImportError as exc:
        raise SystemExit("Need packaging support to parse requires-python") from exc
    return SpecifierSet, Version


def _make_specifier_set(specifier: str) -> "SpecifierSet":
    specifier_set_cls, _ = _load_packaging()
    return specifier_set_cls(specifier)


def _make_version(version: str) -> "Version":
    _, version_cls = _load_packaging()
    return version_cls(version)


def _read_pyproject_toml(pyproject_path: str) -> dict[str, object]:
    # Makefile runs the helper through `uv run --python '>=3.11'`, so older
    # runtimes should fail explicitly instead of using compatibility fallbacks.
    if sys.version_info < (3, 11):
        raise SystemExit("python_requires_helper.py requires Python 3.11+")

    import tomllib

    try:
        with open(pyproject_path, "rb") as fp:
            pyproject_data = tomllib.load(fp)
    except OSError as exc:
        raise SystemExit(f"Could not read pyproject.toml: {pyproject_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"Could not parse pyproject.toml: {pyproject_path}") from exc

    if not isinstance(pyproject_data, dict):
        raise SystemExit(f"Could not parse pyproject.toml as a table: {pyproject_path}")
    return cast(dict[str, object], pyproject_data)


def _read_requires_python(pyproject_path: str) -> str:
    # Use a real TOML parser on every supported runtime so older Python
    # versions read pyproject.toml with the same semantics as tomllib.
    pyproject_data = _read_pyproject_toml(pyproject_path)
    project_data = pyproject_data.get("project")
    if not isinstance(project_data, dict):
        raise SystemExit(f"Could not find [project] in: {pyproject_path}")
    project_table = cast(dict[str, object], project_data)

    requires_python = project_table.get("requires-python")
    if not isinstance(requires_python, str):
        raise SystemExit(f"Could not find requires-python in [project]: {pyproject_path}")
    return requires_python


def _increment_minor(major: int, minor: int, steps: int) -> tuple[int, int]:
    total_minors = major * 100 + minor + steps
    return divmod(total_minors, 100)


def _minor_series_matches(specifier: str, major: int, minor: int) -> bool:
    spec = _make_specifier_set(specifier)
    # We need a concrete minor for `uv venv --python X.Y`, not a single patch.
    # Treat the series as compatible when either the floor or a high patch in
    # that minor satisfies the specifier.
    return _make_version(f"{major}.{minor}.0") in spec or _make_version(f"{major}.{minor}.999999") in spec


def python_minor_series(specifier: str) -> str:
    anchors = [(int(major), int(minor)) for major, minor in MINOR_TOKEN_RE.findall(specifier)]
    if not anchors:
        raise SystemExit(
            "Could not derive a concrete Python minor release from requires-python;"
            " use a specifier with an explicit Python version baseline"
        )

    start_major, start_minor = min(anchors)
    for offset in range(MINOR_SERIES_SEARCH_LIMIT):
        major, minor = _increment_minor(start_major, start_minor, offset)
        if _minor_series_matches(specifier, major, minor):
            return f"{major}.{minor}"

    raise SystemExit(
        "Could not derive a concrete Python minor release from requires-python;"
        " prefer a specifier with an explicit lower-bound baseline, such as >=3.13 or ==3.13.*"
    )


def python_minor_series_from_pyproject(pyproject_path: str) -> int:
    print(python_minor_series(_read_requires_python(pyproject_path)))
    return 0


def main(argv: List[str]) -> int:
    # Keep the CLI small and explicit since Make invokes these entrypoints
    # directly.
    commands: Dict[str, Callable[[str], int]] = {
        "minor-from-pyproject": python_minor_series_from_pyproject,
    }
    if len(argv) != COMMAND_ARGC or argv[1] not in commands:
        print(
            "Usage: python_requires_helper.py {minor-from-pyproject} <pyproject.toml>",
            file=sys.stderr,
        )
        return 2

    command, argument = argv[1], argv[2]
    return commands[command](argument)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
