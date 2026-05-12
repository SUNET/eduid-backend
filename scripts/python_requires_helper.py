#!/usr/bin/env python3

"""
Bootstrap helper for selecting a Python interpreter from requires-python.

This script exists so the Makefile can stay small while the interpreter
selection logic lives in one place. It supports two kinds of inputs:

- a raw PEP 440 specifier via ``select`` and ``check``
- a ``pyproject.toml`` path via ``select-from-pyproject`` and
    ``check-from-pyproject``

Behavior summary:

- load ``requires-python`` from ``[project]`` in ``pyproject.toml``
- parse the specifier with ``packaging`` or pip's vendored fallback
- inspect installed Python executables on ``PATH``
- choose the highest compatible Python executable for bootstrapping
- verify whether a concrete interpreter satisfies the project requirement

The helper intentionally supports Python 3.7 and newer runtimes so it can run
before the target interpreter has been provisioned.

"""

import importlib
import os
import re
import shutil
import subprocess
import sys
from contextlib import suppress
from functools import lru_cache
from types import ModuleType
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Type, cast

if TYPE_CHECKING:
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version

COMMAND_ARGC = 3
PROBE_TIMEOUT_SECONDS = 5
EXACT_MINOR_RE = re.compile(r"^\s*==\s*(\d+\.\d+)(?:\.\*|\.\d+)?\s*$")


@lru_cache(maxsize=1)
def _load_packaging() -> "Tuple[Type[SpecifierSet], Type[Version]]":
    # Cache the packaging imports so the fallback lookup runs only once.
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
    except ImportError:
        try:
            from pip._vendor.packaging.specifiers import SpecifierSet as VendorSpecifierSet
            from pip._vendor.packaging.version import Version as VendorVersion
        except ImportError as exc:
            raise SystemExit("Need packaging support to parse requires-python") from exc
        return cast("Tuple[Type[SpecifierSet], Type[Version]]", (VendorSpecifierSet, VendorVersion))
    return SpecifierSet, Version


def _make_specifier_set(specifier: str) -> "SpecifierSet":
    specifier_set_cls, _ = _load_packaging()
    return specifier_set_cls(specifier)


def _make_version(version: str) -> "Version":
    _, version_cls = _load_packaging()
    return version_cls(version)


def _load_toml_module(pyproject_path: str) -> ModuleType:
    # Use the stdlib parser when available. On older runtimes, prefer tomli and
    # then pip's vendored copy before attempting an on-demand install.
    if sys.version_info >= (3, 11):
        import tomllib as toml

        return toml

    try:
        return importlib.import_module("tomli")
    except ImportError:
        pass

    try:
        return importlib.import_module("pip._vendor.tomli")
    except ImportError:
        pass

    print("Installing tomli to parse pyproject.toml...", file=sys.stderr)
    with suppress(OSError, subprocess.CalledProcessError):
        subprocess.run([sys.executable, "-m", "pip", "install", "tomli"], check=True)

    try:
        return importlib.import_module("tomli")
    except ImportError as exc:
        raise SystemExit(f"Need TOML support to parse pyproject.toml: {pyproject_path}") from exc


def _read_pyproject_toml(pyproject_path: str) -> object:
    # Keep all pyproject parsing behind one loader so every runtime gets the same
    # TOML semantics and error handling.
    toml = cast(Any, _load_toml_module(pyproject_path))

    try:
        with open(pyproject_path, "rb") as fp:
            return toml.load(fp)
    except OSError as exc:
        raise SystemExit(f"Could not read pyproject.toml: {pyproject_path}") from exc
    except toml.TOMLDecodeError as exc:
        raise SystemExit(f"Could not parse pyproject.toml: {pyproject_path}") from exc


def _read_requires_python(pyproject_path: str) -> str:
    # Use a real TOML parser on every supported runtime so older Python
    # versions read pyproject.toml with the same semantics as tomllib.
    pyproject_data = _read_pyproject_toml(pyproject_path)
    if not isinstance(pyproject_data, dict):
        raise SystemExit(f"Could not parse pyproject.toml as a table: {pyproject_path}")

    project_data = pyproject_data.get("project")
    if not isinstance(project_data, dict):
        raise SystemExit(f"Could not find [project] in: {pyproject_path}")

    requires_python = project_data.get("requires-python")
    if not isinstance(requires_python, str):
        raise SystemExit(f"Could not find requires-python in [project]: {pyproject_path}")
    return requires_python


def python_minor_series(specifier: str) -> str:
    match = EXACT_MINOR_RE.fullmatch(specifier)
    if match is None:
        raise SystemExit(
            "requires-python must pin a single Python minor release, such as ==3.13.*,"
            " to derive a concrete bootstrap runtime"
        )
    return match.group(1)


def _candidate_executables() -> List[str]:
    candidates = []
    seen = set()

    # Prefer the generic launcher names first, then scan PATH for versioned
    # executables while deduplicating symlinked aliases.
    for name in ("python3", "python"):
        path = shutil.which(name)
        if path is None:
            continue
        real_path = os.path.realpath(path)
        if real_path in seen:
            continue
        seen.add(real_path)
        candidates.append(path)

    pattern = re.compile(r"^python(?:\d+(?:\.\d+)?)?$")
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory or not os.path.isdir(directory):
            continue
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if not pattern.fullmatch(name):
                continue
            path = os.path.join(directory, name)
            if not os.access(path, os.X_OK):
                continue
            real_path = os.path.realpath(path)
            if real_path in seen:
                continue
            seen.add(real_path)
            candidates.append(path)

    return candidates


def _python_version(executable: str) -> Optional["Version"]:
    # Probe each interpreter in isolation instead of trusting the executable name.
    try:
        result = subprocess.run(
            [
                executable,
                "-c",
                "import sys; print('.'.join(str(part) for part in sys.version_info[:3]))",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

    try:
        return _make_version(result.stdout.strip())
    except Exception:
        return None


def select_python(specifier: str) -> int:
    spec = _make_specifier_set(specifier)
    best_match = None
    for executable in _candidate_executables():
        version = _python_version(executable)
        if version is None:
            continue
        if version in spec and (best_match is None or version > best_match[0]):
            best_match = (version, executable)

    if best_match is None:
        raise SystemExit(f"No installed Python matches requires-python: {specifier}")

    # Return the exact interpreter that satisfied the probe so callers do not
    # have to reconstruct an executable name from the version.
    print(best_match[1])
    return 0


def check_python(specifier: str) -> int:
    # This command validates the interpreter currently running the helper.
    version = _make_version(".".join(str(part) for part in sys.version_info[:3]))
    return 0 if version in _make_specifier_set(specifier) else 1


def select_python_from_pyproject(pyproject_path: str) -> int:
    return select_python(_read_requires_python(pyproject_path))


def check_python_from_pyproject(pyproject_path: str) -> int:
    return check_python(_read_requires_python(pyproject_path))


def python_minor_series_from_pyproject(pyproject_path: str) -> int:
    print(python_minor_series(_read_requires_python(pyproject_path)))
    return 0


def main(argv: List[str]) -> int:
    # Keep the CLI small and explicit since Make invokes these entrypoints
    # directly.
    commands: Dict[str, Callable[[str], int]] = {
        "select": select_python,
        "check": check_python,
        "select-from-pyproject": select_python_from_pyproject,
        "check-from-pyproject": check_python_from_pyproject,
        "minor-from-pyproject": python_minor_series_from_pyproject,
    }
    if len(argv) != COMMAND_ARGC or argv[1] not in commands:
        print(
            "Usage: python_requires_helper.py {select|check} <requires-python>"
            " | {select-from-pyproject|check-from-pyproject|minor-from-pyproject} <pyproject.toml>",
            file=sys.stderr,
        )
        return 2

    command, argument = argv[1], argv[2]
    return commands[command](argument)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
