"""
Root conftest.py - cleans up Docker test containers.

Handles two scenarios:
1. Session start: removes orphaned containers from previous interrupted runs.
2. Keyboard interrupt (Ctrl+C / VS Code stop): immediately kills containers before the process exits.
"""

from __future__ import annotations

import subprocess


def _remove_test_containers() -> None:
    """Find and forcefully remove all test_* Docker containers."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=test_", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            containers = [c.strip() for c in result.stdout.strip().split("\n") if c.strip()]
            if containers:
                subprocess.run(["docker", "rm", "-f", *containers], capture_output=True, timeout=10)
    except Exception:
        pass


def pytest_sessionstart(session):  # noqa: ANN001, ANN201
    """Remove any orphaned test Docker containers from previous runs."""
    _remove_test_containers()


def pytest_keyboard_interrupt(excinfo):  # noqa: ANN001, ANN201
    """Called on Ctrl+C / VS Code stop — immediately kill all test containers."""
    _remove_test_containers()
