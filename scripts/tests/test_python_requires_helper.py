"""
Focused tests for the Makefile bootstrap helper.

These tests cover the helper behaviors that the top-level Makefile relies on
during bootstrap:

- `BOOTSTRAP_PYTHON := $(... select-from-pyproject ...)` depends on the helper
    selecting the best compatible interpreter path from `project.requires-python`.
- `bootstrap_venv` calls `check-from-pyproject` just before creating `.venv`, so
    the helper must keep its command dispatch predictable.
- The bootstrap path must remain robust on older runtimes and odd developer
    machines, which is why these tests also cover TOML fallback ordering and
    interpreter probe timeouts.
"""

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType

import pytest
from pytest_mock import MockerFixture

HELPER_PATH = Path(__file__).resolve().parents[1] / "python_requires_helper.py"


@pytest.fixture
def helper_module() -> ModuleType:
    # Load the helper by path so the tests exercise the standalone script that
    # Makefile invokes, not an importable package wrapper.
    spec = importlib.util.spec_from_file_location("python_requires_helper_under_test", HELPER_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_load_toml_module_prefers_vendored_copy_before_install(
    helper_module: ModuleType, mocker: MockerFixture
) -> None:
    # `make bootstrap` starts by running the helper with a generic Python. On
    # Python 3.7-3.10 we want pyproject parsing to succeed from pip's vendored
    # TOML parser before the helper tries to mutate the environment.
    vendored_toml = ModuleType("pip._vendor.tomli")
    mocker.patch.object(helper_module.sys, "version_info", (3, 10, 0))
    import_module = mocker.patch.object(
        helper_module.importlib,
        "import_module",
        side_effect=[ImportError(), vendored_toml],
    )
    install_tomli = mocker.patch.object(helper_module.subprocess, "run")

    module = helper_module._load_toml_module("pyproject.toml")

    assert module is vendored_toml
    assert import_module.call_args_list[0].args == ("tomli",)
    assert import_module.call_args_list[1].args == ("pip._vendor.tomli",)
    install_tomli.assert_not_called()


def test_python_version_returns_none_on_timeout(helper_module: ModuleType, mocker: MockerFixture) -> None:
    # `select-from-pyproject` scans PATH for candidate interpreters. A broken or
    # hanging python shim must be ignored so `BOOTSTRAP_PYTHON` resolution does
    # not stall the entire bootstrap target.
    mocker.patch.object(
        helper_module.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired("python3", helper_module.PROBE_TIMEOUT_SECONDS),
    )

    assert helper_module._python_version("python3") is None


def test_select_python_uses_highest_compatible_version(
    helper_module: ModuleType, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    # This is the direct contract behind:
    #   BOOTSTRAP_PYTHON := $(... select-from-pyproject ...)
    # The helper should return the newest compatible interpreter path, not just
    # any matching Python.
    versions = {
        "/usr/bin/python3.9": helper_module._make_version("3.9.18"),
        "/usr/bin/python3.10": helper_module._make_version("3.10.14"),
        "/usr/bin/python3.13": helper_module._make_version("3.13.3"),
    }
    mocker.patch.object(helper_module, "_candidate_executables", return_value=list(versions))
    mocker.patch.object(helper_module, "_python_version", side_effect=lambda executable: versions[executable])

    result = helper_module.select_python(">=3.10,<3.14")

    assert result == 0
    assert capsys.readouterr().out.strip() == "/usr/bin/python3.13"


def test_main_dispatches_to_selected_handler(helper_module: ModuleType, mocker: MockerFixture) -> None:
    # `bootstrap_venv` calls the helper through its small CLI surface, so this
    # test locks down the `select-from-pyproject` command routing used by Make.
    select_from_pyproject = mocker.patch.object(helper_module, "select_python_from_pyproject", return_value=0)

    result = helper_module.main(["python_requires_helper.py", "select-from-pyproject", "pyproject.toml"])

    assert result == 0
    select_from_pyproject.assert_called_once_with("pyproject.toml")
