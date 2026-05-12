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


def test_select_python_fails_when_no_compatible_interpreter_exists(
    helper_module: ModuleType, mocker: MockerFixture
) -> None:
    # `BOOTSTRAP_PYTHON` is empty when no interpreter matches. The Makefile's
    # non-uv fallback paths depend on the helper failing clearly in that case.
    mocker.patch.object(helper_module, "_candidate_executables", return_value=[])

    with pytest.raises(SystemExit, match=r"No installed Python matches requires-python: >=3.13,<3.14"):
        helper_module.select_python(">=3.13,<3.14")


def test_check_python_from_pyproject_reports_version_match(helper_module: ModuleType, mocker: MockerFixture) -> None:
    # `bootstrap_venv` calls `check-from-pyproject` before the plain `venv`
    # fallback branches, so the pyproject wrapper must delegate predictably.
    mocker.patch.object(helper_module, "_read_requires_python", return_value="==3.13.*")
    check_python = mocker.patch.object(helper_module, "check_python", return_value=0)

    result = helper_module.check_python_from_pyproject("pyproject.toml")

    assert result == 0
    check_python.assert_called_once_with("==3.13.*")


def test_python_minor_series_requires_single_pinned_minor(helper_module: ModuleType) -> None:
    # `BOOTSTRAP_PYTHON_MINOR` still needs a concrete baseline. Specs that only
    # declare an upper bound do not identify a usable bootstrap target.
    with pytest.raises(SystemExit, match="Could not derive a concrete Python minor release from requires-python"):
        helper_module.python_minor_series("<3.13")


def test_python_minor_series_accepts_lower_bound_baseline(helper_module: ModuleType) -> None:
    # A future repo policy such as `>=3.13` should not require helper changes.
    assert helper_module.python_minor_series(">=3.13") == "3.13"


def test_python_minor_series_accepts_supported_range(helper_module: ModuleType) -> None:
    # Common support windows should still collapse to one concrete bootstrap
    # minor without forcing the Makefile contract to change.
    assert helper_module.python_minor_series(">=3.13,<3.15") == "3.13"


def test_python_minor_series_from_pyproject_prints_pinned_minor(
    helper_module: ModuleType, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    # This is the direct contract behind:
    #   BOOTSTRAP_PYTHON_MINOR := $(... minor-from-pyproject ...)
    mocker.patch.object(helper_module, "_read_requires_python", return_value="==3.13.*")

    result = helper_module.python_minor_series_from_pyproject("pyproject.toml")

    assert result == 0
    assert capsys.readouterr().out.strip() == "3.13"


def test_main_dispatches_to_selected_handler(helper_module: ModuleType, mocker: MockerFixture) -> None:
    # `bootstrap_venv` calls the helper through its small CLI surface, so this
    # test locks down the `select-from-pyproject` command routing used by Make.
    select_from_pyproject = mocker.patch.object(helper_module, "select_python_from_pyproject", return_value=0)

    result = helper_module.main(["python_requires_helper.py", "select-from-pyproject", "pyproject.toml"])

    assert result == 0
    select_from_pyproject.assert_called_once_with("pyproject.toml")


def test_main_dispatches_minor_from_pyproject(helper_module: ModuleType, mocker: MockerFixture) -> None:
    # `BOOTSTRAP_PYTHON_MINOR` is sourced through the helper CLI, so keep the
    # command routing explicit and stable.
    minor_from_pyproject = mocker.patch.object(helper_module, "python_minor_series_from_pyproject", return_value=0)

    result = helper_module.main(["python_requires_helper.py", "minor-from-pyproject", "pyproject.toml"])

    assert result == 0
    minor_from_pyproject.assert_called_once_with("pyproject.toml")
