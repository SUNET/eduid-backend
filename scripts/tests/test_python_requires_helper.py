"""
Focused tests for the Makefile bootstrap helper.

These tests cover the helper behaviors that the top-level Makefile relies on
during bootstrap:

- `bootstrap_venv` depends on `minor-from-pyproject` deriving a concrete pinned
    Python minor for `uv python install`.
- The bootstrap path must remain robust on odd developer machines, which is why
    these tests also cover the Python 3.11+ runtime floor.
"""

import importlib.util
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


def test_read_pyproject_toml_uses_tomllib_on_python_311_or_newer(
    helper_module: ModuleType, mocker: MockerFixture, tmp_path: Path
) -> None:
    # `make bootstrap` runs the helper through `uv run --python '>=3.11'`, so
    # pyproject parsing should use the stdlib TOML parser directly.
    mocker.patch.object(helper_module.sys, "version_info", (3, 11, 0))
    pyproject_path = tmp_path / "pyproject.toml"
    pyproject_path.write_text("[project]\nrequires-python = '>=3.11'\n", encoding="utf-8")

    pyproject_data = helper_module._read_pyproject_toml(str(pyproject_path))

    assert pyproject_data == {"project": {"requires-python": ">=3.11"}}


def test_read_pyproject_toml_requires_python_311_or_newer(helper_module: ModuleType, mocker: MockerFixture) -> None:
    # Direct execution on older runtimes should fail clearly instead of trying
    # to recover through a compatibility path.
    mocker.patch.object(helper_module.sys, "version_info", (3, 10, 0))

    with pytest.raises(SystemExit, match=r"python_requires_helper\.py requires Python 3\.11\+"):
        helper_module._read_pyproject_toml("pyproject.toml")


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


def test_main_dispatches_minor_from_pyproject(helper_module: ModuleType, mocker: MockerFixture) -> None:
    # `bootstrap_venv` sources the pinned minor through the helper CLI, so keep
    # the command routing explicit and stable.
    minor_from_pyproject = mocker.patch.object(helper_module, "python_minor_series_from_pyproject", return_value=0)

    result = helper_module.main(["python_requires_helper.py", "minor-from-pyproject", "pyproject.toml"])

    assert result == 0
    minor_from_pyproject.assert_called_once_with("pyproject.toml")
