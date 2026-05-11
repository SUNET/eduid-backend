# Python bootstrap flow

This document explains how the repository bootstraps a local Python environment
through [Makefile](../Makefile) and
[scripts/python_requires_helper.py](../scripts/python_requires_helper.py).

The goal is to keep the Python version requirement in one place,
`[project].requires-python` in `pyproject.toml`, while still allowing bootstrap
to start from a machine that does not yet have the target interpreter selected.

## Main pieces

The bootstrap flow is split into two layers:

- `Makefile` owns the user-facing targets, mainly `bootstrap_venv` and `bootstrap`.
- `scripts/python_requires_helper.py` owns the Python-specific logic for reading
  `pyproject.toml`, parsing `requires-python`, inspecting interpreters on `PATH`,
  and checking whether a concrete interpreter satisfies the requirement.

This split keeps the shell logic readable and keeps the version-selection logic
in Python, where PEP 440 specifiers and TOML parsing are easier to handle safely.

## Makefile variables

The bootstrap-related variables near the top of `Makefile` are:

- `PYTHON_REQUIRES_HELPER`: absolute path to `scripts/python_requires_helper.py`.
- `PYTHON_FOR_PARSE`: a generic bootstrap interpreter, preferring `python3` and
  then `python`, used only to run the helper before the final interpreter has
  been chosen.
- `BOOTSTRAP_PYTHON`: the exact interpreter path returned by the helper after it
  scans `PATH` for a Python that satisfies `project.requires-python`.
- `VENV`: the virtualenv directory, defaulting to `.venv`.
- `VENV_PYTHON`: the Python executable inside the created virtualenv.

Returning an executable path instead of a version string avoids reconstructing
names such as `python3.13` from a discovered interpreter.

## bootstrap_venv target

`make bootstrap_venv` is responsible only for creating `.venv` with a compatible
interpreter. It does not install the repo dependencies yet.

Its resolution order is:

1. Fail early if the helper could not find any compatible interpreter.
2. If `uv` is installed, call `uv venv --python <selected interpreter>`.
3. Otherwise, re-check the selected interpreter with the helper and create the
   environment with `<selected interpreter> -m venv`.
4. If that path is no longer usable, try `python3` and then `python`, but only
   when the helper confirms that each still satisfies `requires-python`.
5. If none of the above works, print an actionable error and stop.

The explicit re-check is intentional. It keeps bootstrap conservative if `PATH`
or `pyproject.toml` changes between Make variable expansion and recipe execution.

## bootstrap target

`make bootstrap` depends on `bootstrap_venv` and then installs the development
toolchain into the freshly created environment.

The target performs these steps:

1. Ensure `pip` exists inside `.venv`, using `ensurepip` when needed.
2. Upgrade `pip` inside the environment.
3. Install the locked development requirements from
   `requirements/test_requirements.txt`, preferring `uv pip` when `uv` is
   available and falling back to `pip` otherwise.
4. Install the repository itself into `.venv` in editable mode with
   `pip install --no-deps --no-build-isolation -e .`.
5. Run `mypy --install-types --non-interactive` inside `.venv` so common stub
   packages are available without extra manual setup.

The result is a local environment that IDEs, shell commands, and the devcontainer
can all use consistently via `.venv/bin/python`.

## Helper script behavior

`scripts/python_requires_helper.py` is intentionally runnable on Python 3.7 and
newer. That lower minimum lets it run before the target project interpreter has
been provisioned.

The helper supports four commands:

- `select <requires-python>`: print the best compatible interpreter path found
  on `PATH`.
- `check <requires-python>`: exit successfully only if the interpreter running
  the helper satisfies the given specifier.
- `select-from-pyproject <pyproject.toml>`: read `[project].requires-python`
  from the given file, then behave like `select`.
- `check-from-pyproject <pyproject.toml>`: read `[project].requires-python`
  from the given file, then behave like `check`.

Internally, the helper:

- parses `pyproject.toml` with `tomllib` on Python 3.11+ and older-compatible
  TOML loaders on Python 3.7-3.10,
- parses the version specifier with `packaging`, with a fallback to pip's
  vendored copy,
- scans `PATH` for Python executables,
- probes each candidate by executing it and reading `sys.version_info`,
- picks the highest compatible interpreter, and
- prints the exact executable path that satisfied the probe.

## Why this design exists

The design tries to solve a few practical problems at once:

- keep the required Python version in one canonical place,
- avoid hardcoding interpreter names in `Makefile`,
- let bootstrap work both inside and outside the devcontainer,
- prefer `uv` when available without making it mandatory,
- and keep the shell layer small enough to debug quickly.

In short, `Makefile` owns the workflow and user messages, while the helper owns
the Python-specific decision making.
