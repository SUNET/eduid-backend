# Python bootstrap flow

This document explains how the repository bootstraps a local Python environment
through [Makefile](../Makefile).

The host system must provide a working `uv` installation before bootstrap starts.
`uv` resolves and provisions an interpreter that satisfies the project's
`requires-python` setting itself.

The goal is to keep the project Python version requirement in one place,
`[project].requires-python` in `pyproject.toml`, while using `uv` as the single
bootstrap entrypoint for provisioning the target interpreter.

## Main pieces

The bootstrap flow is intentionally small:

- `Makefile` owns the user-facing targets, mainly `bootstrap_venv` and `bootstrap`.
- `uv` reads `[project].requires-python` from `pyproject.toml` and selects a
  compatible interpreter for the environment.

`pyproject.toml` is the single source of truth for the project Python
requirement. `Makefile` and `uv` derive bootstrap behavior from that file; they
do not hardcode the project interpreter version independently.

This split keeps the shell logic readable and delegates PEP 440 handling to the
tool that provisions the interpreter.

## Makefile variables

The bootstrap-related variables near the top of `Makefile` are:

- `VENV`: the virtualenv directory, defaulting to `.venv`.
- `VENV_PYTHON`: the Python executable inside the created virtualenv.

## bootstrap_venv target

`make bootstrap_venv` is responsible only for creating `.venv` with a compatible
interpreter. It does not install the repo dependencies yet.

Its behavior is:

1. Require the host system to provide `uv`.
2. Let `uv` read `[project].requires-python` from `pyproject.toml`.
3. Create the environment with `uv venv .venv`.

When `uv` needs to provision a compatible interpreter, it resolves the Python
request directly from `pyproject.toml` instead of relying on repo-specific
parsing logic.

## bootstrap target

`make bootstrap` depends on `bootstrap_venv` and then installs the development
toolchain into the freshly created environment.

The target performs these steps:

1. Install the locked development requirements from
  `requirements/test_requirements.txt` with `uv pip --require-hashes`.
2. Install the repository itself into `.venv` in editable mode with
  `uv pip install --no-deps --no-build-isolation -e .`.
3. Run `mypy --strict -p eduid` inside `.venv` after the locked stub packages
   have already been installed as part of the development toolchain.

The result is a local environment that IDEs and shell commands can use
consistently via the active virtualenv for that environment. In this repository,
the host workflow defaults to `.venv`, while the devcontainer uses a separate
virtualenv path to avoid reusing host-local artifacts.
For VS Code, those defaults apply independently in the host workspace window and
in the reopened devcontainer window. The Python extension remembers the selected
interpreter for each context after the first selection, so
`python.defaultInterpreterPath` only acts as the initial default.
If the integrated terminal auto-activates the wrong environment, reselection in
the current context with `Python: Select Interpreter` and then opening a fresh
terminal is enough to restore the expected activation behavior.

## Why this design exists

The design tries to solve a few practical problems at once:

- keep the required Python version in one canonical place,
- avoid hardcoding interpreter versions in `Makefile`,
- let bootstrap work both inside and outside the devcontainer,
- use `uv` as the single installer frontend for repo-managed workflows,
- and keep the shell layer small enough to debug quickly.

In short, `Makefile` owns the workflow and user messages, while `uv` owns the
Python-version resolution.
