# Python bootstrap flow

This document explains how the repository bootstraps a local Python environment
through [Makefile](../Makefile) and
[scripts/python_requires_helper.py](../scripts/python_requires_helper.py).

The host system must provide a working `uv` installation before bootstrap starts.
`uv` uses a Python 3.11+ runtime to execute the helper and provisions the
project's pinned interpreter itself.

The goal is to keep the project Python version requirement in one place,
`[project].requires-python` in `pyproject.toml`, while using `uv` as the single
bootstrap entrypoint for provisioning the target interpreter.

## Main pieces

The bootstrap flow is split into two layers:

- `Makefile` owns the user-facing targets, mainly `bootstrap_venv` and `bootstrap`.
- `scripts/python_requires_helper.py` owns the Python-specific logic for reading
  `pyproject.toml`, parsing `requires-python`, and deriving the concrete Python
  minor that bootstrap should provision.

`pyproject.toml` is the single source of truth for the project Python
requirement. `Makefile` and the helper derive bootstrap behavior from that file;
they do not hardcode the project interpreter version independently.

This split keeps the shell logic readable and keeps the version-selection logic
in Python, where PEP 440 specifiers and TOML parsing are easier to handle safely.

## Makefile variables

The bootstrap-related variables near the top of `Makefile` are:

- `PYTHON_REQUIRES_HELPER`: absolute path to `scripts/python_requires_helper.py`.
- `UV_BOOTSTRAP`: the `uv` executable used to run the helper in an isolated
  environment.
- `VENV`: the virtualenv directory, defaulting to `.venv`.
- `VENV_PYTHON`: the Python executable inside the created virtualenv.

The selected bootstrap interpreter and fallback minor are resolved lazily inside
`bootstrap_venv`, so unrelated `make` targets do not run the helper during
Makefile parsing.

## bootstrap_venv target

`make bootstrap_venv` is responsible only for creating `.venv` with a compatible
interpreter. It does not install the repo dependencies yet.

Its resolution order is:

1. Require the host system to provide `uv`.
2. Ask the helper to derive the pinned Python minor from `pyproject.toml`.
3. Run `uv python install <major.minor>`.
4. Create the environment with `uv venv --python <major.minor>`.
5. If the helper cannot derive a concrete pinned minor, print an actionable error and stop.

## bootstrap target

`make bootstrap` depends on `bootstrap_venv` and then installs the development
toolchain into the freshly created environment.

The target performs these steps:

1. Install the locked development requirements from
  `requirements/test_requirements.txt` with `uv pip`.
2. Install the repository itself into `.venv` in editable mode with
  `uv pip install --no-deps --no-build-isolation -e .`.
3. Run `mypy --strict -p eduid` inside `.venv` after the locked stub packages
   have already been installed as part of the development toolchain.

The result is a local environment that IDEs, shell commands, and the devcontainer
can all use consistently via `.venv/bin/python`.

## Helper script behavior

`scripts/python_requires_helper.py` intentionally requires Python 3.11 or
newer. `Makefile` enforces that by running it through `uv run --python '>=3.11'`,
which lets `uv` fetch or select a suitable helper runtime independently of the
target project interpreter while using the stdlib `tomllib` parser.

The helper supports one command:

- `minor-from-pyproject <pyproject.toml>`: read `[project].requires-python`
  from the given file and print the pinned Python minor release used for `uv`
  provisioning.

Internally, the helper:

- parses `pyproject.toml` with the stdlib `tomllib` parser,
- parses the version specifier with `packaging`,
- derives the concrete Python minor bootstrap should provision, and
- prints that minor for `uv python install` and `uv venv --python`.

`Makefile` runs the helper through `uv run --python '>=3.11' --no-project --with packaging ...`,
so the helper no longer depends on system-installed parser modules or pip vendored copies.

## Why this design exists

The design tries to solve a few practical problems at once:

- keep the required Python version in one canonical place,
- avoid hardcoding interpreter versions in `Makefile`,
- let bootstrap work both inside and outside the devcontainer,
- use `uv` as the single installer frontend for repo-managed workflows,
- and keep the shell layer small enough to debug quickly.

In short, `Makefile` owns the workflow and user messages, while the helper owns
the Python-specific decision making.
