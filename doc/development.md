# Development setup

The repository keeps tool configuration in `pyproject.toml` and installs local developer tools into `.venv`.
Using the same local interpreter path makes VS Code, PyCharm, shell commands, and devcontainers behave the same way.
The bootstrap target reads the required Python version from `[project].requires-python` in `pyproject.toml`.
The active bootstrap path combines Makefile targets with `scripts/python_requires_helper.py`.
For the detailed bootstrap flow, see `doc/python-bootstrap.md`.

## Preferred local workflow

Run:

```bash
make bootstrap
```

What it does:

- Creates `.venv`
- Requires the exact Python minor version declared in `pyproject.toml`
- Uses `uv` to provision that version automatically when `uv` is installed but the host OS does not provide it
- Falls back to the matching system `pythonX.Y` or any `python3` that already satisfies `requires-python`
- Installs the locked developer dependencies from `requirements/test_requirements.txt`
- Installs the repository itself into `.venv` in editable mode so imports work without `PYTHONPATH`

The install-first part uses a minimal packaging configuration in `pyproject.toml` only so developer tools can install the repo into `.venv`.
This repository is not intended to be built or published as a release artifact.

If your machine does not have the required Python version, install `uv` first and then run `make bootstrap` again.
That keeps the repo requirement in one place without forcing every developer OS image to ship that interpreter.

## IDE setup

Use `.venv/bin/python` as the project interpreter in every IDE.

VS Code:

- Workspace settings already point at `.venv/bin/python`
- Python tools resolve imports from the active `.venv`
- The mypy extension reads the repo configuration from `pyproject.toml`

PyCharm:

- Set the project interpreter to `.venv/bin/python`
- The editable install makes the `eduid` packages available through the interpreter without extra source-root or `PYTHONPATH` tweaks

## Devcontainers

The devcontainer now runs the same bootstrap command:

```bash
make bootstrap
```

That means container and non-container development both use the same `.venv` layout and dependency installation path.
The container does not carry a separate interpreter override. VS Code reads the shared workspace interpreter path from `.vscode/settings.json`, and `make bootstrap` creates that `.venv` inside the container.
Because the repo is installed editable into `.venv`, local shells, IDEs, and the devcontainer all resolve imports through the same interpreter model.

The shared devcontainer configuration assumes only this repository is mounted.
If you intentionally want to develop against a sibling checkout of `pysaml2`, copy the mount from `.devcontainer/devcontainer.pysaml2.example.json` into your local devcontainer configuration before reopening the container and do not commit it as part of the repo default:

```json
"type=bind,source=${localWorkspaceFolder}/../pysaml2,target=/workspaces/pysaml2"
```

## Why the extra metadata exists

- `[build-system]` tells `pip` which backend to use when installing the repo editable from `pyproject.toml`
- `setuptools` is the backend that maps the `src` layout into the active `.venv`
- `src/eduid/py.typed` tells mypy and other type checkers that the installed `eduid` package ships inline type information

These settings exist to support a consistent local development environment. They do not mean the repository now has a release or publishing workflow.

## Daily commands

```bash
make test
make reformat
make lint
make typecheck
uvx ty check

# Run a focused test slice directly
pytest -vvv src/eduid/webapp/freja_eid/tests/test_app.py
```