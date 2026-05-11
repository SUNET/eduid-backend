# eduID Backend

eduID Backend is a Python 3.13 monorepo for Swedish federated identity management.
It contains Flask web applications, FastAPI services, Celery workers, SATOSA plugins, and shared libraries.

This repository is configured for development convenience.
It is not intended to be built or published as a release artifact from this checkout.

## Development Installation

The supported local workflow is install-first:

1. Create a local virtual environment in `.venv`
2. Install the locked developer dependencies
3. Install the repository itself into `.venv` in editable mode

That makes shells, IDEs, tests, and type checkers resolve imports through the active interpreter without `PYTHONPATH` tweaks.

### Requirements

- A Unix-like environment or devcontainer
- Docker, for the test suite and local service dependencies
- Python 3.13 locally, or `uv` if your host OS does not provide Python 3.13

### Quick Start

From the repository root, run:

```bash
make bootstrap
```

What this does:

- Creates `.venv`
- Reads the required Python version from `pyproject.toml`
- Uses `uv` to provision Python 3.13 automatically when available
- Falls back to a compatible local `python3` or `python`
- Installs the locked dependencies from `requirements/test_requirements.txt`
- Installs the repo itself into `.venv` with `pip install -e .`

If your machine does not already have Python 3.13, install `uv` and rerun `make bootstrap`.

For a detailed explanation of the bootstrap flow, see
[doc/python-bootstrap.md](doc/python-bootstrap.md).

## Using The Environment

Use `.venv/bin/python` as the interpreter in your IDE.

- VS Code: the workspace settings already point to `.venv/bin/python`
- PyCharm: set the project interpreter to `.venv/bin/python`
- Devcontainer: opening the repo in the devcontainer runs the same `make bootstrap` flow

The shared devcontainer configuration assumes only this repository is present.
If you need to develop against a sibling checkout of `pysaml2`, copy the mount from `.devcontainer/devcontainer.pysaml2.example.json` into your local devcontainer configuration before reopening the container and keep it out of committed changes:

```json
"type=bind,source=${localWorkspaceFolder}/../pysaml2,target=/workspaces/pysaml2"
```

## Daily Commands

```bash
make test
make reformat
make lint
make typecheck
uvx ty check

# Example focused test run
pytest -vvv src/eduid/webapp/freja_eid/tests/test_app.py
```

Tests require Docker services such as MongoDB, Redis, Neo4j, and SMTP.
If stale test containers are left behind, run:

```bash
make kill_tests
```

## Why `pyproject.toml` Has Packaging Metadata

The repository includes minimal packaging metadata only to support editable local installs.

- `[build-system]` tells `pip` which backend to use for `pip install -e .`
- `setuptools` maps the `src` layout into the active `.venv`
- `src/eduid/py.typed` tells mypy and similar tools that the installed package includes inline type information

This does not mean the repo now has a publishing workflow.

## More Detail

See [doc/development.md](doc/development.md) for the fuller development guide.