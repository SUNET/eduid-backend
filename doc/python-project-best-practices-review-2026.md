# Python Project Best Practices Review (2026)

Repository: `SUNET/eduid-backend`

Review date: 2026-09-02

## Scope

This review compares the repository against 2026 best practices for a production Python backend project, with emphasis on:

- dependency and environment reproducibility
- CI parity and quality gates
- packaging and release metadata
- supply-chain and security posture
- developer ergonomics for a large monorepo

The review is grounded in repository code and live command checks, not only documentation.

## Executive Summary

This repository is stronger than the average Python backend on reproducibility and development-environment consistency. It uses a modern [pyproject.toml](../pyproject.toml) source of truth, hashed compiled lockfiles in [requirements/](../requirements/), `uv`-based bootstrap in [Makefile](../Makefile), a `src/` layout, a devcontainer, and CI-backed lint, typecheck, and test jobs.

The main gaps are concentrated in the harder 2026 concerns:

1. supply-chain hardening is incomplete
2. package version provenance is weak
3. some local commands depend on the documented active-virtualenv workflow
4. CI does not yet enforce the full stated quality bar
5. coverage and security automation are present but remain below a best-in-class baseline

## Findings

### 1. High: supply-chain hardening is below a 2026 best-practice baseline

What is good:

- The project compiles lockfiles with hashes from a single source of truth in [requirements/Makefile](../requirements/Makefile).
- CI and local bootstrap are aligned around [pyproject.toml](../pyproject.toml) and compiled requirements.

What is missing or risky:

- The dependency metadata includes a vendor-specific `pysaml2` build in [pyproject.toml](../pyproject.toml).
- The FastAPI dependency set includes a direct GitHub archive dependency for `pyhsm` in [pyproject.toml](../pyproject.toml).
- There is no visible SBOM generation, dependency-vulnerability audit job, or dependency-update automation such as Dependabot or Renovate in repository automation.

Why this matters in 2026:

- Best practice has shifted toward immutable internal artifacts, provenance-aware package flows, and continuous dependency scanning.
- Archive URLs are harder to attest, cache, mirror, and triage during incident response.

Assessment:

- Good lock discipline.
- Not yet strong enough artifact governance.

### 2. Medium-high: package version provenance is weak

What I found:

- The project declares `dynamic = ["version"]` in [pyproject.toml](../pyproject.toml).
- There is no visible version-source wiring such as `setuptools_scm`, a generated version module, or a `tool.setuptools.dynamic` declaration in [pyproject.toml](../pyproject.toml).
- [src/eduid/__init__.py](../src/eduid/__init__.py) is empty.
- A live metadata check in the existing virtual environment reported the installed package version as `0.0.0`.

Why this matters in 2026:

- Release provenance, SBOM correlation, forensic debugging, and rollback workflows all benefit from accurate, machine-readable package version identity.
- `0.0.0` is acceptable only as a temporary bootstrap state, not as a stable project standard.

Assessment:

- Packaging metadata exists and supports editable installs.
- Traceable version identity is not yet robust.

### 3. Medium: the secondary type-checking story is incomplete

What I found:

- The project includes `ty` configuration in [pyproject.toml](../pyproject.toml).
- The configuration explicitly describes `ty` as something the project is trying out.
- Several `ty` rule classes are ignored in [pyproject.toml](../pyproject.toml).
- CI runs mypy and Ruff, but does not run `ty`; see [run-tests.yaml](../.github/workflows/run-tests.yaml).
- [README.md](../README.md) presents `uvx ty check` as a normal daily command.

Why this matters in 2026:

- If `ty` is part of the real quality bar, it should be enforced in CI.
- If it is exploratory, the repository should label it clearly as non-blocking and avoid implying stronger guarantees than it provides.

Assessment:

- Good experimentation.
- Unclear enforcement boundary.

### 4. Medium: coverage is configured but not operationalized as a maintained gate

What is good:

- Coverage is configured with branch tracking in [pyproject.toml](../pyproject.toml).
- Coverage source scoping and report exclusions are defined in [pyproject.toml](../pyproject.toml).

What is missing:

- CI runs tests, but there is no visible coverage reporting, changed-code coverage, or minimum-threshold enforcement in [run-tests.yaml](../.github/workflows/run-tests.yaml).

Why this matters in 2026:

- For a large auth-heavy backend, branch coverage without reporting or gating is only partial value.
- Modern teams usually want at least trend visibility and PR-level feedback.

Assessment:

- Configuration exists.
- Governance around that data is incomplete.

### 5. Medium: GitHub Actions hardening is incomplete

What is good:

- The workflow pins `astral-sh/setup-uv` by commit SHA in [run-tests.yaml](../.github/workflows/run-tests.yaml).
- The lint workflow also pins `astral-sh/ruff-action` by commit SHA in [run-tests.yaml](../.github/workflows/run-tests.yaml).
- CodeQL is enabled in [codeql-analysis.yml](../.github/workflows/codeql-analysis.yml).

What is missing:

- Several actions float on major tags, including `actions/checkout`, `actions/setup-python`, and the CodeQL actions; see [run-tests.yaml](../.github/workflows/run-tests.yaml) and [codeql-analysis.yml](../.github/workflows/codeql-analysis.yml).

Why this matters in 2026:

- Full SHA pinning is increasingly standard for high-trust CI pipelines.
- Floating major tags remain common, but they are not the stronger option.

Assessment:

- Better than many repos.
- Not yet hardened to the level many security-conscious teams now expect.

### 6. Low: local commands depend on the documented active-virtualenv workflow

What is good:

- The project has clear top-level targets in [Makefile](../Makefile): `test`, `bootstrap`, `reformat`, `lint`, and `typecheck`.
- `make lint` passed in a live run.
- After activating the project virtual environment, `make typecheck` also passed in a live run.
- The repository documentation explicitly defines `.venv` as the supported local workflow in [README.md](../README.md), [doc/development.md](../doc/development.md), and [doc/python-bootstrap.md](../doc/python-bootstrap.md).

What I found:

- The supported local workflow assumes the repository virtualenv is active when running day-to-day commands.
- `bootstrap` runs mypy via the virtualenv interpreter in [Makefile](../Makefile), while `typecheck` runs bare `mypy` and therefore depends on the selected environment.
- Outside the documented `.venv` workflow, the `typecheck` target is not self-contained.

Why this matters in 2026:

- This is not a correctness problem under the repository's supported workflow.
- It is mainly an ergonomics question: some teams prefer top-level checks to be self-contained even when the project standardizes on an active virtualenv.

Assessment:

- The documented `.venv` contract is coherent and works.
- A more hermetic `typecheck` target would be a convenience improvement, not a prerequisite for a valid local workflow.

## Strengths

The repository does several important things well.

### Reproducibility and environment design

- Python version policy is explicit in [pyproject.toml](../pyproject.toml).
- Dependency groups are defined in [pyproject.toml](../pyproject.toml).
- Compiled, hashed lockfiles are generated from [pyproject.toml](../pyproject.toml) in [requirements/Makefile](../requirements/Makefile).
- The bootstrap flow is install-first and editable-install friendly.

### Packaging fundamentals

- The project uses a `src/` layout declared in [pyproject.toml](../pyproject.toml).
- Package discovery is explicit in [pyproject.toml](../pyproject.toml).
- Typed-package metadata is declared in [pyproject.toml](../pyproject.toml).

### Tooling alignment across local and CI

- Shared system package requirements are centralized in [.github/repo-system-packages.sh](../.github/repo-system-packages.sh).
- The devcontainer mirrors CI package assumptions in [.devcontainer/Dockerfile](../.devcontainer/Dockerfile).
- The devcontainer bootstraps the project environment automatically in [.devcontainer/devcontainer.json](../.devcontainer/devcontainer.json).

### Code quality baseline

- Ruff, mypy, pytest, and coverage configuration are consolidated in [pyproject.toml](../pyproject.toml).
- Linting passes in a live run.
- The mypy target passes once the intended project environment is active, which matches the documented local workflow.

## Validation Performed

The following checks were run during this review:

- `make lint` from the repository root: passed
- `. .venv/bin/activate && make typecheck`: passed with `Success: no issues found in 819 source files`
- `.venv/bin/python -c "import importlib.metadata as m; print(m.version('eduid-backend'))"`: returned `0.0.0`
- `uvx ty check`: could not be completed in this session because the local `uvx` invocation failed with a snap-confine/AppArmor environment error before the type checker could run

## Prioritized Remediation Checklist

### Quick wins

- Decide whether `ty` is experimental or required, then reflect that consistently in [README.md](../README.md), [Makefile](../Makefile), and CI.
- Pin the major-tag GitHub Actions by commit SHA.
- Add a visible dependency-audit job to CI.

### This quarter

- Replace the direct `pyhsm` GitHub archive dependency with a controlled internal artifact or published immutable wheel source.
- Define a real versioning strategy, such as `setuptools_scm` or a generated version module tied to tags or commits.
- Add CI coverage reporting with at least non-blocking PR visibility.
- Add dependency update automation with policy controls.
- Clarify which checks are advisory and which are merge-blocking.

### Longer-term

- Generate and publish SBOM artifacts for release and CI builds.
- Add provenance or attestation support for build artifacts if the release process expands.
- Consider tighter policy around internal mirrors, provenance, and artifact retention for all non-PyPI dependencies.
- Expand security automation beyond CodeQL into dependency and container or image scanning.

## Follow-up Workstreams

### 1. Priority implementation track

Highest-value code and tooling fixes to implement first:

- align [README.md](../README.md), [Makefile](../Makefile), and CI on the actual supported workflow
- add missing CI parity for any check that is meant to be required
- introduce an explicit project version source

Expected outcome:

- developers get predictable one-command checks
- the published workflow matches reality
- CI and local expectations stop drifting

### 2. Supply-chain and security posture track

Focused follow-up review and remediation scope:

- inventory external package sources and trust boundaries
- remove or quarantine archive URL dependencies
- add dependency-vulnerability scanning and update automation
- pin all GitHub Actions and review workflow permissions
- add SBOM and provenance planning where appropriate

Expected outcome:

- stronger artifact integrity and better incident response posture

### 3. Governance and maintainability track

Focused follow-up review and remediation scope:

- formalize versioning strategy
- define required versus advisory quality gates
- introduce coverage reporting policy
- document release and build expectations in one authoritative place

Expected outcome:

- clearer standards, less local knowledge, better long-term maintainability

## Bottom Line

This repository is ahead of many Python backends in environment reproducibility and tooling consolidation. The gap to a 2026 best-practice baseline is mostly about hardening and enforcement, not about adopting the basics.

If the project closes the hermetic task gap, establishes a real version source, and tightens supply-chain and CI controls, it would move from strong internal engineering hygiene to something much closer to a modern best-in-class backend baseline.