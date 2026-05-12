## Resolve repository-relative paths once so every target uses the same base.
TOPDIR:=	$(abspath .)
SRCDIR=		$(TOPDIR)/src
EDUID_SRCDIR=	$(SRCDIR)/eduid

# The bootstrap helper uses Python 3.7+ syntax, parses requires-python, inspects
# installed interpreters, and selects the highest compatible Python executable on PATH.
PYTHON_REQUIRES_HELPER := $(TOPDIR)/scripts/python_requires_helper.py
# Use whichever generic Python launcher is already available so the helper can
# read pyproject.toml before the target interpreter has been selected.
PYTHON_FOR_PARSE := $(strip $(shell if command -v python3 >/dev/null; then printf '%s' python3; elif command -v python >/dev/null; then printf '%s' python; fi))
# The helper returns the exact executable path it probed, which avoids guessing
# names like python3.13 from a discovered version.
BOOTSTRAP_PYTHON := $(strip $(shell $(PYTHON_FOR_PARSE) $(PYTHON_REQUIRES_HELPER) select-from-pyproject $(TOPDIR)/pyproject.toml))
# When requires-python pins a single minor release, uv can provision it even if
# no compatible interpreter is installed yet.
BOOTSTRAP_PYTHON_MINOR := $(strip $(shell $(PYTHON_FOR_PARSE) $(PYTHON_REQUIRES_HELPER) minor-from-pyproject $(TOPDIR)/pyproject.toml 2>/dev/null))

# Keep the virtualenv path overridable so local setups and CI can share targets.
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python

PYTEST_WORKERS ?= 2  # override with e.g. make test PYTEST_WORKERS=4; use 1 for serial fallback; avoid 'auto' (OOMs on large machines)
# --dist=loadgroup: tests with xdist_group("neo4j") all go to one worker; ungrouped tests are load-balanced.
# Do NOT use --dist=loadfile: xdist_group is only respected with loadgroup, not loadfile.

# Default test entrypoint used locally and in CI reproductions.
test:
	pytest -vvv -ra --log-cli-level DEBUG -n $(PYTEST_WORKERS) --dist=loadgroup

# Create a virtualenv with an interpreter that satisfies project.requires-python.
#
# Resolution order:
# 1. Ask the helper to pick the best compatible interpreter already visible on PATH.
# 2. If uv is installed and no compatible interpreter is present, derive the
#    pinned Python minor release from pyproject.toml and let uv provision it.
# 3. Otherwise, re-check the selected executable immediately before use and build
#    the venv with the standard library venv module.
# 4. As a final fallback, try the generic python3/python launchers, but only if
#    they still satisfy requires-python when checked through the helper.
#
# The extra re-checks keep bootstrap conservative if PATH contents or pyproject
# change between Make variable expansion and target execution.
bootstrap_venv:
	@if command -v uv >/dev/null; then \
		if test -n "$(BOOTSTRAP_PYTHON)"; then \
			echo "Creating $(VENV) with uv using Python $(BOOTSTRAP_PYTHON)"; \
			uv venv --python "$(BOOTSTRAP_PYTHON)" $(VENV); \
		elif test -n "$(BOOTSTRAP_PYTHON_MINOR)"; then \
			echo "Creating $(VENV) with uv using Python $(BOOTSTRAP_PYTHON_MINOR) from pyproject.toml"; \
			uv python install "$(BOOTSTRAP_PYTHON_MINOR)"; \
			uv venv --python "$(BOOTSTRAP_PYTHON_MINOR)" $(VENV); \
		else \
			echo "Could not derive a concrete Python minor release from requires-python in pyproject.toml for uv provisioning" >&2; \
			exit 1; \
		fi; \
	elif test -x "$(BOOTSTRAP_PYTHON)" && "$(BOOTSTRAP_PYTHON)" $(PYTHON_REQUIRES_HELPER) check-from-pyproject $(TOPDIR)/pyproject.toml >/dev/null; then \
		echo "Creating $(VENV) with $(BOOTSTRAP_PYTHON)"; \
		"$(BOOTSTRAP_PYTHON)" -m venv $(VENV); \
	elif command -v python3 >/dev/null && python3 $(PYTHON_REQUIRES_HELPER) check-from-pyproject $(TOPDIR)/pyproject.toml >/dev/null; then \
		echo "Creating $(VENV) with python3"; \
		python3 -m venv $(VENV); \
	elif command -v python >/dev/null && python $(PYTHON_REQUIRES_HELPER) check-from-pyproject $(TOPDIR)/pyproject.toml >/dev/null; then \
		echo "Creating $(VENV) with python"; \
		python -m venv $(VENV); \
	else \
		echo "A Python compatible with requires-python in pyproject.toml is required. Install uv to provision it automatically, use the devcontainer, or install a compatible Python locally." >&2; \
		exit 1; \
	fi

# Install the locked development toolchain into the freshly created virtualenv.
#
# Steps:
# 1. Ensure pip exists inside the environment, using ensurepip when the venv was
#    created without it.
# 2. Upgrade pip first so dependency installation uses a recent installer.
# 3. Install the locked test/development requirements, preferring uv for speed
#    when available and falling back to pip otherwise.
# 4. Install this repository in editable mode without dependency resolution,
#    because the locked requirements already describe the environment.
# 5. Pre-install mypy stub packages interactively so later type checks do not
#    stop to ask for missing types.
bootstrap: bootstrap_venv
	$(info Installing locked development dependencies into $(VENV))
	@if ! $(VENV_PYTHON) -m pip --version >/dev/null; then \
		$(VENV_PYTHON) -m ensurepip --upgrade; \
	fi
	$(VENV_PYTHON) -m pip install --upgrade pip
	@if command -v uv >/dev/null; then \
		uv pip install --python $(VENV_PYTHON) -r requirements/test_requirements.txt; \
	else \
		$(VENV_PYTHON) -m pip install -r requirements/test_requirements.txt; \
	fi
	$(VENV_PYTHON) -m pip install --no-deps --no-build-isolation -e .
	$(VENV_PYTHON) -m mypy --install-types --non-interactive

# Reformat imports first, then apply Ruff's code formatter.
reformat:
	# sort imports and remove unused imports
	ruff check --select F401,I --fix
	# reformat
	ruff format

# Fast lint target for local checks and CI parity.
lint:
	ruff check

# Primary mypy entrypoint used by developers and CI.
typecheck:
	mypy --install-types --non-interactive --strict -p eduid

# Alias kept for tooling and developer muscle memory.
typecheck_strict: typecheck

# Refresh extracted webapp translation catalogs from source strings.
update_webapp_translations:
	pybabel extract -k _ -k gettext -k ngettext --mapping=babel.cfg --width=120 --output=$(EDUID_SRCDIR)/webapp/translations/messages.pot $(EDUID_SRCDIR)/webapp/
	pybabel update --input-file=$(EDUID_SRCDIR)/webapp/translations/messages.pot --output-dir=$(EDUID_SRCDIR)/webapp/translations/ --ignore-obsolete
	$(info --- INFO ---)
	$(info Upload message.pot to Transifex, translate.)
	$(info Download for_use_X.po to webapp/translations/XX/LC_MESSAGES/messages.po.)
	$(info --- INFO ---)

# Compile webapp PO files into MO files for runtime use.
compile_webapp_translations:
	pybabel compile --directory=$(EDUID_SRCDIR)/webapp/translations/ --use-fuzzy

# Refresh queue worker translation catalogs from source strings.
update_queue_translations:
	pybabel extract -k _ -k gettext -k ngettext --mapping=babel.cfg --width=120 --output=$(EDUID_SRCDIR)/queue/translations/messages.pot $(EDUID_SRCDIR)/queue/
	pybabel update --input-file=$(EDUID_SRCDIR)/queue/translations/messages.pot --output-dir=$(EDUID_SRCDIR)/queue/translations/ --ignore-obsolete
	$(info --- INFO ---)
	$(info Upload message.pot to Transifex, translate.)
	$(info Download for_use_X.po to queue/translations/XX/LC_MESSAGES/messages.po.)
	$(info --- INFO ---)

# Compile queue PO files into MO files for runtime use.
compile_queue_translations:
	pybabel compile --directory=$(EDUID_SRCDIR)/queue/translations/ --use-fuzzy

# Delegate dependency lockfile regeneration to the requirements sub-make.
update_deps:
	@echo "Updating ALL the dependencies"
	cd requirements && make update_deps

# Sync development dependencies from the compiled lockfiles.
dev_sync_deps:
	cd requirements && make dev_sync_deps

# Remove caches and Python build artefacts produced by local development.
clean:
	rm -rf .pytest_cache .coverage .mypy_cache .cache .eggs
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

# Stop leftover Docker containers created by the test suite bootstrap.
kill_tests:
	@echo "Stopping all temporary instances started by tests"
	docker container stop $$(docker container ls -q --filter name=test_*)

# Continuously mirror local source changes to a remote developer environment.
# Requires DEV to select the destination host suffix.
sync_dev_files:
	test -n '$(DEV)' || exit 1
	fswatch -o src/eduid/ | while read n; do rsync -av --delete src/eduid/ eduid@eduid-developer-${DEV}-1.sunet.se:/opt/eduid/src/eduid-developer/sources/eduid-backend/src/eduid/; done
