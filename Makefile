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
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python

PYTEST_WORKERS ?= 2  # override with e.g. make test PYTEST_WORKERS=4; use 1 for serial fallback; avoid 'auto' (OOMs on large machines)
# --dist=loadgroup: tests with xdist_group("neo4j") all go to one worker; ungrouped tests are load-balanced.
# Do NOT use --dist=loadfile: xdist_group is only respected with loadgroup, not loadfile.

test:
	pytest -vvv -ra --log-cli-level DEBUG -n $(PYTEST_WORKERS) --dist=loadgroup

# Create a virtualenv with an interpreter that satisfies project.requires-python.
#
# Resolution order:
# 1. Ask the helper to pick the best compatible interpreter already visible on PATH.
# 2. If uv is installed, hand that exact interpreter path to uv so it can create
#    the environment directly.
# 3. Otherwise, re-check the selected executable immediately before use and build
#    the venv with the standard library venv module.
# 4. As a final fallback, try the generic python3/python launchers, but only if
#    they still satisfy requires-python when checked through the helper.
#
# The extra re-checks keep bootstrap conservative if PATH contents or pyproject
# change between Make variable expansion and target execution.
bootstrap_venv:
	@test -n "$(BOOTSTRAP_PYTHON)" || { echo "Could not find a compatible installed Python for requires-python in pyproject.toml" >&2; exit 1; }
	@if command -v uv >/dev/null; then \
		echo "Creating $(VENV) with uv using Python $(BOOTSTRAP_PYTHON)"; \
		uv venv --python "$(BOOTSTRAP_PYTHON)" $(VENV); \
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

reformat:
	# sort imports and remove unused imports
	ruff check --select F401,I --fix
	# reformat
	ruff format

lint:
	ruff check

typecheck:
	mypy --install-types --non-interactive --strict -p eduid

typecheck_strict: typecheck

update_webapp_translations:
	pybabel extract -k _ -k gettext -k ngettext --mapping=babel.cfg --width=120 --output=$(EDUID_SRCDIR)/webapp/translations/messages.pot $(EDUID_SRCDIR)/webapp/
	pybabel update --input-file=$(EDUID_SRCDIR)/webapp/translations/messages.pot --output-dir=$(EDUID_SRCDIR)/webapp/translations/ --ignore-obsolete
	$(info --- INFO ---)
	$(info Upload message.pot to Transifex, translate.)
	$(info Download for_use_X.po to webapp/translations/XX/LC_MESSAGES/messages.po.)
	$(info --- INFO ---)

compile_webapp_translations:
	pybabel compile --directory=$(EDUID_SRCDIR)/webapp/translations/ --use-fuzzy

update_queue_translations:
	pybabel extract -k _ -k gettext -k ngettext --mapping=babel.cfg --width=120 --output=$(EDUID_SRCDIR)/queue/translations/messages.pot $(EDUID_SRCDIR)/queue/
	pybabel update --input-file=$(EDUID_SRCDIR)/queue/translations/messages.pot --output-dir=$(EDUID_SRCDIR)/queue/translations/ --ignore-obsolete
	$(info --- INFO ---)
	$(info Upload message.pot to Transifex, translate.)
	$(info Download for_use_X.po to queue/translations/XX/LC_MESSAGES/messages.po.)
	$(info --- INFO ---)

compile_queue_translations:
	pybabel compile --directory=$(EDUID_SRCDIR)/queue/translations/ --use-fuzzy

update_deps:
	@echo "Updating ALL the dependencies"
	cd requirements && make update_deps

dev_sync_deps:
	cd requirements && make dev_sync_deps

clean:
	rm -rf .pytest_cache .coverage .mypy_cache .cache .eggs
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

kill_tests:
	@echo "Stopping all temporary instances started by tests"
	docker container stop $$(docker container ls -q --filter name=test_*)

sync_dev_files:
	test -n '$(DEV)' || exit 1
	fswatch -o src/eduid/ | while read n; do rsync -av --delete src/eduid/ eduid@eduid-developer-${DEV}-1.sunet.se:/opt/eduid/src/eduid-developer/sources/eduid-backend/src/eduid/; done
