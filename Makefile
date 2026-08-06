## Resolve repository-relative paths once so every target uses the same base.
TOPDIR:=	$(abspath .)
SRCDIR=		$(TOPDIR)/src
EDUID_SRCDIR=	$(SRCDIR)/eduid

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
# Bootstrap requires a globally available uv executable and lets uv resolve the
# interpreter directly from pyproject.toml.
bootstrap_venv:
	@if ! command -v uv >/dev/null; then \
		echo "uv is required for bootstrap. Install uv, or use the devcontainer image that includes it." >&2; \
		exit 1; \
	fi
	@echo "Creating $(VENV) with uv using requires-python from pyproject.toml"
	uv venv $(VENV)

# Install the locked development toolchain into the freshly created virtualenv.
#
# Steps:
# 1. Install the locked test/development requirements with uv pip.
# 2. Install this repository in editable mode without dependency resolution,
#    because the locked requirements already describe the environment.
# 3. Run mypy with explicitly pinned stub packages already present in the
#    environment, so type checking stays non-interactive.
bootstrap: bootstrap_venv
	$(info Installing locked development dependencies into $(VENV))
	uv pip install --python $(VENV_PYTHON) -r requirements/test_requirements.txt
	uv pip install --python $(VENV_PYTHON) --no-deps --no-build-isolation -e .
	$(VENV_PYTHON) -m mypy --strict -p eduid

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
	mypy --strict -p eduid

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
