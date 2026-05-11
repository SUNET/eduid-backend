## Resolve the uv executable once so the targets share the same installer frontend.
UV=$(shell which uv)

# All lockfile generation is anchored to the repository root pyproject metadata.
PROJECT_ROOT=..
PYPROJECT=$(PROJECT_ROOT)/pyproject.toml

# Common uv wrappers for lockfile compilation and environment syncing.
# The compile flags preserve hashes and extras in the generated lockfiles.
PIPCOMPILE=$(UV) pip compile --upgrade --generate-hashes --no-strip-extras --index-url https://pypi.sunet.se/simple --emit-index-url --project $(PROJECT_ROOT)
PIPSYNC=$(UV) pip sync --index-url https://pypi.sunet.se/simple

# Regenerate every compiled requirements file from the single pyproject source of truth.
update_deps: main.txt fastapi_requirements.txt satosa_scim_requirements.txt test_requirements.txt webapp_requirements.txt worker_requirements.txt

# Base dependency set used by the repository.
main.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) -o $@

# Dependencies for FastAPI-based applications and services.
fastapi_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --extra fastapi -o $@

# Dependencies for the SATOSA SCIM integration.
satosa_scim_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --extra satosa-scim -o $@

# Full test and development environment, including all extras used in tests.
test_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --all-extras --group test -o $@

# Dependencies needed by the Flask webapp components.
webapp_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --extra webapp -o $@

# Dependencies needed by worker processes and background jobs.
worker_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --extra worker -o $@

# Synchronize an already-activated virtualenv to the compiled test requirements.
dev_sync_deps:
	@test $${VIRTUAL_ENV?virtual env not activated}
	$(PIPSYNC) test_requirements.txt
