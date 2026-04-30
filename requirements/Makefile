UV=$(shell which uv)
PROJECT_ROOT=..
PIPCOMPILE=$(UV) pip compile --upgrade --generate-hashes --no-strip-extras --index-url https://pypi.sunet.se/simple --emit-index-url --project $(PROJECT_ROOT)
PIPSYNC=$(UV) pip sync --index-url https://pypi.sunet.se/simple
PYPROJECT=$(PROJECT_ROOT)/pyproject.toml

update_deps: main.txt fastapi_requirements.txt satosa_scim_requirements.txt test_requirements.txt webapp_requirements.txt worker_requirements.txt

main.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) -o $@

fastapi_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --extra fastapi -o $@

satosa_scim_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --extra satosa-scim -o $@

test_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --all-extras --group test -o $@

webapp_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --extra webapp -o $@

worker_requirements.txt: $(PYPROJECT)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --extra worker -o $@

dev_sync_deps:
	@test $${VIRTUAL_ENV?virtual env not activated}
	$(PIPSYNC) test_requirements.txt
