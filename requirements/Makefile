UV=$(shell which uv)
PROJECT_ROOT=..
PIPCOMPILE=$(UV) pip compile --upgrade --generate-hashes --no-strip-extras --index-url https://pypi.sunet.se/simple --emit-index-url --project $(PROJECT_ROOT)
PIPSYNC=$(UV) pip sync --index-url https://pypi.sunet.se/simple
PYPROJECT=$(PROJECT_ROOT)/pyproject.toml
CONSTRAINTS=constraints.txt

update_deps: sub_main.txt main.txt fastapi_requirements.txt satosa_scim_requirements.txt test_requirements.txt webapp_requirements.txt worker_requirements.txt

main.txt: $(PYPROJECT) $(CONSTRAINTS)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --group sub_main -c $(CONSTRAINTS) -o $@

sub_main.txt: $(PYPROJECT) $(CONSTRAINTS)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) --group sub_main -c $(CONSTRAINTS) -o $@

fastapi_requirements.txt: $(PYPROJECT) $(CONSTRAINTS)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --group sub_main --extra fastapi -c $(CONSTRAINTS) -o $@

satosa_scim_requirements.txt: $(PYPROJECT) $(CONSTRAINTS)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --group sub_main --extra satosa-scim -c $(CONSTRAINTS) -o $@

test_requirements.txt: $(PYPROJECT) $(CONSTRAINTS)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --group sub_main --all-extras --group test -c $(CONSTRAINTS) -o $@

webapp_requirements.txt: $(PYPROJECT) $(CONSTRAINTS)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --group sub_main --extra webapp -c $(CONSTRAINTS) -o $@

worker_requirements.txt: $(PYPROJECT) $(CONSTRAINTS)
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $(PYPROJECT) --group sub_main --extra worker -c $(CONSTRAINTS) -o $@

dev_sync_deps:
	@test $${VIRTUAL_ENV?virtual env not activated}
	$(PIPSYNC) test_requirements.txt
