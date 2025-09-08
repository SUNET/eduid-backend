TOPDIR:=	$(abspath .)
SRCDIR=		$(TOPDIR)/src
SOURCE=		$(SRCDIR)/eduid
MYPY_ARGS=	--install-types --non-interactive --pretty --ignore-missing-imports \
			--warn-unused-ignores \
			# --disallow-untyped-decorators
MYPY_STRICT= --strict \
			 --implicit-reexport \
			 --allow-untyped-calls

test:
	PYTHONPATH=$(SRCDIR) pytest -vvv -ra --log-cli-level DEBUG

reformat:
	# sort imports and remove unused imports
	ruff check --select F401,I --fix
	# reformat
	ruff format
	# make an extended check with rules that might be triggered by reformat
	ruff check --config ruff-extended.toml

lint:
	ruff check

typecheck:
	MYPYPATH=$(SRCDIR) mypy $(MYPY_ARGS) --namespace-packages -p eduid
	MYPYPATH=$(SRCDIR) mypy $(MYPY_ARGS) --namespace-packages -p eduid --check-untyped-defs --exclude '/test_.*\.py$$'

typecheck_strict:
	$(info Running mypy in semi-strict mode (not enforced in the build pipeline yet))
	MYPYPATH=$(SRCDIR) mypy $(MYPY_ARGS) $(MYPY_STRICT) --namespace-packages -p eduid \
		 				--allow-untyped-defs
        # a second pass with --strict (minus some things we're not ready for yet), excluding test files
	MYPYPATH=$(SRCDIR) mypy $(MYPY_ARGS) $(MYPY_STRICT) --namespace-packages -p eduid --check-untyped-defs --exclude '/test_.*\.py$$'

update_webapp_translations:
	pybabel extract -k _ -k gettext -k ngettext --mapping=babel.cfg --width=120 --output=$(SOURCE)/webapp/translations/messages.pot $(SOURCE)/webapp/
	pybabel update --input-file=$(SOURCE)/webapp/translations/messages.pot --output-dir=$(SOURCE)/webapp/translations/ --ignore-obsolete
	$(info --- INFO ---)
	$(info Upload message.pot to Transifex, translate.)
	$(info Download for_use_X.po to webapp/translations/XX/LC_MESSAGES/messages.po.)
	$(info --- INFO ---)

compile_webapp_translations:
	pybabel compile --directory=$(SOURCE)/webapp/translations/ --use-fuzzy

update_queue_translations:
	pybabel extract -k _ -k gettext -k ngettext --mapping=babel.cfg --width=120 --output=$(SOURCE)/queue/translations/messages.pot $(SOURCE)/queue/
	pybabel update --input-file=$(SOURCE)/queue/translations/messages.pot --output-dir=$(SOURCE)/queue/translations/ --ignore-obsolete
	$(info --- INFO ---)
	$(info Upload message.pot to Transifex, translate.)
	$(info Download for_use_X.po to queue/translations/XX/LC_MESSAGES/messages.po.)
	$(info --- INFO ---)

compile_queue_translations:
	pybabel compile --directory=$(SOURCE)/queue/translations/ --use-fuzzy

update_deps:
	@echo "Updating ALL the dependencies"
	touch requirements/*.in
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

vscode_hosts:
	# tests connect to mongodb etc. on "localhost", so we have to point that name at the docker gateway
	rm -f /dev/shm/hosts
	sed '/localhost/ s/^#*/#/' /etc/hosts > /dev/shm/hosts
	echo "$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$$(hostname)") localhost" >> /dev/shm/hosts
	cat /dev/shm/hosts | sudo tee /etc/hosts
	rm -f /dev/shm/hosts

vscode_venv:
	$(info Creating virtualenv in devcontainer)
	python3 -m venv .venv

vscode_pip: vscode_venv
	$(info Installing pip packages in devcontainer)
	.venv/bin/pip install uv
	.venv/bin/uv pip install -r requirements/test_requirements.txt
	.venv/bin/mypy --install-types

sync_dev_files:
	test -n '$(DEV)' || exit 1
	fswatch -o src/eduid/ | while read n; do rsync -av --delete src/eduid/ eduid@eduid-developer-${DEV}-1.sunet.se:/opt/eduid/src/eduid-developer/sources/eduid-backend/src/eduid/; done

# This target is used by the devcontainer.json to configure the devcontainer
vscode:  vscode_pip 
