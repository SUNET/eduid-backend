TOPDIR:=	$(abspath .)
SRCDIR=		$(TOPDIR)/src
SOURCE=		$(SRCDIR)/eduid
PIPCOMPILE=	pip-compile -v --generate-hashes --index-url https://pypi.sunet.se/simple

test:
	PYTHONPATH=$(SRCDIR) pytest -vvv -ra --log-cli-level DEBUG

reformat:
	isort --line-width 120 --atomic --project eduid $(SOURCE)
	black --line-length 120 --target-version py39 $(SOURCE)

typecheck:
	MYPYPATH=$(SRCDIR) mypy --ignore-missing-imports --namespace-packages -p eduid
        # a second pass with --check-untyped-defs, excluding test files
	MYPYPATH=$(SRCDIR) mypy --ignore-missing-imports --namespace-packages -p eduid --check-untyped-defs --exclude '/test_.*\.py$$'

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
	cd requirements && make update_deps

dev_sync_deps:
	cd requirements && make dev_sync_deps

kill_tests:
	@echo "Stopping all temporary instances started by tests"
	docker container stop $$(docker container ls -q --filter name=test_*)

vscode_hosts:
	rm -f /dev/shm/hosts
	sed '/localhost/ s/^#*/#/' /etc/hosts > /dev/shm/hosts
	echo "$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$$(hostname)") localhost" >> /dev/shm/hosts
	cat /dev/shm/hosts | sudo tee /etc/hosts
	rm -f /dev/shm/hosts

vscode_venv:
	python3 -m venv .venv

vscode_pip: vscode_venv
	.venv/bin/pip install -r requirements/test_requirements.txt

vscode_packages:
	sudo apt-get update
	sudo apt install -y swig xmlsec1 python3-venv docker.io

vscode_update: vscode_packages vscode_pip vscode_hosts
