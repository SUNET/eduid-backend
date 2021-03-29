TOPDIR:=	$(abspath .)
SRCDIR=		$(TOPDIR)/src
SOURCE=		$(SRCDIR)/eduid
PIPCOMPILE=	pip-compile -v --generate-hashes --index-url https://pypi.sunet.se/simple

test:
	PYTHONPATH=$(SRCDIR) pytest -vvv -ra --log-cli-level DEBUG

reformat:
	isort --line-width 120 --atomic --project eduid $(SOURCE)
	black --line-length 120 --target-version py38 --skip-string-normalization $(SOURCE)

typecheck:
	MYPYPATH=$(SRCDIR) mypy --ignore-missing-imports --namespace-packages -p eduid

update_translations:
	pybabel extract -k _ -k gettext -k ngettext --mapping=babel.cfg --width=120 --output=$(SOURCE)/webapp/translations/messages.pot $(SOURCE)/webapp/
	pybabel update --input-file=$(SOURCE)/webapp/translations/messages.pot --output-dir=$(SOURCE)/webapp/translations/ --ignore-obsolete
	$(info --- INFO ---)
	$(info Upload message.pot to Transifex, translate.)
	$(info Download for_use_X.po to translations/XX/LC_MESSAGES/messages.po.)
	$(info --- INFO ---)

compile_translations:
	pybabel compile --directory=$(SOURCE)/webapp/translations/ --use-fuzzy

update_deps:
	cd requirements && make all
