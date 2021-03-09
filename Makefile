SOURCE=	src
PIPCOMPILE=	pip-compile --generate-hashes --extra-index-url https://pypi.sunet.se/simple

test:
	PYTHONPATH=$(abspath .)/src pytest --log-cli-level DEBUG

reformat:
	isort --line-width 120 --atomic --project eduid $(SOURCE)
	black --line-length 120 --target-version py38 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

typecheck_extra:
	mypy --ignore-missing-imports $(SOURCE)

update_translations:
	pybabel extract -k _ -k gettext -k ngettext --mapping=babel.cfg --width=120 --output=src/eduid/webapp/translations/messages.pot src/eduid/webapp/
	pybabel update --input-file=src/eduid/webapp/translations/messages.pot --output-dir=src/eduid/webapp/translations/ --ignore-obsolete
	$(info --- INFO ---)
	$(info Upload message.pot to Transifex, translate.)
	$(info Download for_use_X.po to translations/XX/LC_MESSAGES/messages.po.)
	$(info --- INFO ---)

compile_translations:
	pybabel compile --directory=src/eduid/webapp/translations/ --use-fuzzy

%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $<

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))
