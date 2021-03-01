SOURCE=	eduid_am
EDUIDCOMMON= ../eduid-common/src
EDUIDUSERDB= ../eduid-userdb/src

test:
	pytest

reformat:
	isort --line-width 120 --atomic --project eduid_am --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

typecheck_extra:
	mypy --ignore-missing-imports $(EDUIDCOMMON) $(EDUIDUSERDB) $(SOURCE)

requirements.txt:: requirements.in
	CUSTOM_COMPILE_COMMAND="make $@" pip-compile --extra-index-url https://pypi.sunet.se/simple < $< > $@

test_requirements.txt:: test_requirements.in
	CUSTOM_COMPILE_COMMAND="make $@" pip-compile --extra-index-url https://pypi.sunet.se/simple < $< > $@
