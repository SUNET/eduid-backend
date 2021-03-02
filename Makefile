SOURCE=		src
EDUIDUSERDB=	../eduid-userdb/src
EDUIDAM=	../eduid-am/eduid_am
EDUIDMSG=	../eduid_msg/eduid_msg
PIPCOMPILE=	pip-compile --generate-hashes --extra-index-url https://pypi.sunet.se/simple


test:
	pytest

reformat:
	isort --line-width 120 --atomic --project eduid_common --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

typecheck_extra:
	mypy --ignore-missing-imports $(EDUIDUSERDB) $(EDUIDAM) $(EDUIDMSG) $(SOURCE)

%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< > $@

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))
