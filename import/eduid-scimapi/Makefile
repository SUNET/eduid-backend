SOURCE=		src test-scripts
PIPCOMPILE=	pip-compile -v --generate-hashes --extra-index-url https://pypi.sunet.se/simple

reformat:
	isort --line-width 120 --atomic --project eduid_scimapi --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

test:
	pytest

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< > $@

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))
