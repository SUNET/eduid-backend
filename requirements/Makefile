PIPCOMPILE=	pip-compile -v --upgrade --generate-hashes --index-url https://pypi.sunet.se/simple

update_deps: main.txt $(patsubst %_requirements.in,%_requirements.txt,$(wildcard *_requirements.in))

main.txt: main.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) main.in

%_requirements.txt: main.in %_requirements.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $<
