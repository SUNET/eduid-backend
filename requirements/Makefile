PIPCOMPILE=	pip-compile -v --upgrade --generate-hashes --index-url https://pypi.sunet.se/simple

update_deps: main.txt sub_main.txt $(patsubst %_requirements.in,%_requirements.txt,$(wildcard *_requirements.in))

main.txt: main.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) main.in

sub_main.txt: sub_main.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) sub_main.in

%_requirements.txt: %_requirements.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $<
