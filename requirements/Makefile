VIRTUALENV=$VIRTUALENV
PIPCOMPILE=uv pip compile --upgrade --generate-hashes --no-strip-extras --index-url https://pypi.sunet.se/simple
PIPSYNC=uv pip sync --index-url https://pypi.sunet.se/simple

update_deps: sub_main.txt main.txt $(patsubst %_requirements.in,%_requirements.txt,$(wildcard *_requirements.in))

main.txt: sub_main.in main.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) main.in -o $@

sub_main.txt: sub_main.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) sub_main.in -o $@

%_requirements.txt: %_requirements.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< -o $@

dev_sync_deps:
ifndef VIRTUALENV
	echo "Not in a virtualenv, aborting."
	false
endif
	$(PIPSYNC) test_requirements.txt
