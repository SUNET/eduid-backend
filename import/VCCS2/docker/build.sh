#!/bin/bash
#
# Run build commands that should never be docker-build cached
#

set -e
set -x

PYPI="https://pypi.sunet.se/simple/"
/opt/eduid/bin/pip install -i ${PYPI} -r requirements.txt

/opt/eduid/bin/pip freeze
