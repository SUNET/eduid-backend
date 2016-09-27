#!/bin/bash
#
# Run build commands that should never be docker-build cached
#

set -e
set -x

cd /opt/eduid/eduid-webapp/

PYPI="https://pypi.nordu.net/simple/"
/opt/eduid/bin/pip install -i ${PYPI} -r requirements/prod.txt

/opt/eduid/bin/pip freeze
