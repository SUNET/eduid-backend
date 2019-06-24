#!/bin/bash
#
# Run build commands that should never be docker-build cached
#

set -e
set -x

PYPI=${PYPI-'https://pypi.sunet.se/simple/'}

echo "#############################################################"
echo "$0: Using PyPi URL ${PYPI}"
echo "#############################################################"

/opt/eduid/bin/pip install --pre -i ${PYPI} /src/eduid-am

/opt/eduid/bin/pip freeze
