#!/bin/bash
#
# Run build commands that should never be docker-build cached
#

set -e
set -x

. /opt/eduid/bin/activate
cd /opt/eduid/eduid-queue/

PYPI="https://pypi.sunet.se/simple/"
pip install -i ${PYPI} .
pip freeze
