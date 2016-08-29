#!/bin/bash
#
# Run build commands that should never be docker-build cached
#

set -e
set -x

PYPI="https://pypi.nordu.net/simple/"
ping -c 1 -q pypiserver.docker && PYPI="http://pypiserver.docker:8080/simple/"

echo "#############################################################"
echo "$0: Using PyPi URL ${PYPI}"
echo "#############################################################"

/opt/eduid/bin/pip install --pre -i ${PYPI} 'eduid-am'
# eduid-api currently doesn't do attribute updating
#/opt/eduid/bin/pip install -i https://pypi.nordu.net/simple/ eduid-api-amp
/opt/eduid/bin/pip install --pre -i ${PYPI} eduid-signup-amp
/opt/eduid/bin/pip install --pre -i ${PYPI} eduid-dashboard-amp
/opt/eduid/bin/pip install --pre -i ${PYPI} eduid-proofing-amp
/opt/eduid/bin/pip install --pre -i ${PYPI} eduid_action.tou

/opt/eduid/bin/pip freeze
