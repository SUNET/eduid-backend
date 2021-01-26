#!/bin/bash

set -e
set -x

. /opt/eduid/bin/activate

# These could be set from Puppet if multiple instances are deployed
eduid_name=${eduid_name-'eduid-vccs'}
base_dir=${base_dir-"/opt/eduid/${eduid_name}"}
# These *can* be set from Puppet, but are less expected to...
log_dir=${log_dir-'/var/log/eduid'}
run=${run-'/opt/eduid/VCCS2/src/vccs/server/run.py'}
yhsm_device=${yhsm_device-'/dev/ttyACM0'}

chown -R eduid: "${log_dir}" "${yhsm_device}"

if [ -r /opt/eduid/src/vccs/server/run.py ]; then
    run=/opt/eduid/src/vccs/server/run.py
fi
# nice to have in docker run output, to check what
# version of something is actually running.
/opt/eduid/bin/pip freeze

echo ""
echo "$0: Starting ${run}"
exec start-stop-daemon --start --quiet -c eduid:eduid \
     --pidfile "${state_dir}/${eduid_name}.pid" --make-pidfile \
     --exec /opt/eduid/bin/python3 -- $run
