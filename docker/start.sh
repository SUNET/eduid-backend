#!/bin/sh

set -e
set -x

# activate python virtualenv
. /opt/eduid/bin/activate

# These could be set from Puppet if multiple instances are deployed
eduid_name=${eduid_name-'eduid-msg'}
eduid_queue=${eduid_queue-'msg'}
# this is a Python module name, so can't have hyphen (also name of .ini file)
app_name=$(echo $eduid_name | tr "-" "_")
base_dir=${base_dir-"/opt/eduid/${eduid_name}"}
# These *can* be set from Puppet, but are less expected to...
log_dir=${log_dir-'/var/log/eduid'}
logfile=${logfile-"${log_dir}/${eduid_name}.log"}

chown eduid: "${log_dir}"

# || true to not fail on read-only cfg_dir
chgrp eduid "${ini}" || true
chmod 640 "${ini}" || true

celery_args=${celery_args-'--loglevel INFO'}
if [ -f /opt/eduid/src/setup.py ]; then
    celery_args='--loglevel DEBUG'
else
    if [ -f "${cfg_dir}/${app_name}_DEBUG" ]; then
	# eduid-dev environment
	celery_args='--loglevel DEBUG'
    fi
fi

echo "$0: Starting Celery app '${app_name}' (queue: ${eduid_queue})"
exec celery worker --app="${app_name}.worker" -Q ${eduid_queue} --events \
     --uid eduid --gid eduid --logfile="${logfile}" \
    $celery_args
