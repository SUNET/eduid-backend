#!/bin/bash

# Activate virtual env and run command

set -e
source /opt/eduid/bin/activate
echo ""
echo "Exec:ing $@"
echo ""
exec $@

