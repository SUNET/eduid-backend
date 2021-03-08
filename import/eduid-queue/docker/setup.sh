#!/bin/bash
#
# Install all requirements
#

set -e
set -x

apt-get update
#apt-get -y install \

apt-get clean
rm -rf /var/lib/apt/lists/*

