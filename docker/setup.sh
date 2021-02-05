#!/bin/bash
#
# Install all requirements
#

set -e
set -x

export DEBIAN_FRONTEND noninteractive

apt-get -y update && apt-get -y install \
    git \
    curl \
    python3-pip \
    python3.7-venv

apt-get clean
rm -rf /var/lib/apt/lists/*

