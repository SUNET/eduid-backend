#!/bin/bash
#
# Install all requirements
#

set -e
set -x

apt-get update
apt-get -y dist-upgrade
apt-get -y install \
    git \
    libffi-dev \
    libtiff5-dev \
    libjpeg8-dev \
    zlib1g-dev \
    libfreetype6-dev \
    libssl-dev

apt-get clean
rm -rf /var/lib/apt/lists/*

