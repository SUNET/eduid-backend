#!/bin/bash

set -e

# APT dependencys for eduid_msg
apt-get update
apt-get -y install \
    libxml2-dev \
    libxslt-dev \
    zlib1g-dev \
    locales  # tmp test
apt-get clean
rm -rf /var/lib/apt/lists/*

# tmp test
locale-gen en_US.UTF-8
