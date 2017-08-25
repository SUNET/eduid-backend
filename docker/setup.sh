#!/bin/bash
#
# Install all requirements
#

set -e
set -x

apt-get update
apt-get -y dist-upgrade
apt-get -y install \
    libffi-dev \
    libtiff5-dev \
    libjpeg62-turbo-dev \
    zlib1g-dev \
    libfreetype6-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    xmlsec1 \
    libxml2-utils

apt-get clean
rm -rf /var/lib/apt/lists/*

