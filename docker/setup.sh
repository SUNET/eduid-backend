#!/bin/bash
#
# Install all requirements
#

set -e
set -x

apt-get update
apt-get -y install \
    libffi-dev \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libssl-dev \
    libtiff5-dev \
    libxml2-dev \
    libxml2-utils
    libxslt1-dev \
    xmlsec1 \
    zlib1g-dev

apt-get clean
rm -rf /var/lib/apt/lists/*

