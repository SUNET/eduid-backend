#!/bin/bash

set -e

apt-get update
apt-get -u dist-upgrade
apt-get clean
rm -rf /var/lib/apt/lists/*
