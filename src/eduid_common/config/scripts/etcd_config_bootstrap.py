#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Write contents from a YAML file with eduid component configurations into etcd.
#
# Upstream source of this file:
#
#   eduid-common/src/eduid_common/config/scripts/etcd_config_bootstrap.py
#

import argparse
import json
import os
import sys

import etcd
import yaml

__author__ = 'lundberg'

VERBOSE = False


def load_yaml(file_path):
    """
    :param file_path: Full path to a file with configuration in yaml
    :type file_path: str | unicode

    :return: dict representation of the yaml
    :rtype: dict
    """
    try:
        with open(file_path) as f:
            if VERBOSE:
                print('Loading configuration from {!s}'.format(file_path))
            return yaml.safe_load(f)
    except IOError as e:
        sys.stderr.writelines(str(e) + '\n')
        sys.exit(1)


def init_etcd_client(host=None, port=None, protocol=None, cert=None, certkey=None, ca_cert=None):
    if not host:
        host = os.environ.get('ETCD_HOST', '127.0.0.1')
    if not port:
        port = int(os.environ.get('ETCD_PORT', '2379'))
    if not protocol:
        protocol = os.environ.get('ETCD_PROTOCOL', 'http')
    if not cert:
        cert = os.environ.get('ETCD_CERT', '')
    if not certkey:
        certkey = os.environ.get('ETCD_CERTKEY', '')
    if not ca_cert:
        ca_cert = os.environ.get('ETCD_CACERT', '')
    if VERBOSE:
        print('Initializing etcd client {!s}:{!s}'.format(host, port))
    if cert and certkey:
        if VERBOSE:
            print('Using cert {!s} and key {!s}'.format(cert, certkey))
        if ca_cert:
            if VERBOSE:
                print('Using ca cert {!s}'.format(ca_cert))
        return etcd.Client(host, port, protocol=protocol, cert=(cert, certkey), ca_cert=ca_cert)
    return etcd.Client(host, port, protocol=protocol)


def prepare_configuration(config, skip_levels, ns='', ret_list=None):
    """
    :param config: Dictionary with config
    :type config: dict
    :param skip_levels: How many levels to skip over
    :type skip_levels: int
    :param ns: Cumulative base namespace
    :type ns: str | unicode
    :param depth: Current depth in the dictionary
    :type depth: int
    :param ret_list: To hold result during
    :type ret_list: list

    :return List with fq_key, value tuples
    :rtype list

    Ex

    The following yaml has been loaded from file
    eduid:
        webapp:
            common:
                SAML_CONFIG:
                    xmlsec_binary: /usr/bin/xmlsec1
            oidc_proofing:
                MONGO_URI: mongodb://user:pw@mongodb.docker
                LOG_TYPE:
                   - rotating
                   - gelf

    and results in the a dict like below:

    {
        'eduid': {
            'webapp': {
                'common': {
                    'SAML_CONFIG': {
                        'xmlsec_binary': '/usr/bin/xmlsec1'
                    }
                },
                'oidc_proofing': {
                    'LOG_TYPE': ['rotating', 'gelf'],
                    'MONGO_URI': 'mongodb://user:pw@mongodb.docker'
                }
            },
            'worker': {'foo': 'bar'}
        }
    }

    With base_namespace_depth set to 3 we know that the key-value pairs below common and oidc_proofing
    are the ones we want write to etcd.

    This will result in the following key-value pairs being returned:
    /eduid/webapp/oidc_proofing/log_type -> '["rotating", "gelf"]'
    /eduid/webapp/oidc_proofing/mongo_uri -> 'mongodb://user:pw@mongodb.docker'
    /eduid/webapp/common/saml_config -> '{"xmlsec_binary": "/usr/bin/xmlsec1"}'
    /eduid/worker/foo -> "bar"}'
    """
    if ret_list is None:
        ret_list = []

    for level in config.keys():
        if skip_levels:
            next_ns = '{!s}/{!s}'.format(ns, level)
            prepare_configuration(config[level], skip_levels - 1, next_ns, ret_list)
        else:
            this_ns = '{!s}/{!s}'.format(ns, level)
            for key, value in config[level].items():
                fq_key = '{!s}/{!s}'.format(this_ns, key).lower()
                json_value = json.dumps(value)
                ret_list.append((fq_key, json_value))
    return ret_list


def remove_old_keys(client, config, depth):
    """
    :param client: etcd client
    :type client: etcd.Client
    :param config: List of fq_keys and json values
    :type config: list
    :param depth: How many levels of base namespace
    :type depth: int
    """
    new_keys = [item[0] for item in config]
    base_ns = '/'.join(new_keys[0].split('/')[:depth])

    try:
        for item in client.read(base_ns, recursive=True).children:
            if item.key not in new_keys:
                client.delete(item.key, recursive=True)
                if VERBOSE:
                    print('{!s} -> Removed'.format(item.key))
    except etcd.EtcdKeyNotFound:
        pass  # base_ns is missing, nothing to remove


def write_config(client, config):
    """
    :param client: etcd client
    :type client: etcd.Client
    :param config: List of fq_keys and json values
    :type config: list
    """

    for fq_key, json_value in config:
        client.write(fq_key, json_value)
        if VERBOSE:
            print('{!s} -> {!s}'.format(fq_key, json_value))


def main():
    # User friendly usage output
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--configuration', help='Path to the yaml configuration file.', default='conf.yaml')
    parser.add_argument('-b', '--base-ns-depth', nargs='?', help='Base namespace depth', default=3, type=int)
    parser.add_argument('--host', nargs='?', help='etcd hostname')
    parser.add_argument('--port', nargs='?', type=int, help='etcd port')
    parser.add_argument('--protocol', nargs='?', help='etcd protocol')
    parser.add_argument('--cert', nargs='?', help='etcd cert')
    parser.add_argument('--certkey', nargs='?', help='etcd cert key')
    parser.add_argument('--cacert', nargs='?', help='etcd ca cert')
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    args = parser.parse_args()

    if not args.configuration:
        print('Please provide a configuration file with -c.')
        sys.exit(1)

    if args.verbose:
        global VERBOSE
        VERBOSE = True

    config_dict = load_yaml(args.configuration)
    etcd_client = init_etcd_client(args.host, args.port, args.protocol, args.cert, args.certkey, args.cacert)
    config_list = prepare_configuration(config_dict, args.base_ns_depth - 1)

    try:
        remove_old_keys(etcd_client, config_list, args.base_ns_depth)
        write_config(etcd_client, config_list)
    except etcd.EtcdConnectionFailed as e:
        sys.stderr.writelines(str(e) + '\n')
        sys.exit(1)


if __name__ == '__main__':
    main()
