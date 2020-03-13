# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from __future__ import absolute_import

import importlib.util
import logging
import os.path
import sys
import time

import six
from pwgen import pwgen
from saml2 import server
from saml2.config import SPConfig

from eduid_common.api.utils import urlappend

logger = logging.getLogger(__name__)


def get_saml2_config(module_path: str) -> SPConfig:
    """Load SAML2 config file, in the form of a Python module."""
    spec = importlib.util.spec_from_file_location('saml2_settings', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore

    conf = SPConfig()
    conf.load(module.SAML_CONFIG)  # type: ignore
    return conf


def get_location(http_info):
    """Extract the redirect URL from a pysaml2 http_info object"""
    assert 'headers' in http_info
    headers = http_info['headers']

    assert len(headers) == 1
    header_name, header_value = headers[0]
    assert header_name == 'Location'
    return header_value


def get_saml_attribute(session_info, attr_name):
    """
    Get value from a SAML attribute received from the SAML IdP.

    session_info is a pysaml2 response.session_info(). This is a dictionary like
        {'mail': ['user@example.edu'],
         'eduPersonPrincipalName': ['gadaj-fifib@idp.example.edu']
      }

    :param session_info: SAML attributes received by pysaml2 client.
    :param attr_name: The attribute to look up
    :returns: Attribute values

    :type session_info: dict()
    :type attr_name: string()
    :rtype: [string()]
    """
    if 'ava' not in session_info:
        raise ValueError('SAML attributes (ava) not found in session_info')

    attributes = session_info['ava']

    logger.debug('SAML attributes received: %s' % attributes)

    # Look for the canonicalized attribute in the SAML assertion attributes
    for saml_attr, _ in attributes.items():
        if saml_attr.lower() == attr_name.lower():
            return attributes[saml_attr]


def no_authn_views(app, paths):
    """
    :param app: Flask app
    :type app: flask.Flask
    :param paths: Paths that does not require authentication
    :type paths: list

    :return: Flask app
    :rtype: flask.Flask
    """
    app_root = app.config.get('APPLICATION_ROOT')
    if app_root is None:
        app_root = ''
    for path in paths:
        no_auth_regex = '^{!s}$'.format(urlappend(app_root, path))
        if no_auth_regex not in app.config['NO_AUTHN_URLS']:
            app.config['NO_AUTHN_URLS'].append(no_auth_regex)
    return app


def generate_password(length=12):
    return pwgen(int(length), no_capitalize=True, no_symbols=True)


def check_previous_identification(session_ns):
    """
    Check that the user, though not properly authenticated, has been recognized
    by some app with access to the shared session
    Must be called within a request context.

    Used after signup or for idp actions.

    :return: The eppn in case the check is successful, None otherwise
    """
    from eduid_common.session import session

    eppn = session.common.eppn
    if eppn is None:
        eppn = session.get('user_eppn', None)
    timestamp = session_ns.ts
    logger.debug('Trying to authenticate user {} with timestamp {!r}'.format(eppn, timestamp))
    # check that the eppn and timestamp have been set in the session
    if eppn is None or timestamp is None:
        return None
    # check timestamp to make sure it is within -300..900
    now = int(time.time())
    ts = timestamp.timestamp()
    if (ts < now - 300) or (ts > now + 900):
        logger.debug('Auth token timestamp {} out of bounds ({} seconds from {})'.format(timestamp, ts - now, now))
        return None
    return eppn


def maybe_xml_to_string(message, logger=None):
    """
    Try to parse message as an XML string, and then return it pretty-printed.

    If message couldn't be parsed, return string representation of it instead.

    This is used to (debug-)log SAML requests/responses in a readable way.

    :param message: XML string typically
    :param logger: logging logger
    :return: something ready for logging
    :rtype: string
    """
    if isinstance(message, six.binary_type):
        # message is returned as binary from pysaml2 in python3
        message = message.decode('utf-8')
    message = str(message)
    try:
        from defusedxml import ElementTree as DefusedElementTree

        parser = DefusedElementTree.DefusedXMLParser()
        xml = DefusedElementTree.XML(message, parser)
        return DefusedElementTree.tostring(xml)
    except Exception as exc:
        if logger is not None:
            logger.debug("Could not parse message of type {!r} as XML: {!r}".format(type(message), exc))
        return message


def init_pysaml2(cfgfile):
    """
    Initialization of PySAML2.

    :return:
    """
    old_path = sys.path
    cfgdir = os.path.dirname(cfgfile)
    if cfgdir:
        # add directory part to sys.path, since pysaml2 'import's it's config
        sys.path = [cfgdir] + sys.path
        cfgfile = os.path.basename(cfgfile)

    try:
        return server.Server(cfgfile)
    finally:
        # restore path
        sys.path = old_path
