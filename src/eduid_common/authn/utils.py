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
import time

from pwgen import pwgen
from saml2.config import SPConfig

from eduid_common.api.utils import urlappend
from eduid_common.session import session

logger = logging.getLogger(__name__)


def get_saml2_config(module_path: str) -> SPConfig:
    """Load SAML2 config file, in the form of a Python module."""
    spec = importlib.util.spec_from_file_location('saml2_settings', module_path)
    module = importlib.util.module_from_spec(spec)

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
    if not 'ava' in session_info:
        raise ValueError('SAML attributes (ava) not found in session_info')

    attributes = session_info['ava']

    logger.debug('SAML attributes received: %s' % attributes)

    attr_name = attr_name.lower()
    # Look for the canonicalized attribute in the SAML assertion attributes
    for saml_attr, local_fields in attributes.items():
        if saml_attr.lower() == attr_name:
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
        logger.debug('Auth token timestamp {} out of bounds ({} seconds from {})'.format(
            timestamp, ts - now, now))
        return None
    return eppn


# XXX TRANSITION_TOKEN_LOGIN the code below is deprecated and only kept fr the transition to implicit
# logins with data in the session. Please remove after the transition

import six
from hashlib import sha256
from nacl import secret, encoding
import nacl.exceptions

def verify_auth_token(shared_key, eppn, token, nonce, timestamp, usage, generator=sha256):
    """
    Authenticate a user with a token.
    Used after signup or for idp actions.
    Authentication is done using a shared key in the configuration of the
    authn and signup applications or another shared key in the configuration of idp and actions.
    :param shared_key: Applications shared key
    :param eppn: the identifier of the user as string
    :param token: authentication token as string
    :param nonce: a public nonce for this authentication request as string
    :param timestamp: unixtime of signup application as hex string
    :param usage: The intended usage of the token, to safeguard against tokens being maliciously
                  sent to another token consumer than intended
    :param generator: hash function to use (default: SHA-256)
    :return: bool, True on valid authentication
    """
    logger.debug('Trying to authenticate user {} with auth token {!r}'.format(eppn, token))
    if six.PY2:
        shared_key = shared_key.encode('ascii')

    # check timestamp to make sure it is within -300..900 seconds from now
    now = int(time.time())
    if (timestamp < now - 300) or (timestamp > now + 900):
        logger.debug('Auth token timestamp {} out of bounds ({} seconds from {})'.format(
            timestamp, timestamp - now, now))
        return False

    # try to open secret box
    try:
        box = secret.SecretBox(encoding.URLSafeBase64Encoder.decode(shared_key))
        plaintext = box.decrypt(token.encode('ascii'), encoder=encoding.URLSafeBase64Encoder)
        expected = '{}|{}|{}'.format(usage, timestamp, eppn).encode('ascii')
        logger.debug('Comparing plaintext {!r} with expected {!r}'.format(plaintext, expected))
        return plaintext == expected
    except (LookupError,  ValueError, nacl.exceptions.CryptoError) as e:
        logger.debug('Secretbox decryption failed, error: ' + str(e))

    # Fall back to HMAC validation

    # verify there is a long enough nonce
    if len(nonce) < 16:
        logger.warning('Auth token nonce {} too short'.format(nonce))
        return False

    # verify token format
    data = u'{0}|{1}|{2}|{3}'.format(shared_key, eppn, nonce, timestamp)
    hashed = generator(data.encode('ascii'))
    expected = hashed.hexdigest()
    if len(expected) != len(token):
        logger.warning('Auth token bad length')
        return False

    # constant time comparision of the hash, courtesy of
    # http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/
    result = 0
    if isinstance(expected, six.binary_type):
        expected = expected.decode('ascii')
    if isinstance(token, six.binary_type):
        token = token.decode('ascii')
    for x, y in zip(expected, token):
        result |= ord(x) ^ ord(str(y))
    logger.debug('Auth token match result: {}'.format(result == 0))
    return result == 0
