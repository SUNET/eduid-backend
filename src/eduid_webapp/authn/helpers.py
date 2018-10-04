# -*- coding: utf-8 -*-
from __future__ import absolute_import

import time
import six
from flask import current_app
from hashlib import sha256
try:
    from urlparse import urlparse  # Python 2
except ImportError:
    from urllib.parse import urlparse  # Python 3

import nacl.secret
import nacl.utils
import nacl.exceptions

__author__ = 'lundberg'


def verify_auth_token(eppn, token, nonce, timestamp, generator=sha256):
    """
    Authenticate a user who just signed up, for user convenience.

    Authentication is done using a shared secret in the configuration of the
    authn and signup applications. The signup application can effectively
    log a new user in.

    :param eppn: the identifier of the user as string
    :param token: authentication token as string
    :param nonce: a public nonce for this authentication request as string
    :param timestamp: unixtime of signup application as hex string
    :param generator: hash function to use (default: SHA-256)
    :return: bool, True on valid authentication
    """
    current_app.logger.debug('Trying to authenticate user {} with auth token {}'.format(eppn, token))
    shared_key = current_app.config.get('TOKEN_LOGIN_SHARED_KEY')
    secret_key = shared_key
    if not isinstance(shared_key, six.binary_type):
        secret_key = shared_key.encode('ascii')

    # check timestamp to make sure it is within -300..900 seconds from now
    now = int(time.time())
    ts = int(timestamp, 16)
    if (ts < now - 300) or (ts > now + 900):
        current_app.logger.debug('Auth token timestamp {} out of bounds ({} seconds from {})'.format(
            timestamp, ts - now, now))
        return False

    # try to open secret box
    if isinstance(token, six.text_type):
        token = token.encode('ascii')
    else:
        if six.PY2:
            encrypted = token.decode('hex')
        else:
            encrypted = token.fromhex(token)
    try:
        box = nacl.secret.SecretBox(secret_key)
        plaintext = box.decrypt(encrypted)
        return plaintext == '{}|{}'.format(timestamp, eppn).encode('ascii')
    except (LookupError, nacl.exceptions.CryptoError) as e:
        current_app.logger.debug('Secretbox decryption failed, error: ' + str(e))

    # verify there is a long enough nonce
    if len(nonce) < 16:
        current_app.logger.warning('Auth token nonce {} too short'.format(nonce))
        return False

    # verify token format

    data = '{0}|{1}|{2}|{3}'.format(shared_key, eppn, nonce, timestamp)
    hashed = generator(data.encode('ascii'))
    expected = hashed.hexdigest()
    if len(expected) != len(token):
        current_app.logger.warning('Auth token bad length')
        return False

    # constant time comparision of the hash, courtesy of
    # http://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/
    result = 0
    for x, y in zip(expected, token):
        result |= ord(x) ^ ord(y)
    current_app.logger.debug('Auth token match result: {}'.format(result == 0))
    return result == 0
