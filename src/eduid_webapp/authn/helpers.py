# -*- coding: utf-8 -*-
from __future__ import absolute_import

import time
import re
from flask import current_app
from hashlib import sha256

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

    # check timestamp to make sure it is within -300..900 seconds from now
    now = int(time.time())
    ts = int(timestamp, 16)
    if (ts < now - 300) or (ts > now + 900):
        current_app.logger.debug('Auth token timestamp {} out of bounds ({} seconds from {})'.format(
            timestamp, ts - now, now))
        return False

    # verify there is a long enough nonce
    if len(nonce) < 16:
        current_app.logger.warning('Auth token nonce {} too short'.format(nonce))
        return False

    # verify token format
    expected = generator('{0}|{1}|{2}|{3}'.format(
        shared_key, eppn, nonce, timestamp)).hexdigest()
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


def verify_relay_state(relay_state, safe_default='/'):
    """
    :param relay_state: Next url
    :param safe_default: The default if relay state is found unsafe

    :type safe_default: six.string_types
    :type relay_state: six.string_types

    :return: Safe relay state
    :rtype: six.string_types
    """
    if relay_state is not None:
        current_app.logger.debug('Checking if relay state {} is safe'.format(relay_state))
        url_scheme = current_app.config['PREFERRED_URL_SCHEME']
        safe_domain = current_app.config['SAFE_RELAY_DOMAIN']
        safe_relay_regex = '^{}\:\/\/.*{}|^\/\w*'.format(url_scheme, safe_domain)
        if re.match(safe_relay_regex, relay_state):
            return relay_state
        current_app.logger.warning('Caught unsafe relay state: {}. '
                'Using safe relay state: {}.'.format(relay_state, safe_default))
    return safe_default
