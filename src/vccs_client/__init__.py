#-*- encoding: utf-8 -*-
#
# Copyright (c) 2013, 2014, 2017 NORDUnet A/S
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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

"""
the VCCS authentication client package

Copyright (c) 2013, 2014, 2017 NORDUnet A/S
See the source file for complete license statement.


Short usage, see the README for details :

Add credential, and authenticate with correct password :

  >>> import vccs_client
  >>> f = vccs_client.VCCSPasswordFactor('password', credential_id=4712)
  >>> client = vccs_client.VCCSClient(base_url='http://localhost:8550/')
  >>> client.add_credentials('ft@example.net', [f])
  True
  >>> f.salt
  '$2a$12$F0TIdfp4quhVJYIOO1ojU.'
  >>>

The salt and the credential_id needs to be remembered in the client
application for use when validating the password later on.


Authenticate with incorrect password :

  >>> client.authenticate('ft@example.net', [f])
  True
  >>> incorrect_f = vccs_client.VCCSPasswordFactor('foobar', credential_id=4712,
  ...       salt='$2a$12$F0TIdfp4quhVJYIOO1ojU.')
  >>> client.authenticate('ft@example.net', [incorrect_f])
  False
  >>>

Revoke a credential (irreversible!) :

  >>> r = vccs_client.VCCSRevokeFactor(4712, 'testing revoke', reference='foobar')
  >>> client.revoke_credentials('ft@example.net', [r])
  True
  >>>

"""

__version__ = '0.5.0b0'
__copyright__ = 'NORDUnet A/S'
__organization__ = 'NORDUnet'
__license__ = 'BSD'
__authors__ = ['Fredrik Thulin']

__all__ = [
    ]


import os
import six
import bson
import bcrypt
from six.moves.urllib.parse import urlencode
from six.moves.urllib.request import urlopen, Request
from six.moves.urllib.error import HTTPError, URLError
from six import string_types
import simplejson as json


class VCCSClientException(Exception):
    """
    Base exception class for VCCS client.
    """
    def __init__(self, reason):
        Exception.__init__(self)
        self.reason = reason


class VCCSClientHTTPError(VCCSClientException):
    """
    Class to convey HTTP errors to VCCS client users in a
    way that does not make them have to know what HTTP
    library is used by the VCCS client.
    """
    def __init__(self, reason, http_code):
        VCCSClientException.__init__(self, reason)
        self.http_code = http_code

    def __str__(self):
        return '<{cl} instance at {addr}: {code!r} {reason!r}>'.format(
            cl = self.__class__.__name__,
            addr = hex(id(self)),
            code = self.http_code,
            reason = self.reason,
            )


class VCCSFactor(object):
    """
    Base class for authentication factors. Do not use directly.
    """
    def __init__(self):
        pass

    def to_dict(self, _action):
        """
        Return factor as a dict that can be serialized for sending to the
        authentication backend.

        :param _action: 'auth', 'add_creds' or 'revoke_creds'
        :returns: dict
        """
        raise NotImplementedError('Sub-class must implement to_dict')


class VCCSPasswordFactor(VCCSFactor):
    """
    Object representing an ordinary password authentication factor.
    """

    def __init__(self, password, credential_id, salt=None, strip_whitespace=True):
        """
        :param password: string, password as plaintext
        :param credential_id: unique id of credential in the authentication backend databas
        :param salt: string or None, NDNv1H1 salt to be used for pre-hashing
                      (if None, one will be generated. If non-default salt
                      parameters are requested, use generate_salt() directly)
        :param strip_whitespace: boolean, Remove all whitespace from input

        :type password: string_types
        :type credential_id: string_types | bson.ObjectId
        :type salt: None | string_types
        :type strip_whitespace: bool
        """
        if salt is None:
            salt = self.generate_salt()
        if not salt.startswith('$NDNv1H1$'):
            raise ValueError('Invalid salt (not NDNv1H1)')
        self.salt = salt
        if isinstance(credential_id, bson.ObjectId):
            # backwards compatibility
            credential_id = str(credential_id)
        if not isinstance(credential_id, string_types):
            raise ValueError('Non-string credential id: {!r}'.format(credential_id))
        self.credential_id = credential_id
        salt, key_length, rounds, = self._decode_parameters(salt)

        cid_str = str(self.credential_id)
        if strip_whitespace:
            password = ''.join(password.split())
        if six.PY2:
            # Allow passwords containing non-ascii characters, while
            # keeping backward-capability by converting to byte string.
            # UTF-8 is the encoding used for POST-requests, for more info see the
            # section handling-form-submissions-in-view-callables-unicode-and-character-set-issues
            # at http://docs.pylonsproject.org/projects/pyramid/en/latest/narr/views.html
            if isinstance(password, unicode):
                password = password.encode('UTF-8')
            T1 = "{!s}{!s}{!s}{!s}".format(len(cid_str), cid_str,
                                           len(password), password)
        else:
            password = bytes(password, 'utf-8')
            T1 = "{!s}{!s}{!s}".format(len(cid_str), cid_str, len(password))
            T1 = bytes(T1, 'utf-8') + password

        # password = '4471120passwordåäöхэж' (T1 as hex:'3434373131323070617373776f7264c3a5c3a4c3b6d185d18dd0b6')
        # should give res == '80e6759a26bb9d439bc77d52'
        res = bcrypt.kdf(T1, salt, key_length, rounds)
        if six.PY2:
            res = res.encode('hex')
        else:
            res = res.hex()
        self.hash = res
        VCCSFactor.__init__(self)

    def generate_salt(self, salt_length=32, desired_key_length=32, rounds=2 ** 5):
        """
        Generate a NDNv1H1 salt.

        Encoded into the salt will be the KDF parameter values desired_key_length
        and rounds.

        For number of rounds, it is recommended that a measurement is made to achieve
        a cost of at least 100 ms on current hardware.

        :param salt_length: Number of bytes of salt to generate (recommended min 16).
        :param desired_key_length: Length of H1 hash to produce (recommended min 32).
        :param rounds: bcrypt pbkdf number of rounds.
        :returns: string with salt and parameters
        """
        random = self._get_random_bytes(salt_length)
        if six.PY2:
            random_str = random.encode('hex')
        else:
            random_str = random.hex()

        return "$NDNv1H1${!s}${!r}${!r}$".format(random_str, desired_key_length, rounds)

    def _decode_parameters(self, salt):
        """
        Internal function to decode a NDNv1H1 salt.
        """
        _, version, salt, desired_key_length, rounds, _ = salt.split('$')
        if version == 'NDNv1H1':
            if six.PY2:
                salt = salt.decode('hex')
            else:
                salt = bytes().fromhex(salt)
            return salt, int(desired_key_length), int(rounds)
        raise NotImplementedError('Unknown hashing scheme')

    def _get_random_bytes(self, bytes):
        """
        Internal function to make salt generation testable.
        """
        return os.urandom(bytes)

    def to_dict(self, _action):
        """
        Return factor as dictionary, transmittable to authentiation backends.
        :param _action: 'auth', 'add_creds' or 'revoke_creds'
        """
        res = {'type': 'password',
               'H1': self.hash,
               'credential_id': self.credential_id,
               }
        return res


class VCCSOathFactor(VCCSFactor):
    """
    Object representing an OATH token authentication factor.
    """

    def __init__(self, oath_type, credential_id, user_code=None, nonce=None,
                 aead=None, key_handle=None, digits=6, oath_counter=0):
        """
        :param oath_type: 'oath-totp' or 'oath-hotp' (time based or event based OATH)
        :param credential_id: integer, unique index of credential

        for authentication :
        :param user_code: integer, the user supplied token code

        for initialization (add_creds) :
        :param nonce: string, AEAD nonce
        :param aead: string, encrypted OATH secret
        :param key_handle: integer(), YubiHSM key handle used to create AEAD
        :param digits: integer, OATH token number of digits per code (6/8)
        :param oath_counter: initial OATH counter value of token
        """
        if oath_type not in ['oath-totp', 'oath-hotp']:
            raise ValueError('Invalid OATH type (not oath-totp or oath-hotp)')
        self.oath_type = oath_type
        self.credential_id = credential_id
        self.user_code = user_code
        self.nonce = nonce
        self.aead = aead
        self.key_handle = key_handle
        self.digits = digits
        self.oath_counter = oath_counter
        VCCSFactor.__init__(self)

    def to_dict(self, action):
        """
        Return factor as dictionary, transmittable to authentiation backends.
        :param action: 'auth', 'add_creds' or 'revoke_creds'

        :returns: Factor in dict format
        :rtype: dict
        """
        if action == 'auth':
            if self.user_code is None:
                raise ValueError('User code not provided')
            res = {'type': self.oath_type,
                   'user_code': self.user_code,
                   'credential_id': self.credential_id,
                   }
        elif action == 'add_creds':
            res = {'type': self.oath_type,
                   'credential_id': self.credential_id,
                   'nonce': self.nonce,
                   'aead': self.aead,
                   'key_handle': self.key_handle,
                   'digits': self.digits,
                   'oath_counter': self.oath_counter,
                   }
        elif action == 'revoke_creds':
            # XXX implement this
            raise NotImplementedError()
        else:
            raise ValueError('Unknown \'action\' value (not auth or add_creds)')
        for (k, v) in res.items():
            if v is None:
                raise ValueError('{!r} property {!r} not provided'.format(action, k))
        return res


class VCCSRevokeFactor(VCCSFactor):
    """
    Object representing a factor to be revoked.
    """

    def __init__(self, credential_id, reason, reference=''):
        """
        :param credential_id: unique index of credential
        :param reason: reason for revocation
        :param reference: optional data to identify this event in logs on frontend

        :type credential_id: string_types | bson.ObjectId
        :type reason: string_types
        :type reference: string_types
        """
        if isinstance(credential_id, bson.ObjectId):
            # backwards compatibility
            credential_id = str(credential_id)
        if not isinstance(credential_id, string_types):
            raise TypeError('Non-string credential id: {!r}'.format(credential_id))
        if not isinstance(reason, string_types):
            raise TypeError('Revocation reason value type error : {!r}'.format(reason))
        if not isinstance(reference, string_types):
            raise TypeError('Revocation reference value type error : {!r}'.format(reference))

        self.credential_id = credential_id
        self.reason = reason
        self.reference = reference
        VCCSFactor.__init__(self)

    def to_dict(self, _action):
        """
        Return factor as dictionary, transmittable to authentiation backends.
        :param _action: string, 'auth' or 'add_creds'
        """
        res = {'credential_id': self.credential_id,
               'reason': self.reason,
               'reference': self.reference,
               }
        return res


class VCCSClient(object):
    """
    Connection class for handling a connection to a VCCS authentication backend server.

    Using this connection, requests can be made to authenticate, add or revoke
    credentials (authentication factors).
    """

    def __init__(self, base_url='http://localhost:8550/'):
        self.base_url = base_url

    def authenticate(self, user_id, factors):
        """
        Make an authentication request for one or more factors belonging to a certain user.

        The backend is intentionally secret about details for failures, and will in fact
        return a HTTP error for many errors. The only thing that is for certain is that
        if this function returns True, the backend considers the user properly authenticated
        based on the provided factors.

        :param user_id: persistent user identifier
        :param factors: Factors to authenticate

        :type user_id: string_types
        :type factors: list of VCCSFactor

        :returns: success or not
        :rtype: bool
        """
        auth_req = self._make_request('auth', user_id, factors)

        response = self._execute(auth_req, 'auth_response')
        resp_auth = response['authenticated']
        if type(resp_auth) != bool:
            raise TypeError('Authenticated value type error : {!r}'.format(resp_auth))
        return resp_auth is True

    def add_credentials(self, user_id, factors):
        """
        Ask the authentication backend to add one or more credentials to it's
        private credential store.

        :param user_id: persistent user identifier as string
        :param factors: list of VCCSFactor() instances
        :returns: boolean, success or not
        """
        add_creds_req = self._make_request('add_creds', user_id, factors)

        response = self._execute(add_creds_req, 'add_creds_response')
        success = response['success']
        if type(success) != bool:
            raise TypeError('Operation success value type error : {!r}'.format(success))
        return success is True

    def revoke_credentials(self, user_id, factors):
        """
        Ask the authentication backend to revoke one or more credentials in it's
        private credential store.

        :param user_id: persistent user identifier
        :param factors: Factors to revoke

        :type user_id: string_types
        :type factors: list of VCCSRevokeFactor

        :returns: success or not
        :rtype: bool
        """
        revoke_creds_req = self._make_request('revoke_creds', user_id, factors)

        response = self._execute(revoke_creds_req, 'revoke_creds_response')
        success = response['success']
        if type(success) != bool:
            raise TypeError('Operation success value type error : {!r}'.format(success))
        return success is True

    def _execute(self, data, response_label):
        """
        Make a HTTP POST request to the authentication backend, and parse the result.

        :param data: request as string (JSON)
        :param response_label: 'auth_response' or 'add_creds_response'
        :returns: data from response identified by key response_label - supposedly a dict
        """
        # make the request
        if response_label == 'auth_response':
            service = 'authenticate'
        elif response_label == 'add_creds_response':
            service = 'add_creds'
        elif response_label == 'revoke_creds_response':
            service = 'revoke_creds'
        else:
            raise ValueError('Unknown response_label {!r}'.format(response_label))
        values = {'request': data}
        body = self._execute_request_response(service, values)

        # parse the response
        resp = json.loads(body)
        if not response_label in resp:
            raise ValueError('Expected {!r} not found in parsed response'.format(response_label))
        resp_ver = resp[response_label]['version']
        if resp_ver != 1:
            raise AssertionError('Received response of unknown version {!r}'.format(resp_ver))
        return resp[response_label]

    def _execute_request_response(self, service, values):
        """
        The part of _execute that has actual side effects. In a separate function
        to make everything else easily testable.
        """
        data = bytes(urlencode(values), 'utf-8')
        req = Request(self.base_url + service, data)
        try:
            response = urlopen(req)
        except HTTPError as exc:
            # don't want the vccs_client user to have to know what http client we use.
            raise VCCSClientHTTPError(reason='Authentication backend error',
                                      http_code=exc.getcode())
        except URLError:
            raise VCCSClientHTTPError(reason='Authentication backend unavailable',
                                      http_code=503)

        return response.read()

    def _make_request(self, action, user_id, factors):
        """
        :param action: 'auth', 'add_creds' or 'revoke_creds'
        :param factors: list of VCCSFactor instance
        :returns: request as string (JSON)
        """
        if action not in ['auth', 'add_creds', 'revoke_creds']:
            raise ValueError('Unknown action {!r}'.format(action))
        a = {action:
                 {'version': 1,
                  'user_id': user_id,
                  'factors': [x.to_dict(action) for x in factors],
                  }
             }
        return json.dumps(a, sort_keys=True, indent=4)
