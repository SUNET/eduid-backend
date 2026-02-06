"""
the VCCS authentication client package

Copyright (c) 2013, 2014, 2017 NORDUnet A/S
See the source file for complete license statement.


Short usage, see the README for details :

Add credential, and authenticate with correct password :

  >>> from eduid.vccs.client import *
  >>> f = VCCSPasswordFactor('password', credential_id='4712')
  >>> client = VCCSClient(base_url='http://localhost:8550/')
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
  >>> incorrect_f = VCCSPasswordFactor('foobar', credential_id='4712',
  ...       salt='$2a$12$F0TIdfp4quhVJYIOO1ojU.')
  >>> client.authenticate('ft@example.net', [incorrect_f])
  False
  >>>

Revoke a credential (irreversible!) :

  >>> r = VCCSRevokeFactor('4712', 'testing revoke', reference='foobar')
  >>> client.revoke_credentials('ft@example.net', [r])
  True
  >>>

"""

import os
from collections.abc import Sequence
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import bcrypt
import simplejson as json


class VCCSClientException(Exception):
    """
    Base exception class for VCCS client.
    """

    def __init__(self, reason: str) -> None:
        Exception.__init__(self)
        self.reason = reason


class VCCSClientHTTPError(VCCSClientException):
    """
    Class to convey HTTP errors to VCCS client users in a
    way that does not make them have to know what HTTP
    library is used by the VCCS client.
    """

    def __init__(self, reason: str, http_code: int) -> None:
        VCCSClientException.__init__(self, reason)
        self.http_code = http_code

    def __str__(self) -> str:
        return f"<{self.__class__.__name__} instance at {hex(id(self))}: {self.http_code!r} {self.reason!r}>"


class VCCSFactor:
    """
    Base class for authentication factors. Do not use directly.
    """

    def __init__(self) -> None:
        pass

    def to_dict(self, action: str) -> dict[str, Any]:
        """
        Return factor as a dict that can be serialized for sending to the
        authentication backend.

        :param action: 'auth', 'add_creds' or 'revoke_creds'
        :returns: dict
        """
        raise NotImplementedError("Sub-class must implement to_dict")


class VCCSPasswordFactor(VCCSFactor):
    """
    Object representing an ordinary password authentication factor.
    """

    def __init__(
        self, password: str, credential_id: str, salt: str | None = None, strip_whitespace: bool = True
    ) -> None:
        """
        :param password: string, password as plaintext
        :param credential_id: unique id of credential in the authentication backend database
        :param salt: string or None, NDNv1H1 salt to be used for pre-hashing
                      (if None, one will be generated. If non-default salt
                      parameters are requested, use generate_salt() directly)
        :param strip_whitespace: boolean, Remove all whitespace from input
        """
        if salt is None:
            salt = self.generate_salt()
        if not salt.startswith("$NDNv1H1$"):
            raise ValueError("Invalid salt (not NDNv1H1)")
        self.salt = salt
        if not isinstance(credential_id, str):
            raise ValueError(f"Non-string credential id: {credential_id!r}")
        self.credential_id = credential_id
        (
            salt_bytes,
            key_length,
            rounds,
        ) = self._decode_parameters(salt)

        cid_str = str(self.credential_id)
        if strip_whitespace:
            password = "".join(password.split())
        password_bytes = bytes(password, "utf-8")
        T1 = f"{len(cid_str)!s}{cid_str!s}{len(password_bytes)!s}"
        T1_bytes = bytes(T1, "utf-8") + password_bytes

        # password = '4471120passwordåäöхэж' (T1 as hex:'3434373131323070617373776f7264c3a5c3a4c3b6d185d18dd0b6')
        # should give res == '80e6759a26bb9d439bc77d52'
        res = bcrypt.kdf(T1_bytes, salt_bytes, key_length, rounds)
        res = res.hex()
        self.hash = res
        VCCSFactor.__init__(self)

    def generate_salt(self, salt_length: int = 32, desired_key_length: int = 32, rounds: int = 2**5) -> str:
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
        random_str = random.hex()

        return f"$NDNv1H1${random_str!s}${desired_key_length!r}${rounds!r}$"

    def _decode_parameters(self, salt: str) -> tuple[bytes, int, int]:
        """
        Internal function to decode a NDNv1H1 salt.
        """
        _, version, salt, desired_key_length, rounds, _ = salt.split("$")
        if version == "NDNv1H1":
            salt_bytes = b"".fromhex(salt)
            return salt_bytes, int(desired_key_length), int(rounds)
        raise NotImplementedError("Unknown hashing scheme")

    def _get_random_bytes(self, num_bytes: int) -> bytes:
        """
        Internal function to make salt generation testable.
        """
        return os.urandom(num_bytes)

    def to_dict(self, action: str) -> dict[str, Any]:
        """
        Return factor as dictionary, transmittable to authentiation backends.
        :param action: 'auth', 'add_creds' or 'revoke_creds'
        """
        res = {
            "type": "password",
            "H1": self.hash,
            "credential_id": self.credential_id,
        }
        return res


class VCCSOathFactor(VCCSFactor):
    """
    Object representing an OATH token authentication factor.
    """

    def __init__(
        self,
        oath_type: str,
        credential_id: int,
        user_code: int | None = None,
        nonce: str | None = None,
        aead: str | None = None,
        key_handle: int | None = None,
        digits: int = 6,
        oath_counter: int = 0,
    ) -> None:
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
        if oath_type not in ["oath-totp", "oath-hotp"]:
            raise ValueError("Invalid OATH type (not oath-totp or oath-hotp)")
        self.oath_type = oath_type
        self.credential_id = credential_id
        self.user_code = user_code
        self.nonce = nonce
        self.aead = aead
        self.key_handle = key_handle
        self.digits = digits
        self.oath_counter = oath_counter
        VCCSFactor.__init__(self)

    def to_dict(self, action: str) -> dict[str, Any]:
        """
        Return factor as dictionary, transmittable to authentiation backends.
        :param action: 'auth', 'add_creds' or 'revoke_creds'

        :returns: Factor in dict format
        :rtype: dict
        """
        if action == "auth":
            if self.user_code is None:
                raise ValueError("User code not provided")
            res = {
                "type": self.oath_type,
                "user_code": self.user_code,
                "credential_id": self.credential_id,
            }
        elif action == "add_creds":
            res = {
                "type": self.oath_type,
                "credential_id": self.credential_id,
                "nonce": self.nonce,
                "aead": self.aead,
                "key_handle": self.key_handle,
                "digits": self.digits,
                "oath_counter": self.oath_counter,
            }
        elif action == "revoke_creds":
            # XXX implement this
            raise NotImplementedError()
        else:
            raise ValueError("Unknown 'action' value (not auth or add_creds)")
        for k, v in res.items():
            if v is None:
                raise ValueError(f"{action!r} property {k!r} not provided")
        return res


class VCCSRevokeFactor(VCCSFactor):
    """
    Object representing a factor to be revoked.
    """

    def __init__(self, credential_id: str, reason: str, reference: str = "") -> None:
        """
        :param credential_id: unique index of credential
        :param reason: reason for revocation
        :param reference: optional data to identify this event in logs on frontend
        """
        if not isinstance(credential_id, str):
            raise TypeError(f"Non-string credential id: {credential_id!r}")
        if not isinstance(reason, str):
            raise TypeError(f"Revocation reason value type error : {reason!r}")
        if not isinstance(reference, str):
            raise TypeError(f"Revocation reference value type error : {reference!r}")

        self.credential_id = credential_id
        self.reason = reason
        self.reference = reference
        VCCSFactor.__init__(self)

    def to_dict(self, action: str) -> dict[str, Any]:
        """
        Return factor as dictionary, transmittable to authentication backends.
        :param action: string, 'auth' or 'add_creds'
        """
        res = {
            "credential_id": self.credential_id,
            "reason": self.reason,
            "reference": self.reference,
        }
        return res


class VCCSClient:
    """
    Connection class for handling a connection to a VCCS authentication backend server.

    Using this connection, requests can be made to authenticate, add or revoke
    credentials (authentication factors).
    """

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = base_url if base_url else "http://localhost:8550/"

    def authenticate(self, user_id: str, factors: Sequence[VCCSFactor]) -> bool:
        """
        Make an authentication request for one or more factors belonging to a certain user.

        The backend is intentionally secret about details for failures, and will in fact
        return a HTTP error for many errors. The only thing that is for certain is that
        if this function returns True, the backend considers the user properly authenticated
        based on the provided factors.

        :param user_id: persistent user identifier
        :param factors: Factors to authenticate

        :returns: success or not
        """
        auth_req = self._make_request("auth", user_id, factors)

        response = self._execute(auth_req, "auth_response")
        resp_auth = response["authenticated"]
        if type(resp_auth) is not bool:
            raise TypeError(f"Authenticated value type error : {resp_auth!r}")
        return resp_auth is True

    def add_credentials(self, user_id: str, factors: Sequence[VCCSFactor]) -> bool:
        """
        Ask the authentication backend to add one or more credentials to it's
        private credential store.

        :param user_id: persistent user identifier as string
        :param factors: list of VCCSFactor() instances
        :returns: boolean, success or not
        """
        add_creds_req = self._make_request("add_creds", user_id, factors)

        response = self._execute(add_creds_req, "add_creds_response")
        success = response["success"]
        if type(success) is not bool:
            raise TypeError(f"Operation success value type error : {success!r}")
        return success is True

    def revoke_credentials(self, user_id: str, factors: Sequence[VCCSRevokeFactor]) -> bool:
        """
        Ask the authentication backend to revoke one or more credentials in it's
        private credential store.

        :param user_id: persistent user identifier
        :param factors: Factors to revoke

        :returns: success or not
        """
        revoke_creds_req = self._make_request("revoke_creds", user_id, factors)

        response = self._execute(revoke_creds_req, "revoke_creds_response")
        success = response["success"]
        if type(success) is not bool:
            raise TypeError(f"Operation success value type error : {success!r}")
        return success is True

    def _execute(self, data: str, response_label: str) -> dict:
        """
        Make a HTTP POST request to the authentication backend, and parse the result.

        :param data: request as string (JSON)
        :param response_label: 'auth_response' or 'add_creds_response'
        :returns: data from response identified by key response_label - supposedly a dict
        """
        # make the request
        if response_label == "auth_response":
            service = "authenticate"
        elif response_label == "add_creds_response":
            service = "add_creds"
        elif response_label == "revoke_creds_response":
            service = "revoke_creds"
        else:
            raise ValueError(f"Unknown response_label {response_label!r}")
        values = {"request": data}
        body = self._execute_request_response(service, values)

        # parse the response
        resp = json.loads(body)
        if response_label not in resp:
            raise ValueError(f"Expected {response_label!r} not found in parsed response")
        resp_ver = resp[response_label]["version"]
        if resp_ver != 1:
            raise AssertionError(f"Received response of unknown version {resp_ver!r}")
        return resp[response_label]

    def _execute_request_response(self, service: str, values: dict[str, Any]) -> str:
        """
        The part of _execute that has actual side effects. In a separate function
        to make everything else easily testable.
        """
        data = bytes(urlencode(values), "utf-8")
        req = Request(self.base_url + service, data)
        try:
            response = urlopen(req)
        except HTTPError as exc:
            # don't want the vccs_client user to have to know what http client we use.
            http_code = exc.status or 500
            raise VCCSClientHTTPError(reason="Authentication backend error", http_code=http_code) from exc
        except URLError as exc:
            raise VCCSClientHTTPError(reason="Authentication backend unavailable", http_code=503) from exc

        return response.read()

    def _make_request(self, action: str, user_id: str, factors: Sequence[VCCSFactor]) -> str:
        """
        :param action: 'auth', 'add_creds' or 'revoke_creds'
        :param factors: list of VCCSFactor instance
        :returns: request as string (JSON)
        """
        if action not in ["auth", "add_creds", "revoke_creds"]:
            raise ValueError(f"Unknown action {action!r}")
        a = {action: {"version": 1, "user_id": user_id, "factors": [x.to_dict(action) for x in factors]}}
        return json.dumps(a, sort_keys=True, indent=4)
