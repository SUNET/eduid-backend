import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass, field

import nacl.utils

HMAC_DIGEST_SIZE = 256 // 8
SESSION_KEY_BITS = 256

# Prepend an 'a' so we always have a valid NCName,
# needed by pysaml2 for its session ids.
TOKEN_PREFIX = "a"


@dataclass(frozen=True)
class SessionMeta:
    cookie_val: str  # the value to store as a cookie in the user's browser (basically session_id + signature)
    session_id: str  # the lookup key used to locate the session in the session store
    signature: bytes = field(repr=False)  # cryptographic signature of session_id
    hmac_key: bytes = field(repr=False)  # key used to sign the session_id

    @classmethod
    def new(cls, app_secret: str) -> "SessionMeta":
        # Generate a random session_id
        _bin_session_id = nacl.utils.random(SESSION_KEY_BITS // 8)
        _bin_hmac_key = derive_key(app_secret, _bin_session_id, "hmac", HMAC_DIGEST_SIZE)
        _bin_signature = cls._sign_session_id(_bin_session_id, _bin_hmac_key)
        token = cls._encode_token(_bin_session_id, _bin_signature)
        session_id = _bin_session_id.hex()
        return cls(token, session_id, _bin_signature, _bin_hmac_key)

    @classmethod
    def from_cookie(cls, cookie_val: str, app_secret: str) -> "SessionMeta":
        _bin_session_id, _bin_signature = cls._decode_cookie(cookie_val)
        hmac_key = derive_key(app_secret, _bin_session_id, "hmac", HMAC_DIGEST_SIZE)
        if not cls._verify_session_id(_bin_session_id, hmac_key, _bin_signature):
            raise ValueError("Token signature check failed")
        session_id = _bin_session_id.hex()
        return cls(cookie_val, session_id, _bin_signature, hmac_key)

    @staticmethod
    def _encode_token(bin_session_id: bytes, signature: bytes) -> str:
        """
        Encode a session id and it's signature into a token that is stored
        in the users browser as a cookie.

        :return: a token with the signed session_id
        """
        # The last byte ('x') is padding to prevent b32encode from adding an = at the end
        combined = base64.b32encode(bin_session_id + signature + b"x")
        # Make sure token will be a valid NCName (pysaml2 requirement)
        while combined.endswith(b"="):
            combined = combined[:-1]
        return TOKEN_PREFIX + combined.decode("utf-8")

    @staticmethod
    def _decode_cookie(cookie_val: str) -> tuple[bytes, bytes]:
        """
        Decode a token (token is what is stored in a cookie) into it's components.

        :param cookie_val: the token with the signed session_id

        :return: the session_id and signature
        """
        # the slicing is to remove a leading 'a' needed so we have a
        # valid NCName so pysaml2 doesn't complain when it uses the token as
        # session id.
        if not cookie_val.startswith(TOKEN_PREFIX):
            raise ValueError(f"Invalid token string {cookie_val!r}")
        val = cookie_val[len(TOKEN_PREFIX) :]
        # Split the token into it's two parts - the session_id and the HMAC signature of it
        # (the last byte is ignored - it is padding to make b32encode not put an = at the end)
        try:
            _decoded = base64.b32decode(val)
        except binascii.Error as e:
            raise ValueError(f"Token string b32decode failed: {e}") from e
        _bin_session_id, _bin_sig = _decoded[:HMAC_DIGEST_SIZE], _decoded[HMAC_DIGEST_SIZE:-1]
        return _bin_session_id, _bin_sig

    @staticmethod
    def _sign_session_id(session_id: bytes, signing_key: bytes) -> bytes:
        """
        Generate a HMAC signature of session_id using the session-unique signing key.

        :param session_id: Session id (Redis key)
        :param signing_key: Key for generating the signature

        :return: HMAC signature of session_id
        """
        return hmac.new(signing_key, session_id, digestmod=hashlib.sha256).digest()

    @classmethod
    def _verify_session_id(cls, session_id: bytes, signing_key: bytes, signature: bytes) -> bool | None:
        """
        Verify the HMAC signature on a session_id using the session-unique signing key.

        :param session_id: Session id (Redis key)
        :param signing_key: Key for generating the signature
        :param signature: Signature of session_id

        :return: True if the signature matches, False otherwise
        :rtype: bool
        """
        calculated_sig = cls._sign_session_id(session_id, signing_key)

        # Avoid timing attacks, copied from Beaker https://beaker.readthedocs.org/
        invalid_bits = 0
        if len(calculated_sig) != len(signature):
            return None

        for a, b in zip(calculated_sig, signature, strict=True):
            invalid_bits += a != b

        return bool(not invalid_bits)

    def derive_key(self, app_secret: str, usage: str, size: int) -> bytes:
        _bin_session_id = bytes.fromhex(self.session_id)

        return derive_key(app_secret, _bin_session_id, usage, size)


# TODO: This standalone version of this function should perhaps be moved to some utility module.
def derive_key(app_secret: str, bin_session_id: bytes, usage: str, size: int) -> bytes:
    """
    Derive a cryptographic key for a specific usage from the app_secret and session_id.

    The app_secret is a shared secret between all instances of this app (e.g. eduid-dashboard).
    The session_id is a randomized value unique to this session.

    :param app_secret: Application shared session_id
    :param usage: 'sign' or 'encrypt' or something else
    :param session_id: Session unique session_id
    :param size: Size of key requested in bytes

    :return: Derived key
    """
    # the low number of rounds (3) is not important here - we use this to derive two keys
    # (different 'usage') from a single key which is comprised of a 256 bit app_key
    # (shared between instances), and a random session key of 128 bits.
    _salt = usage.encode("ascii") + bin_session_id
    return hashlib.pbkdf2_hmac("sha256", app_secret.encode("ascii"), _salt, 3, dklen=size)
