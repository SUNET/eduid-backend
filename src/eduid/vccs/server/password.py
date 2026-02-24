from binascii import unhexlify

from ndnkdf import NDNKDF

from eduid.vccs.server.db import PasswordCredential, Version
from eduid.vccs.server.factors import RequestFactor
from eduid.vccs.server.hasher import VCCSHasher
from eduid.vccs.server.log import audit_log

MAX_T1_LENGTH = 255


async def authenticate_password(
    cred: PasswordCredential,
    factor: RequestFactor,
    user_id: str,
    hasher: VCCSHasher,
    kdf: NDNKDF,
    new_hasher: VCCSHasher | None = None,
) -> bool:
    res = False
    H2 = await calculate_cred_hash(
        user_id=user_id, H1=factor.H1, cred=cred, hasher=hasher, kdf=kdf, new_hasher=new_hasher
    )
    # XXX need to log successful login in credential_store to be able to ban
    # accounts after a certain time of inactivity (Kantara AL2_CM_CSM#050)
    # XXX can as well log counter of invalid attempts per credential too -
    # so that credentials that have had a total of too many failed logins
    # can be blocked based on that
    # Avoid logging the full hashes to make the audit logs less sensitive.
    # 16 chars (8 bytes) should still be unique enough for 'all' purposes.
    if cred.derived_key == H2:
        audit_log(f"result=OK, factor=password, credential_id={cred.credential_id}, H2[16]={H2[:16]}")
        res = True
    else:
        audit_log(
            f"result=FAIL, factor=password, credential_id={cred.credential_id}, H2[16]={H2[:16]}, "
            f"stored[16]={cred.derived_key[:16]}"
        )
    return res


async def calculate_cred_hash(
    user_id: str,
    H1: str,
    cred: PasswordCredential,
    hasher: VCCSHasher,
    kdf: NDNKDF,
    new_hasher: VCCSHasher | None = None,
) -> str:
    """
    Calculate the expected password hash value for a credential, along this
    pseudo code :

    NDNv1 (HMAC-SHA-1):
        T1 = 'A' | user_id | credential_id | H1
        T2 = PBKDF2-HMAC-SHA512(T1, iterations=many, salt)
        local_salt = yhsm_hmac_sha1(key_handle, T2)
        H2 = PBKDF2-HMAC-SHA512(T2, iterations=1, local_salt)

    NDNv2 (HMAC-SHA-256):
        T1 = 'A' | user_id | credential_id | H1
        T2 = PBKDF2-HMAC-SHA512(T1, iterations=many, salt)
        local_salt = hmac_sha256(key_label, T2)
        H2 = PBKDF2-HMAC-SHA512(T2, iterations=1, local_salt)
    """
    # Lock down key usage & credential to auth
    T1 = b""
    _components: list[str | bytes] = ["A", user_id, cred.credential_id, unhexlify(H1)]
    for this in _components:
        # Turn strings into bytes
        if isinstance(this, str):
            _bthis = bytes(this, "ascii")
        else:
            _bthis = this
        if len(this) > MAX_T1_LENGTH:
            raise RuntimeError(f"Too long T1 component ({this[:10]!r}... length {len(this)})")
        # length-encode each part, to avoid having a designated delimiter that
        # could potentially be misused
        T1 += bytes([len(_bthis)])
        T1 += _bthis

    # This is the really time consuming PBKDF2 step.
    T2 = kdf.pbkdf2_hmac_sha512(T1, cred.iterations, unhexlify(cred.salt))

    try:
        if cred.version == Version.NDNv2:
            if cred.key_label is None:
                raise ValueError("NDNv2 credential requires key_label for HMAC-SHA-256")
            if new_hasher is None:
                raise RuntimeError("NDNv2 credential requires new_hasher, but new_hasher is not configured")
            local_salt = await new_hasher.hmac_sha256(cred.key_label, T2)
        else:
            if cred.key_handle is None:
                raise ValueError("NDNv1 credential requires key_handle for HMAC-SHA-1")
            local_salt = await hasher.hmac_sha1(cred.key_handle, T2)
    except (ValueError, RuntimeError):
        raise  # Don't wrap ValueError/RuntimeError in another RuntimeError
    except Exception as e:
        raise RuntimeError(f"Hashing operation failed : {e}") from e

    # PBKDF2 again with iter=1 to mix in the local_salt into the final H2.
    H2 = kdf.pbkdf2_hmac_sha512(T2, 1, local_salt)
    return H2.hex()
