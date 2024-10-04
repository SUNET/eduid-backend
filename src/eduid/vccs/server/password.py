from binascii import unhexlify

from ndnkdf import NDNKDF

from eduid.vccs.server.db import PasswordCredential
from eduid.vccs.server.factors import RequestFactor
from eduid.vccs.server.hasher import VCCSYHSMHasher
from eduid.vccs.server.log import audit_log


async def authenticate_password(
    cred: PasswordCredential, factor: RequestFactor, user_id: str, hasher: VCCSYHSMHasher, kdf: NDNKDF
) -> bool:
    res = False
    H2 = await calculate_cred_hash(user_id=user_id, H1=factor.H1, cred=cred, hasher=hasher, kdf=kdf)
    # XXX need to log successful login in credential_store to be able to ban
    # accounts after a certain time of inactivity (Kantara AL2_CM_CSM#050)
    # XXX can as well log counter of invalid attempts per credential too -
    # so that credentials that have had a total of too many failed logins
    # can be blocked based on that
    # Avoid logging the full hashes to make the audit logs less sensitive.
    # 16 chars (8 bytes) should still be unique enough for 'all' purposes.
    if H2 == cred.derived_key:
        audit_log(f"result=OK, factor=password, credential_id={cred.credential_id}, H2[16]={H2[:16]}")
        res = True
    else:
        audit_log(
            f"result=FAIL, factor=password, credential_id={cred.credential_id}, H2[16]={H2[:16]}, "
            f"stored[16]={cred.derived_key[:16]}"
        )
    return res


async def calculate_cred_hash(
    user_id: str, H1: str, cred: PasswordCredential, hasher: VCCSYHSMHasher, kdf: NDNKDF
) -> str:
    """
    Calculate the expected password hash value for a credential, along this
    pseudo code :

    T1 = 'A' | user_id | credential_id | H1
    T2 = PBKDF2-HMAC-SHA512(T1, iterations=many, salt)
    local_salt = yhsm_hmac_sha1(T2)
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
        if len(this) > 255:
            raise RuntimeError(f"Too long T1 component ({repr(this[:10])}... length {len(this)})")
        # length-encode each part, to avoid having a designated delimiter that
        # could potentially be misused
        T1 += bytes([len(_bthis)])
        T1 += _bthis

    # This is the really time consuming PBKDF2 step.
    T2 = kdf.pbkdf2_hmac_sha512(T1, cred.iterations, unhexlify(cred.salt))

    try:
        # If speed becomes an issue, truncating T2 to 48 bytes would decrease the
        # time it takes the YubiHSM to compute the HMAC-SHA-1 from around 1.9 ms
        # to around 1.2 ms.
        #
        # The difference is likely due to > 48 bytes requiring more USB transactions.
        local_salt = await hasher.hmac_sha1(cred.key_handle, T2)
    except Exception as e:
        raise RuntimeError(f"Hashing operation failed : {e}")

    # PBKDF2 again with iter=1 to mix in the local_salt into the final H2.
    H2 = kdf.pbkdf2_hmac_sha512(T2, 1, local_salt)
    return H2.hex()
