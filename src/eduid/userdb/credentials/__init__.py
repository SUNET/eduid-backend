from eduid.userdb.credentials.base import Credential
from eduid.userdb.credentials.fido import U2F, FidoCredential, Webauthn
from eduid.userdb.credentials.list import CredentialList
from eduid.userdb.credentials.password import Password

# well-known proofing methods
METHOD_SWAMID_AL2_MFA = 'SWAMID_AL2_MFA'
METHOD_SWAMID_AL2_MFA_HI = 'SWAMID_AL2_MFA_HI'
