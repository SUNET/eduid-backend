from eduid_userdb.credentials.base import Credential
from eduid_userdb.credentials.fido import U2F, FidoCredential, Webauthn, u2f_from_dict, webauthn_from_dict
from eduid_userdb.credentials.list import CredentialList
from eduid_userdb.credentials.password import Password, password_from_dict

# well-known proofing methods
METHOD_SWAMID_AL2_MFA = 'SWAMID_AL2_MFA'
METHOD_SWAMID_AL2_MFA_HI = 'SWAMID_AL2_MFA_HI'
