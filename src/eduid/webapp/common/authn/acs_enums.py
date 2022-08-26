# Solve circular imports of these by having them in a 'leaf' file :/

from enum import Enum, unique


@unique
class AuthnAcsAction(str, Enum):
    login = 'login-action'
    change_password = 'change-password-action'
    terminate_account = 'terminate-account-action'
    reauthn = 'reauthn-action'


@unique
class EidasAcsAction(str, Enum):
    token_verify = 'token-verify-action'
    mfa_authn = 'mfa-authentication-action'
    token_verify_foreign_eid = 'token-verify-foreign-eid-action'
    mfa_authn_foreign_eid = 'mfa-authentication-foreign-eid-action'
    verify_identity = 'verify-identity-action'
    verify_credential = 'verify-credential-action'
    mfa_authenticate = 'mfa-authenticate-action'
