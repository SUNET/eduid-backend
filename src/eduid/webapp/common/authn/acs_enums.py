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
    nin_verify = 'nin-verify-action'
    mfa_authn = 'mfa-authentication-action'
