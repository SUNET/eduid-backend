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
    verify_identity = 'verify-identity-action'
    verify_credential = 'verify-credential-action'
    mfa_authenticate = 'mfa-authenticate-action'

    # keep these until old_views are gone. used to send correct success-responses.
    old_token_verify = 'token-verify-action'
    old_nin_verify = 'nin-verify-action'
    old_mfa_authn = 'mfa-authentication-action'


def is_old_action(frontend_action: EidasAcsAction) -> bool:
    return frontend_action in [
        EidasAcsAction.old_mfa_authn,
        EidasAcsAction.old_token_verify,
        EidasAcsAction.old_nin_verify,
    ]
