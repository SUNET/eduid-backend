# Solve circular imports of these by having them in a 'leaf' file :/

from enum import Enum, unique


@unique
class AuthnAcsAction(str, Enum):
    login = "login-action"
    change_password = "change-password-action"
    terminate_account = "terminate-account-action"
    reauthn = "reauthn-action"


@unique
class EidasAcsAction(str, Enum):
    verify_identity = "verify-identity-action"
    verify_credential = "verify-credential-action"
    mfa_authenticate = "mfa-authenticate-action"


@unique
class BankIDAcsAction(str, Enum):
    verify_identity = "verify-identity-action"
    verify_credential = "verify-credential-action"
    mfa_authenticate = "mfa-authenticate-action"
