# Solve circular imports of these by having them in a 'leaf' file :/

from enum import StrEnum, unique


@unique
class AuthnAcsAction(StrEnum):
    login = "login-action"
    change_password = "change-password-action"
    terminate_account = "terminate-account-action"
    reauthn = "reauthn-action"


@unique
class EidasAcsAction(StrEnum):
    verify_identity = "verify-identity-action"
    verify_credential = "verify-credential-action"
    mfa_authenticate = "mfa-authenticate-action"


@unique
class BankIDAcsAction(StrEnum):
    verify_identity = "verify-identity-action"
    verify_credential = "verify-credential-action"
    mfa_authenticate = "mfa-authenticate-action"


@unique
class SamlEidAcsAction(StrEnum):
    verify_identity = "verify-identity-action"
    verify_credential = "verify-credential-action"
    mfa_authenticate = "mfa-authenticate-action"
