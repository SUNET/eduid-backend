from re import findall

from pwgen import pwgen

import vccs_client

from eduid_webapp.signup.app import current_signup_app as current_app


def generate_password(credential_id, user):
    """
    Generate a new password credential and add it to the VCCS authentication backend.

    The salt returned needs to be saved for use in subsequent authentications using
    this password. The password is returned so that it can be conveyed to the user.

    :param credential_id: VCCS credential_id as string
    :param user: user data as dict
    :return: (password, salt) both strings
    """
    user_id = str(user.user_id)
    config = current_app.config
    password = pwgen(int(config.password_length), no_capitalize=True, no_symbols=True)
    factor = vccs_client.VCCSPasswordFactor(password, credential_id)
    current_app.logger.info(
        "Adding VCCS password factor for user {}, " "credential_id {!r}".format(user, credential_id)
    )

    vccs = vccs_client.VCCSClient(base_url=config.vccs_url)
    try:
        result = vccs.add_credentials(user_id, [factor])
    except vccs_client.VCCSClientHTTPError as e:
        current_app.logger.error('There was an error adding credentials for user {} ' ': {!r}'.format(user, e))
        raise e
    current_app.logger.debug("VCCS password (id {!r}) creation result: " "{!r}".format(credential_id, result))

    return _human_readable(password), factor.salt


def _human_readable(password):
    """
    Format a random password more readable to humans (groups of four characters).

    :param password: string
    :return: readable password as string
    :rtype: string
    """
    regexp = '.{,4}'
    parts = findall(regexp, password)
    return ' '.join(parts).rstrip()
