from enum import unique

from eduid.webapp.common.api.messages import TranslatableMsg


@unique
class OrcidMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # ORCID account already connected to eduID account
    already_connected = "orc.already_connected"
    # Authorization error at ORCID
    authz_error = "orc.authorization_fail"
    # proofing state corresponding to ORCID response not found
    no_state = "orc.unknown_state"
    # nonce received from ORCID not known
    unknown_nonce = "orc.unknown_nonce"
    # The 'sub' of userinfo does not match 'sub' of ID Token for user
    sub_mismatch = "orc.sub_mismatch"
    # ORCID proofing data saved for user
    authz_success = "orc.authorization_success"
