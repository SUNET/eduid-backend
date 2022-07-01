# -*- coding: utf-8 -*-

from enum import unique

from eduid.webapp.common.api.messages import TranslatableMsg

__author__ = 'lundberg'


@unique
class SvipeIDMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # Authorization error at ORCID
    authz_error = 'svipe_id.authorization_fail'
    # proofing state corresponding to response not found
    no_state = 'svipe_id.unknown_state'
    # nonce not known
    unknown_nonce = 'svipe_id.unknown_nonce'
    # The 'sub' of userinfo does not match 'sub' of ID Token for user
    sub_mismatch = 'svipe_id.sub_mismatch'
    # identity proofing data saved for user
    identity_proofing_success = 'svipe_id.identity_proofing_success'
