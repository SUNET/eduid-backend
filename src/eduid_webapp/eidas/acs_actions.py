# -*- coding: utf-8 -*-

from __future__ import absolute_import

from six.moves.urllib_parse import urlencode, urlsplit, urlunsplit
from flask import session, current_app, redirect

from eduid_common.authn.acs_registry import acs_action
from eduid_common.authn.eduid_saml2 import get_authn_ctx
from eduid_common.authn.utils import get_saml_attribute
from eduid_common.api.decorators import require_user
from eduid_common.api.utils import urlappend, save_and_sync_user
from eduid_userdb.proofing.user import ProofingUser
from eduid_userdb.credentials import U2F


__author__ = 'lundberg'


@acs_action('token-verify-action')
@require_user
def token_verify_action(session_info, user):
    url = urlappend(current_app.config['DASHBOARD_URL'], 'security')
    scheme, netloc, path, query_string, fragment = urlsplit(url)

    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
    token_to_verify = proofing_user.credentials.filter(U2F).find(session['verify_token_action_key_id'])

    # TODO: Check that a verified nin is equal to personalIdentityNumber
    asserted_nin = get_saml_attribute(session_info, 'personalIdentityNumber')
    current_app.logger.debug('Asserted NIN: {}'.format(asserted_nin))

    # Check (again) if token was used to authenticate this session
    if token_to_verify.key not in session['eduidIdPCredentialsUsed']:
        new_query_string = urlencode({'msg': ':ERROR:eidas.token_not_in_credentials_used'})
        url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(url)

    # Set token as verified
    token_to_verify.is_verified = True
    token_to_verify.proofing_method = 'SWAMID_AL2_MFA_HI'
    token_to_verify.proofing_version = 'testing'

    # TODO: Create proofing log entry
    issuer = session_info['issuer']
    current_app.logger.debug('Assertion issuer: {}'.format(issuer))
    authn_context = get_authn_ctx(session_info)
    current_app.logger.debug('Authn context: {}'.format(authn_context))
    # TODO: Lookup nin in navet?
    # TODO: Save proofing log entry and save user
    save_and_sync_user(proofing_user)
    current_app.stats.count(name='u2f_token_verified')

    new_query_string = urlencode({'msg': 'eidas.token_verify_success'})
    url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
    return redirect(url)
