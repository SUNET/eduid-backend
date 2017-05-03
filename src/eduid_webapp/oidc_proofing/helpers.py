# -*- coding: utf-8 -*-
from __future__ import absolute_import
import requests
import qrcode
import qrcode.image.svg
import json

from flask import request, make_response, url_for
from flask import current_app, Blueprint
from oic.oic.message import AuthorizationResponse, ClaimsRequest, Claims
from operator import itemgetter
from marshmallow.exceptions import ValidationError

from eduid_userdb.proofing import ProofingUser
from eduid_userdb.nin import Nin
from eduid_common.api.utils import get_unique_hash, StringIO
from eduid_common.api.decorators import require_user, require_eppn, MarshalWith, UnmarshalWith
from eduid_userdb.proofing import OidcProofingState
from eduid_webapp.oidc_proofing import schemas

__author__ = 'lundberg'


def create_proofing_state(user, nin):
    """
    :param user: Proofing user
    :type user: eduid_userdb.proofing.ProofingUser
    :param nin: National Identity Number
    :type nin: str
    :return:
    :rtype:
    """
    state = get_unique_hash()
    nonce = get_unique_hash()
    token = get_unique_hash()
    nin_element = Nin(number=nin, application='eduid_oidc_proofing', verified=False, primary=False)
    proofing_state = OidcProofingState({'eduPersonPrincipalName': user.eppn, 'nin': nin_element.to_dict(),
                                        'state': state, 'nonce': nonce, 'token': token})
    return proofing_state


def do_authn_request(proofing_state, claims_request, redirect_url):
    """
    :param proofing_state: Proofing state for user
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :param claims_request: Requested claims
    :type claims_request: oic.oic.message.ClaimsRequest
    :param redirect_url: authn response url
    :type redirect_url: str
    :return: success
    :rtype: bool
    """
    oidc_args = {
        'client_id': current_app.oidc_client.client_id,
        'response_type': 'code',
        'scope': ['openid'],
        'redirect_uri': redirect_url,
        'state': proofing_state.state,
        'nonce': proofing_state.nonce,
        'claims': claims_request.to_json()
    }
    current_app.logger.debug('AuthenticationRequest args:')
    current_app.logger.debug(oidc_args)

    response = requests.post(current_app.oidc_client.authorization_endpoint, data=oidc_args)
    if response.status_code == 200:
        current_app.logger.debug('Authentication request delivered to provider {!s}'.format(
            current_app.config['PROVIDER_CONFIGURATION_INFO']['issuer']))
        return True
    current_app.logger.error('Bad response from OP: {!s} {!s} {!s}'.format(response.status_code,
                                                                           response.reason, response.content))
    return False


def add_nin_to_user(user, proofing_state):
    """
    :param user: Central userdb user
    :type user: eduid_userdb.user.User
    :param proofing_state: Proofing state for user
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :return: None
    :rtype: None
    """
    proofing_user = ProofingUser(data=user.to_dict())
    # Add nin to user if not already there
    if not proofing_user.nins.find(proofing_state.nin.number):
        nin_element = Nin(data=proofing_state.nin.to_dict())
        nin_element.is_primary = False
        proofing_user.nins.add(nin_element)
        proofing_user.modified_ts = True
        # Save user to private db
        current_app.proofing_userdb.save(proofing_user, check_sync=False)
        # Ask am to sync user to central db
        try:
            current_app.logger.info('Request sync for user {!s}'.format(proofing_user))
            result = current_app.am_relay.request_user_sync(proofing_user)
            current_app.logger.info('Sync result for user {!s}: {!s}'.format(proofing_user, result))
        except Exception as e:
            current_app.logger.error('Sync request failed for user {!s}'.format(proofing_user))
            current_app.logger.error('Exception: {!s}'.format(e))


def handle_seleg_userinfo(user, proofing_state, userinfo):
    """
    :param user: Central userdb user
    :type user: eduid_userdb.user.User
    :param proofing_state: Proofing state for user
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :param userinfo: userinfo from OP
    :type userinfo: dict
    :return: user, success
    :rtype: eduid_userdb.user.User, bool
    """
    # Check proofed nin against self proclaimed OidcProofingState.nin.number
    number = userinfo['identity']
    # Check if the self professed NIN is the same as the NIN returned by the vetting provider
    if proofing_state.nin.number != number:
        current_app.logger.error('NIN does not match for user {}'.format(user))
        current_app.logger.debug('Self professed NIN: {}. NIN from vetting provider {}'.format(
            proofing_state.nin.number, number))
        return user, False
    # Check if the NIN is already verified
    elif any(nin for nin in user.nins.verified if nin.number == number):
        current_app.logger.info('NIN is already verified for user {}'.format(user))
        current_app.logger.debug('NIN: {}'.format(number))
        return user, False
    nin = Nin(data=proofing_state.nin.to_dict())
    nin.is_verified = True
    # Check if the user has more than one verified nin
    if user.nins.primary is None:
        # No primary NIN found, make the only verified NIN primary
        nin.is_primary = True
    user.nins.add(nin)
    return user, True


def handle_freja_userinfo(user, proofing_state, userinfo):
    """
    :param user: Central userdb user
    :type user: eduid_userdb.user.User
    :param proofing_state: Proofing state for user
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :param userinfo: userinfo from OP
    :type userinfo: dict
    :return: user, success
    :rtype: eduid_userdb.user.User, bool
    """
    # TODO
    return user, False
