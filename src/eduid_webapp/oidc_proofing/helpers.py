# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
from datetime import datetime, timedelta
from enum import unique
from typing import Any, Mapping

import requests
from flask import render_template
from flask_babel import gettext as _

from eduid_common.api.helpers import number_match_proofing, verify_nin_for_user
from eduid_common.api.messages import TranslatableMsg
from eduid_common.api.utils import get_unique_hash
from eduid_userdb.logs import SeLegProofing, SeLegProofingFrejaEid
from eduid_userdb.proofing import OidcProofingState, ProofingUser
from eduid_userdb.proofing.element import NinProofingElement

from eduid_webapp.oidc_proofing.app import current_oidcp_app as current_app

__author__ = 'lundberg'


@unique
class OIDCMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # Connection error sending a request to the authz endpoint
    no_conn = 'No connection to authorization endpoint'


def create_proofing_state(user, nin):
    """
    :param user: Proofing user
    :param nin: National Identity Number

    :type user: eduid_userdb.proofing.ProofingUser
    :type nin: str

    :return: OidcProofingState
    :rtype: eduid_userdb.proofing.OidcProofingState
    """
    state = get_unique_hash()
    nonce = get_unique_hash()
    token = get_unique_hash()
    nin_element = NinProofingElement.from_dict(dict(number=nin, created_by='oidc_proofing', verified=False))
    proofing_state = OidcProofingState(
        id=None, modified_ts=None, eppn=user.eppn, nin=nin_element, state=state, nonce=nonce, token=token
    )
    return proofing_state


def create_opaque_data(nonce, token):
    """
    :param nonce: Nonce
    :param token: Token

    :type nonce: six.string_types
    :type token: six.string_types

    :return: Opaque data for the user
    :rtype: six.string_types
    """
    # The "1" below denotes the version of the data exchanged, right now only version 1 is supported.
    return '1' + json.dumps({'nonce': nonce, 'token': token})


def get_proofing_state_valid_until(proofing_state, expire_time_hours):
    """
    :param proofing_state: Proofing state for user
    :param expire_time_hours: Expire time in hours

    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type expire_time_hours: int

    :return: Proofing state valid until
    :rtype datetime
    """

    grace_hours = 24 - proofing_state.modified_ts.hour  # Give the user the full day to complete
    return proofing_state.modified_ts + timedelta(hours=expire_time_hours + grace_hours)


def is_proofing_state_expired(proofing_state, expire_time_hours):
    """
    :param proofing_state: Proofing state for user
    :param expire_time_hours: Expire time in hours

    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type expire_time_hours: int

    :return: True/False
    :rtype bool
    """
    valid_until = get_proofing_state_valid_until(proofing_state, expire_time_hours)
    # Use tzinfo from timezone aware mongodb datetime
    if datetime.now(valid_until.tzinfo) > valid_until:
        return True
    return False


def do_authn_request(proofing_state, claims_request, redirect_url):
    """
    :param proofing_state: Proofing state for user
    :param claims_request: Requested claims
    :param redirect_url: authn response url

    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type claims_request: oic.oic.message.ClaimsRequest
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
        'claims': claims_request.to_json(),
    }
    current_app.logger.debug('AuthenticationRequest args:')
    current_app.logger.debug(oidc_args)

    response = requests.post(current_app.oidc_client.authorization_endpoint, data=oidc_args)
    if response.status_code == 200:
        current_app.logger.debug(
            'Authentication request delivered to provider {!s}'.format(
                current_app.config.provider_configuration_info['issuer']
            )
        )
        return True
    current_app.logger.error(
        'Bad response from OP: {!s} {!s} {!s}'.format(response.status_code, response.reason, response.content)
    )
    return False


def send_new_verification_method_mail(user):
    site_name = current_app.config.eduid_site_name
    site_url = current_app.config.eduid_site_url
    subject = _('%(site_name)s account verification', site_name=site_name)

    email_address = user.mail_addresses.primary.email

    context = {
        "site_url": site_url,
        "site_name": site_name,
    }

    text = render_template('redo_verification.txt.jinja2', **context)
    html = render_template('redo_verification.html.jinja2', **context)

    current_app.mail_relay.sendmail(subject, [email_address], text, html)
    current_app.logger.info('Sent email to user {} requesting another vetting method'.format(user))


def handle_seleg_userinfo(user: ProofingUser, proofing_state: OidcProofingState, userinfo: Mapping[str, Any]) -> None:
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param userinfo: userinfo from OP

    :return: None
    """
    current_app.logger.info('Verifying NIN from seleg for user {}'.format(user))
    number = userinfo['identity']
    metadata = userinfo.get('metadata', {})
    if metadata.get('score', 0) == 100:
        if not number_match_proofing(user, proofing_state, number):
            current_app.logger.warning(
                'Proofing state number did not match number in userinfo. Using number from userinfo.'
            )
            proofing_state.nin.number = number
        current_app.logger.info('Getting address for user {}'.format(user))
        # Lookup official address via Navet
        address = current_app.msg_relay.get_postal_address(proofing_state.nin.number, timeout=15)
        # Transaction id is the same data as used for the QR code
        transaction_id = metadata['opaque']
        proofing_log_entry = SeLegProofing(
            user,
            created_by=proofing_state.nin.created_by,
            nin=proofing_state.nin.number,
            vetting_by='se-leg',
            transaction_id=transaction_id,
            user_postal_address=address,
            proofing_version='2017v1',
        )
        if not verify_nin_for_user(user, proofing_state, proofing_log_entry):
            current_app.logger.error(f'Verifying NIN for user {user} failed')
            # TODO: propagate error to caller
            return None
        current_app.stats.count(name='seleg.nin_verified')
    else:
        current_app.logger.info('se-leg proofing did not result in a verified account due to low score')
        current_app.stats.count(name='seleg.authn_response_with_low_score')
        send_new_verification_method_mail(user)


def handle_freja_eid_userinfo(user, proofing_state, userinfo):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param userinfo: userinfo from OP

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type userinfo: dict

    :return: None
    """
    current_app.logger.info('Verifying NIN from Freja eID for user {}'.format(user))
    number = userinfo['results']['freja_eid']['ssn']
    opaque = userinfo['results']['freja_eid']['opaque']
    transaction_id = userinfo['results']['freja_eid']['ref']
    if not number_match_proofing(user, proofing_state, number):
        current_app.logger.warning(
            'Proofing state number did not match number in userinfo.' 'Using number from userinfo.'
        )
        proofing_state.nin.number = number

    current_app.logger.info('Getting address for user {}'.format(user))
    # Lookup official address via Navet
    address = current_app.msg_relay.get_postal_address(proofing_state.nin.number, timeout=15)
    proofing_log_entry = SeLegProofingFrejaEid(
        user,
        created_by=proofing_state.nin.created_by,
        nin=proofing_state.nin.number,
        transaction_id=transaction_id,
        opaque_data=opaque,
        user_postal_address=address,
        proofing_version='2017v1',
    )
    if not verify_nin_for_user(user, proofing_state, proofing_log_entry):
        current_app.logger.error(f'Verifying NIN for user {user} failed')
        # TODO: Propagate error to caller
        return None
    current_app.stats.count(name='freja.nin_verified')
