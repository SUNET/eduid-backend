# -*- coding: utf-8 -*-
from typing import Optional, Union

from flask import Blueprint, redirect, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import User
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import FluxData
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.authn.utils import get_location
from eduid.webapp.common.proofing.methods import ProofingMethod, get_proofing_method
from eduid.webapp.common.session import session
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import (
    check_credential_to_verify,
)

__author__ = 'lundberg'

from eduid.webapp.eidas.views import _authn

old_eidas_views = Blueprint('old_eidas', __name__, url_prefix='', template_folder='templates')


# TODO: Make frontend use POST /verify-token instead of this endpoint
@old_eidas_views.route('/verify-token/<credential_id>', methods=['GET'])
@require_user
def verify_token(user: User, credential_id: ElementKey) -> Union[FluxData, WerkzeugResponse]:
    current_app.logger.debug(f'verify-token called with credential_id: {credential_id}')
    # Return URL where user should be sent after completed proofing (successful or not)
    redirect_url = current_app.conf.token_verify_redirect_url

    # verify that the user has the credential and that it was used for login recently
    ret = check_credential_to_verify(user=user, credential_id=credential_id)
    if ret.response is not None:
        return ret.response

    # Store the id of the credential that is supposed to be proofed in the session
    session.eidas.verify_token_action_credential_id = credential_id

    # Request an authentication from the idp
    proofing_method = get_proofing_method(method='freja', config=current_app.conf)
    return _authn_redirect(EidasAcsAction.token_verify, proofing_method, finish_url=redirect_url)


# TODO: Make frontend use /verify-identity instead of this endpoint
@old_eidas_views.route('/verify-nin', methods=['GET'])
@require_user
def verify_nin(user: User) -> WerkzeugResponse:
    current_app.logger.debug('verify-nin called')
    proofing_method = get_proofing_method(method='freja', config=current_app.conf)
    return _authn_redirect(
        EidasAcsAction.nin_verify,
        proofing_method,
        finish_url=current_app.conf.identity_verify_redirect_url,
    )


@old_eidas_views.route('/mfa-authentication', methods=['GET'])
def mfa_authentication() -> WerkzeugResponse:
    current_app.logger.debug('mfa-authentication called')
    redirect_url = sanitise_redirect_url(request.args.get('next', '/'))
    proofing_method = get_proofing_method(method='freja', config=current_app.conf)
    return _authn_redirect(EidasAcsAction.mfa_authn, proofing_method, finish_url=redirect_url)


@old_eidas_views.route('/mfa-authentication-foreign-eid', methods=['GET'])
def mfa_authentication_foreign_eid() -> WerkzeugResponse:
    current_app.logger.debug('mfa-authentication foreign eid called')
    redirect_url = sanitise_redirect_url(request.args.get('next', '/'))
    proofing_method = get_proofing_method(method='eidas', config=current_app.conf)
    return _authn_redirect(EidasAcsAction.mfa_authn_foreign_eid, proofing_method, finish_url=redirect_url)


def _authn_redirect(
    action: EidasAcsAction,
    proofing_method: ProofingMethod,
    finish_url: str,
    force_authn: bool = True,
    proofing_credential_id: Optional[ElementKey] = None,
) -> WerkzeugResponse:
    """
    :param action: name of action
    :param force_authn: should a new authentication be forced
    :param finish_url: redirect url after successful authentication

    :return: redirect response
    """
    current_app.logger.debug(f'Requested proofing: {proofing_method}')

    if check_magic_cookie(current_app.conf):
        # set a test IdP with minimal interaction for the integration tests
        idp = current_app.conf.magic_cookie_idp
        current_app.logger.debug(f'Changed requested IdP due to magic cookie: {idp}')

    authn_res = _authn(
        action=action,
        force_authn=force_authn,
        finish_url=finish_url,
        proofing_credential_id=proofing_credential_id,
        proofing_method=proofing_method,
    )

    # TODO: 1. Release code that stores all this in both the SP_AuthnRequest, and the old place: session.mfa_action
    #       2. When all sessions in Redis has data in both places, update the ACS function to read from the new place
    #       3. Remove session.mfa_action
    #

    # Clear session keys used for external mfa
    del session.mfa_action
    # Ideally, we should be able to support multiple ongoing external MFA requests at the same time,
    # but for now at least remember the SAML request id and the login_ref (when the frontend has been
    # updated to supply it to /mfa-authentication) so that the IdP can verify the login_ref matches
    # when processing a successful response in session.mfa_action.
    session.mfa_action.authn_req_ref = authn_res.authn_id
    session.mfa_action.framework = proofing_method.framework
    session.mfa_action.required_loa = proofing_method.required_loa

    current_app.logger.info(f'Redirecting the user to {proofing_method.idp} for {action}')
    return redirect(get_location(authn_res.authn_req))
