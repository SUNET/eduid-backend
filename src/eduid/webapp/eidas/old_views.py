from typing import Optional

from flask import Blueprint, redirect, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb import User
from eduid.userdb.element import ElementKey
from eduid.webapp.common.api.decorators import require_user
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.acs_enums import EidasAcsAction
from eduid.webapp.common.session import session
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import check_credential_to_verify

__author__ = "lundberg"

from eduid.webapp.eidas.views import _authn

old_eidas_views = Blueprint("old_eidas", __name__, url_prefix="", template_folder="templates")


# TODO: Make frontend use POST /verify-credential instead of this endpoint
@old_eidas_views.route("/verify-token/<credential_id>", methods=["GET"])
@require_user
def verify_token(user: User, credential_id: ElementKey) -> WerkzeugResponse:
    current_app.logger.debug(f"verify-token called with credential_id: {credential_id}")

    # verify that the user has the credential and that it was used for login recently
    ret = check_credential_to_verify(user=user, credential_id=credential_id)
    current_app.logger.debug(f"Credential check result: {ret}")
    if not ret.verified_ok:
        if ret.response is not None:
            return ret.response
        if ret.location is not None:
            return redirect(ret.location)
        raise RuntimeError("Credential verification failed, but no response nor location")

    # Store the id of the credential that is supposed to be proofed in the session
    # session.eidas.verify_token_action_credential_id = credential_id

    # Request an authentication from the idp

    redirect_url = current_app.conf.token_verify_redirect_url
    frontend_action = EidasAcsAction.old_token_verify

    return _authn_redirect(
        EidasAcsAction.verify_credential,
        frontend_action=frontend_action,
        redirect_url=redirect_url,
        proofing_credential_id=credential_id,
    )


# TODO: Make frontend use POST /verify-identity instead of this endpoint
@old_eidas_views.route("/verify-nin", methods=["GET"])
@require_user
def verify_nin(user: User) -> WerkzeugResponse:
    current_app.logger.debug("verify-nin called")
    redirect_url = current_app.conf.identity_verify_redirect_url
    frontend_action = EidasAcsAction.old_nin_verify
    return _authn_redirect(EidasAcsAction.verify_identity, frontend_action=frontend_action, redirect_url=redirect_url)


# TODO: Make frontend use POST /mfa-authenticate instead of this endpoint
@old_eidas_views.route("/mfa-authentication", methods=["GET"])
def mfa_authentication() -> WerkzeugResponse:
    current_app.logger.debug("mfa-authentication called")
    redirect_url = sanitise_redirect_url(request.args.get("next", "/"))
    frontend_action = EidasAcsAction.old_mfa_authn
    return _authn_redirect(EidasAcsAction.mfa_authenticate, frontend_action=frontend_action, redirect_url=redirect_url)


def _authn_redirect(
    action: EidasAcsAction,
    frontend_action: str,
    redirect_url: Optional[str] = None,
    proofing_credential_id: Optional[ElementKey] = None,
) -> WerkzeugResponse:
    """
    :param action: name of action
    :param redirect_url: redirect url after successful authentication

    :return: redirect response
    """
    authn_res = _authn(
        action=action,
        method="freja",
        frontend_action=frontend_action,
        proofing_credential_id=proofing_credential_id,
        redirect_url=redirect_url,
    )

    current_app.logger.debug(f"_authn result: {authn_res}")

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

    if not authn_res.url:
        raise RuntimeError("No URL in authn_res")

    current_app.logger.info(f"Redirecting the user to {authn_res.url} for {action}")
    return redirect(authn_res.url)
