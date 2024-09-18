from flask import Blueprint, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import uses_sso_session
from eduid.webapp.idp.login import SSO
from eduid.webapp.idp.logout import SLO
from eduid.webapp.idp.sso_session import SSOSession

saml_views = Blueprint("saml", __name__, url_prefix="")


@saml_views.route("/sso/post", methods=["POST"])
@uses_sso_session
def sso_post(sso_session: SSOSession | None) -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleSignOn POST: {request.path} ---")
    return SSO(sso_session).post()


@saml_views.route("/sso/redirect", methods=["GET"])
@uses_sso_session
def sso_redirect(sso_session: SSOSession | None) -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleSignOn REDIRECT: {request.path} ---")
    return SSO(sso_session).redirect()


@saml_views.route("/slo/post", methods=["POST"])
@uses_sso_session
def slo_post(sso_session: SSOSession | None) -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleLogOut POST: {request.path} ---")
    return SLO(sso_session).post()


@saml_views.route("/slo/soap", methods=["POST"])
@uses_sso_session
def slo_soap(sso_session: SSOSession | None) -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleLogOut SOAP: {request.path} ---")
    return SLO(sso_session).soap()


@saml_views.route("/slo/redirect", methods=["GET"])
@uses_sso_session
def slo_redirect(sso_session: SSOSession | None) -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleLogOut REDIRECT: {request.path} ---")
    return SLO(sso_session).redirect()
