from flask import Blueprint, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.login import SSO
from eduid.webapp.idp.logout import SLO

saml_views = Blueprint("saml", __name__, url_prefix="")


@saml_views.route("/sso/post", methods=["POST"])
def sso_post() -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleSignOn POST: {request.path} ---")
    sso_session = current_app._lookup_sso_session()
    return SSO(sso_session).post()


@saml_views.route("/sso/redirect", methods=["GET"])
def sso_redirect() -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleSignOn REDIRECT: {request.path} ---")
    sso_session = current_app._lookup_sso_session()
    return SSO(sso_session).redirect()


@saml_views.route("/slo/post", methods=["POST"])
def slo_post() -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleLogOut POST: {request.path} ---")
    sso_session = current_app._lookup_sso_session()
    return SLO(sso_session).post()


@saml_views.route("/slo/soap", methods=["POST"])
def slo_soap() -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleLogOut SOAP: {request.path} ---")
    sso_session = current_app._lookup_sso_session()
    return SLO(sso_session).soap()


@saml_views.route("/slo/redirect", methods=["GET"])
def slo_redirect() -> WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- SingleLogOut REDIRECT: {request.path} ---")
    slo_session = current_app._lookup_sso_session()
    return SLO(slo_session).redirect()
