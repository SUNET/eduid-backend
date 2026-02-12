import logging
import pprint
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from xml.etree.ElementTree import ParseError

from dateutil.parser import parse as dt_parse
from flask import abort, make_response, redirect, request
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.ident import decode
from saml2.response import AuthnResponse, LogoutResponse, StatusError, UnsolicitedResponse
from saml2.saml import Subject
from saml2.typing import SAMLHttpArgs
from werkzeug.exceptions import Forbidden
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb import UserDB
from eduid.userdb.exceptions import MultipleUsersReturned, UserDoesNotExist
from eduid.userdb.user import User
from eduid.webapp.authn.app import current_authn_app as current_app
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.cache import IdentityCache, OutstandingQueriesCache, StateCache
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.authn.utils import SPConfig, get_saml_attribute
from eduid.webapp.common.session import EduidSession, session
from eduid.webapp.common.session.namespaces import AuthnRequestRef, SP_AuthnRequest, SPAuthnData

logger = logging.getLogger(__name__)


class BadSAMLResponse(Exception):
    """Bad SAML response"""


def get_authn_ctx(session_info: SessionInfo) -> EduidAuthnContextClass | None:
    """
    Get the SAML2 AuthnContext of the currently logged in users session.

    session_info is a dict like

        {'authn_info': [('http://www.swamid.se/policy/assurance/al1',
                    ['https://dev.idp.eduid.se/idp.xml'])],
         ...
        }

    :param session_info: The SAML2 session_info
    :return: The first AuthnContext
    """
    try:
        accr = session_info["authn_info"][0][0]
    except KeyError:
        logger.debug("No authn context class found in session_info")
        return None

    try:
        return EduidAuthnContextClass(accr)
    except ValueError:
        logger.error(f"Authn context class {accr} not implemented in EduidAuthnContextClass")
        return None


def get_authn_request(
    saml2_config: SPConfig,
    session: EduidSession,
    relay_state: str,
    authn_id: AuthnRequestRef,
    selected_idp: str | None,
    force_authn: bool = False,
    req_authn_ctx: list | None = None,
    sign_alg: str | None = None,
    digest_alg: str | None = None,
    subject: Subject | None = None,
) -> SAMLHttpArgs:
    logger.debug(f"Authn request args: force_authn={force_authn}")

    client = Saml2Client(saml2_config)

    # authn context class
    kwargs: dict[str, Any] = {}
    if req_authn_ctx is not None:
        logger.debug(f"Requesting AuthnContext {req_authn_ctx}")
        kwargs["requested_authn_context"] = {"authn_context_class_ref": req_authn_ctx, "comparison": "exact"}

    try:
        session_id: str
        info: Mapping[str, Any]
        (session_id, info) = client.prepare_for_authenticate(
            entityid=selected_idp,
            relay_state=relay_state,
            binding=BINDING_HTTP_REDIRECT,
            sigalg=sign_alg,
            digest_alg=digest_alg,
            subject=subject,
            force_authn=str(force_authn).lower(),
            **kwargs,
        )
    except TypeError:
        logger.error("Unable to know which IdP to use")
        raise

    oq_cache = OutstandingQueriesCache(session.authn.sp.pysaml2_dicts)
    oq_cache.set(session_id, authn_id)
    return info


def get_authn_response(
    saml2_config: SPConfig, sp_data: SPAuthnData, session: EduidSession, raw_response: str
) -> tuple[AuthnResponse, AuthnRequestRef]:
    """
    Check a SAML response and return the response.

    The response can be used to retrieve a session_info dict.

    Example session_info:

    {'authn_info': [('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', [],
                     '2019-06-17T00:00:01Z')],
     'ava': {'eduPersonPrincipalName': ['eppn@eduid.se'],
             'eduidIdPCredentialsUsed': ['...']},
     'came_from': 'https://dashboard.eduid.se/profile/personaldata',
     'issuer': 'https://login.idp.eduid.se/idp.xml',
     'name_id': <saml2.saml.NameID object>,
     'not_on_or_after': 156000000,
     'session_index': 'id-foo'}
    """
    client = Saml2Client(saml2_config, identity_cache=IdentityCache(sp_data.pysaml2_dicts))

    oq_cache = OutstandingQueriesCache(sp_data.pysaml2_dicts)
    outstanding_queries = oq_cache.outstanding_queries()

    try:
        # process the authentication response
        response = client.parse_authn_request_response(raw_response, BINDING_HTTP_POST, outstanding_queries)
    except AssertionError as e:
        logger.error("SAML response is not verified")
        raise BadSAMLResponse(EduidErrorsContext.SAML_RESPONSE_FAIL) from e
    except ParseError as e:
        logger.error(f"SAML response is not correctly formatted: {e!r}")
        raise BadSAMLResponse(EduidErrorsContext.SAML_RESPONSE_FAIL) from e
    except UnsolicitedResponse as e:
        logger.error("Unsolicited SAML response")
        # Extra debug to try and find the cause for some of these that seem to be incorrect
        logger.debug(f"Session: {session}")
        logger.debug(f"Outstanding queries cache: {oq_cache}")
        logger.debug(f"Outstanding queries: {outstanding_queries}")
        raise BadSAMLResponse(EduidErrorsContext.SAML_RESPONSE_UNSOLICITED) from e
    except StatusError as e:
        logger.error(f"SAML response was a failure: {e!r}")
        raise BadSAMLResponse(EduidErrorsContext.SAML_RESPONSE_FAIL) from e

    if response is None:
        logger.error("SAML response is None")
        raise BadSAMLResponse(EduidErrorsContext.SAML_RESPONSE_FAIL)

    session_id = response.session_id()
    oq_cache.delete(session_id)

    authn_reqref = outstanding_queries[session_id]
    logger.debug(
        f"Response {session_id}, request reference {authn_reqref}\n"
        f"session info:\n{pprint.pformat(response.session_info())}\n\n"
    )

    return response, authn_reqref


def authenticate(session_info: SessionInfo, strip_suffix: str | None, userdb: UserDB) -> User | None:
    """
    Locate a user using the identity found in the SAML assertion.

    :param session_info: Session info received by pysaml2 client
    :param strip_suffix: SAML scope to strip from the end of the eppn
    :param userdb: In what database to look for the user

    :returns: User, if found
    """
    if session_info is None:
        raise TypeError("Session info is None")

    attribute_values = get_saml_attribute(session_info, "eduPersonPrincipalName")
    if not attribute_values:
        logger.error("Could not find attribute eduPersonPrincipalName in the SAML assertion")
        return None

    saml_user = attribute_values[0]

    # eduPersonPrincipalName might be scoped and the scope (e.g. "@example.com")
    # might have to be removed before looking for the user in the database.
    if strip_suffix:
        saml_user = saml_user.removesuffix(strip_suffix)

    logger.debug(f"Looking for user with eduPersonPrincipalName == {saml_user!r}")
    try:
        return userdb.get_user_by_eppn(saml_user)
    except UserDoesNotExist:
        logger.error(f"No user with eduPersonPrincipalName = {saml_user!r} found")
    except MultipleUsersReturned:
        logger.error(f"There are more than one user with eduPersonPrincipalName == {saml_user!r}")
    return None


def saml_logout(sp_config: SPConfig, user: User, location: str) -> WerkzeugResponse:
    """
    SAML Logout Request initiator.
    This function initiates the SAML2 Logout request
    using the pysaml2 library to create the LogoutRequest.
    """
    if not session.authn.name_id:
        logger.warning(f"The session does not contain the subject id for user {user}")
        session.invalidate()
        logger.info(f"Invalidated session for {user}")
        logger.info(f"Redirection user to {location} for logout")
        return redirect(location)

    # Since we have a subject_id, call the IdP to do a global logout

    state = StateCache(session.authn.sp.pysaml2_dicts)  # _saml2_state in the session
    identity = IdentityCache(session.authn.sp.pysaml2_dicts)  # _saml2_identities in the session
    client = Saml2Client(sp_config, state_cache=state, identity_cache=identity)

    _subject_id = decode(session.authn.name_id)
    logger.info(f"Initiating global logout for {_subject_id}")
    logouts = client.global_logout(_subject_id)
    logger.debug(f"Logout response: {logouts}")

    # Invalidate session, now that Saml2Client is done with the information within.
    session.invalidate()
    logger.info(f"Invalidated session for {user}")

    loresponse = list(logouts.values())[0]
    # loresponse is a dict for REDIRECT binding, and LogoutResponse for SOAP binding
    if isinstance(loresponse, LogoutResponse):
        if loresponse.status_ok():
            location = sanitise_redirect_url(request.form.get("RelayState", location), location)
            return redirect(location)
        else:
            logger.error(f"The logout response was not OK: {loresponse}")
            abort(500)

    headers_tuple = loresponse[1]["headers"]
    location = headers_tuple[0][1]
    logger.info(f"Redirecting {user} to {location} after successful logout")
    return redirect(location)


@dataclass
class AssertionData:
    session_info: SessionInfo
    user: User | None
    authn_data: SP_AuthnRequest
    authn_req_ref: AuthnRequestRef

    def __str__(self) -> str:
        return (
            f"<{self.__class__.__name__}: user={self.user}, authn_data={self.authn_data}, "
            f"session_info={self.session_info}>"
        )


def process_assertion(
    form: Mapping[str, Any],
    sp_data: SPAuthnData,
    strip_suffix: str | None = None,
    authenticate_user: bool = True,
) -> AssertionData | WerkzeugResponse:
    """
    Common code for our various SAML SPs (currently authn and eidas) to process a received SAML assertion.

    If the IdP is our own, we load the list of credentials used for this particular authentication and
    put that in the result. This way, token vetting applications can know that a particular token was
    used for authentication when they request re-authn.
    """
    if "SAMLResponse" not in form:
        abort(400)

    saml_response = form["SAMLResponse"]
    try:
        response, authn_ref = get_authn_response(current_app.saml2_config, sp_data, session, saml_response)
        current_app.logger.debug(f"authn response: {response}")
    except BadSAMLResponse as e:
        current_app.logger.error(f"BadSAMLResponse: {e}")
        if not current_app.conf.errors_url_template:
            return make_response(str(e), 400)
        _ctx = EduidErrorsContext.SAML_RESPONSE_FAIL
        if isinstance(e.args[0], EduidErrorsContext):
            _ctx = e.args[0]
        return goto_errors_response(
            current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_RESPONSE_FAIL,
            rp=current_app.conf.app_name,
        )

    if authn_ref not in sp_data.authns:
        current_app.logger.info("Unknown response. Redirecting user to eduID Errors page")
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn response", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_RESPONSE_UNSOLICITED,
            rp=current_app.saml2_config.entityid,
        )

    authn_data = sp_data.authns[authn_ref]
    current_app.logger.debug(f"Authentication request data retrieved from session: {authn_data}")

    session_info = response.session_info()
    authn_data.authn_instant = dt_parse(session_info["authn_info"][0][2])
    authn_data.asserted_authn_ctx = get_authn_ctx(session_info)

    user = None
    if authenticate_user:
        current_app.logger.debug("Trying to locate the user authenticated by the IdP")
        user = authenticate(session_info, strip_suffix=strip_suffix, userdb=current_app.central_userdb)
        if user is None:
            current_app.logger.error("Could not find the user identified by the IdP")
            raise Forbidden("Access not authorized")

        credentials_used = get_saml_attribute(session_info, "eduidIdPCredentialsUsed")
        if credentials_used:
            for cred_used in credentials_used:
                this = user.credentials.find(cred_used)
                if not this:
                    current_app.logger.warning(f"Could not find credential with key {cred_used} on user {user}")
                    continue
                authn_data.credentials_used += [this.key]

    return AssertionData(session_info=session_info, user=user, authn_data=authn_data, authn_req_ref=authn_ref)
