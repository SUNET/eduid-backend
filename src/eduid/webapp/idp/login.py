# This SAML IdP implementation is derived from the pysaml2 example 'idp2'.
# That code is covered by the following copyright (from pysaml2 LICENSE.txt 2013-05-06) :
#
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY ROLAND HEDBERG ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ROLAND HEDBERG OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# -------------------------------------------------------------------------------
#
# All the changes made during the eduID development are subject to the following
# copyright:
#
# Copyright (c) 2013 SUNET. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY SUNET "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL SUNET OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of SUNET.

"""
Code handling Single Sign On logins.
"""

import hmac
import pprint
import time
from base64 import b64encode
from hashlib import sha256
from typing import Any
from uuid import uuid4

from defusedxml import ElementTree as DefusedElementTree
from flask import redirect
from pydantic import BaseModel, ConfigDict
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from werkzeug.exceptions import BadRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now
from eduid.common.utils import urlappend
from eduid.userdb import User
from eduid.userdb.idp import IdPUser
from eduid.userdb.idp.user import SAMLAttributeSettings
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import IdP_OtherDevicePendingRequest, IdP_SAMLPendingRequest, RequestRef
from eduid.webapp.idp import assurance
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import (
    AssuranceException,
    AuthnContextNotSupported,
    AuthnState,
    IdentityProofingMethodNotAllowed,
    MfaProofingMethodNotAllowed,
    MissingAuthentication,
    MissingMultiFactor,
    MissingSingleFactor,
)
from eduid.webapp.idp.assurance_data import AuthnInfo
from eduid.webapp.idp.helpers import IdPMsg, lookup_user
from eduid.webapp.idp.idp_saml import ResponseArgs, SamlResponse, SAMLResponseParams
from eduid.webapp.idp.login_context import LoginContext, LoginContextOtherDevice, LoginContextSAML
from eduid.webapp.idp.mfa_action import need_security_key
from eduid.webapp.idp.mischttp import get_user_agent
from eduid.webapp.idp.other_device.data import OtherDeviceState
from eduid.webapp.idp.service import SAMLQueryParams, Service
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.tou_action import need_tou_acceptance


class MustAuthenticate(Exception):
    """
    This exception is raised in special circumstances when the IdP decides
    that a user really must authenticate again, even though there exist an
    SSO session.
    """


# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


class NextResult(BaseModel):
    message: IdPMsg
    error: bool = False
    authn_info: AuthnInfo | None = None
    authn_state: AuthnState | None = None
    user: User | None = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __str__(self) -> str:
        return (
            f"<{self.__class__.__name__}: message={self.message.value}, error={self.error}, authn={self.authn_info}, "
            f"user={self.user}>"
        )


def login_next_step(ticket: LoginContext, sso_session: SSOSession | None) -> NextResult:
    """The main state machine for the login flow(s)."""
    if ticket.pending_request.aborted:
        current_app.logger.debug("Login request is aborted")
        return NextResult(message=IdPMsg.aborted)

    if current_app.conf.known_devices_feature_enabled:
        if ticket.known_device_info and ticket.remember_me is False:
            current_app.logger.debug("Forgetting user device upon request by user")
            # User has requested that eduID do not remember them on this device. Forgetting a device is done
            # using ttl to give the user a grace period in which they can revert the decision.
            if ticket.known_device:
                current_app.known_device_db.save(
                    ticket.known_device,
                    from_browser=ticket.known_device_info,
                    ttl=current_app.conf.known_devices_new_ttl,
                )
            ticket.forget_known_device()
            current_app.stats.count("login_known_device_forgotten")

        if not ticket.known_device:
            _require_known_device = True

            ua = get_user_agent()
            if ua and (ua.parsed.is_bot or ua.parsed.browser.family in ["Python Requests", "PingdomBot"]):
                # Except monitoring and bots from the known device requirement (for now at least)
                current_app.logger.debug(f"Not requiring known_device from UA {str(ua)}")

            if ticket.remember_me is False:
                current_app.logger.info("User asks to not be remembered")
                _require_known_device = False

            if _require_known_device:
                current_app.logger.debug("Login request from unknown device")
                return NextResult(message=IdPMsg.unknown_device)

    if current_app.conf.allow_other_device_logins:
        if ticket.is_other_device_1:
            state = None
            if ticket.other_device_state_id:
                state = current_app.other_device_db.get_state_by_id(ticket.other_device_state_id)
            if (
                state
                and state.expires_at > utc_now()
                and state.state in [OtherDeviceState.NEW, OtherDeviceState.IN_PROGRESS]
            ):
                current_app.logger.debug(f"Logging in using another device, {ticket.other_device_state_id}")
                return NextResult(message=IdPMsg.other_device)

    if not isinstance(sso_session, SSOSession):
        current_app.logger.debug("No SSO session found - initiating authentication")
        return NextResult(message=IdPMsg.must_authenticate)

    user = lookup_user(sso_session.eppn, managed_account_allowed=True)
    if not user:
        current_app.logger.error(f"User with eppn {sso_session.eppn} (from SSO session) not found")
        return NextResult(message=IdPMsg.general_failure, error=True)

    if user.terminated:
        current_app.logger.info(f"User {user} is terminated")
        return NextResult(message=IdPMsg.user_terminated, error=True)

    authn_state = AuthnState(user, sso_session, ticket)
    try:
        authn_info = assurance.response_authn(authn_state, ticket, user)
        res = NextResult(message=IdPMsg.proceed, authn_info=authn_info, authn_state=authn_state)
    except MissingSingleFactor:
        res = NextResult(message=IdPMsg.must_authenticate, authn_state=authn_state)
    except MissingMultiFactor:
        res = NextResult(message=IdPMsg.mfa_required, authn_state=authn_state)
    except MissingAuthentication:
        res = NextResult(message=IdPMsg.must_authenticate, authn_state=authn_state)
    except IdentityProofingMethodNotAllowed:
        res = NextResult(message=IdPMsg.identity_proofing_method_not_allowed, error=True)
    except MfaProofingMethodNotAllowed:
        res = NextResult(message=IdPMsg.mfa_proofing_method_not_allowed, error=True)
    except AuthnContextNotSupported:
        res = NextResult(message=IdPMsg.assurance_failure, error=True)
    except AssuranceException as exc:
        current_app.logger.info(f"Assurance not possible: {repr(exc)}")
        res = NextResult(message=IdPMsg.assurance_not_possible, error=True)

    if res.message == IdPMsg.must_authenticate:
        # User might not be authenticated enough for e.g. ToU acceptance yet
        return res

    if user.is_managed_account:
        current_app.logger.debug("Skipping eduID session, TOU and MFA for managed account")
        return res

    # User is at least partially authenticated, put the eppn in the shared session
    if session.common.eppn and session.common.eppn != user.eppn:
        current_app.logger.warning(f"Refusing to change eppn in session from {session.common.eppn} to {user.eppn}")
        return NextResult(message=IdPMsg.wrong_user, error=True)
    session.common.eppn = user.eppn

    if need_tou_acceptance(user):
        return NextResult(message=IdPMsg.tou_required)

    if need_security_key(user, ticket):
        return NextResult(message=IdPMsg.security_key_required, authn_state=authn_state)

    return res


class SSO(Service):
    """
    Single Sign On service.
    """

    def __init__(self, sso_session: SSOSession | None) -> None:
        super().__init__(sso_session)

    def redirect(self) -> WerkzeugResponse:
        """This is the HTTP-redirect endpoint.

        :return: HTTP response
        """
        current_app.logger.debug("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        current_app.logger.debug(f"Unpacked redirect :\n{pprint.pformat(_info)}")

        return self._redirect_or_post(_info, BINDING_HTTP_REDIRECT)

    def post(self) -> WerkzeugResponse:
        """
        The HTTP-Post endpoint

        :return: HTTP response
        """
        current_app.logger.debug("--- In SSO POST ---")
        _info = self.unpack_either()

        return self._redirect_or_post(_info, BINDING_HTTP_POST)

    def _redirect_or_post(self, info: SAMLQueryParams, binding: str) -> WerkzeugResponse:
        """Common code for redirect() and post() endpoints."""

        ticket = get_ticket(info, binding)
        if not ticket:
            # User probably pressed 'back' in the browser after authentication
            current_app.logger.info(f"Redirecting user without a SAML request to {current_app.conf.eduid_site_url}")
            return redirect(current_app.conf.eduid_site_url)

        if not current_app.conf.login_bundle_url:
            raise BadRequest("No login_bundle_url configured")

        if info.SAMLRequest:
            # redirect user to the Login javascript bundle
            loc = urlappend(str(current_app.conf.login_bundle_url), ticket.request_ref)
            current_app.logger.info(f"Redirecting user to login bundle {loc}")
            return redirect(loc)
        else:
            raise BadRequest("No SAMLRequest, and login_bundle_url is set")

    def get_response_params(self, authn_info: AuthnInfo, ticket: LoginContextSAML, user: IdPUser) -> SAMLResponseParams:
        resp_args = self._validate_login_request(ticket)

        try:
            req_authn_context = ticket.get_requested_authn_context()
            current_app.logger.debug(f"Asserting AuthnContext {authn_info} (requested: {req_authn_context})")
        except AttributeError:
            current_app.logger.debug(f"Asserting AuthnContext {authn_info} (none requested)")

        assert self.sso_session  # please mypy
        attributes = self.gather_attributes(response_authn=authn_info, resp_args=resp_args, user=user, ticket=ticket)
        missing_attributes = self.get_missing_attributes(ticket=ticket, attributes=attributes)
        saml_response = self._make_saml_response(
            response_authn=authn_info, resp_args=resp_args, user=user, ticket=ticket, attributes=attributes
        )

        binding = resp_args["binding"]
        destination = resp_args["destination"]
        http_args = ticket.saml_req.apply_binding(resp_args, ticket.RelayState, saml_response)

        # INFO-Log the SSO session id and the AL and destination
        current_app.logger.info(f"{ticket.request_ref}: response authn={authn_info}, dst={destination}")
        _used = ticket.pending_request.used
        ticket.pending_request.used = True
        if not _used:
            self._fticks_log(
                relying_party=resp_args.get("sp_entity_id", destination),
                authn_method=authn_info.class_ref,
                user_id=str(user.user_id),
            )

        params = {
            "SAMLResponse": b64encode(str(saml_response).encode("utf-8")).decode("ascii"),
            "RelayState": ticket.RelayState,
            "used": _used,
        }
        return SAMLResponseParams(
            url=http_args.url,
            post_params=params,
            missing_attributes=missing_attributes,
            binding=binding,
            http_args=http_args,
        )

    def gather_attributes(
        self,
        response_authn: AuthnInfo,
        resp_args: ResponseArgs,
        user: IdPUser,
        ticket: LoginContextSAML,
    ) -> dict[str, Any]:
        sp_identifier = resp_args.get("sp_entity_id", resp_args["destination"])
        current_app.logger.debug(f"Creating SAML response for SP {sp_identifier}")
        sp_entity_categories = ticket.saml_req.sp_entity_attributes.get("http://macedir.org/entity-category", [])
        current_app.logger.debug(f"SP entity categories: {sp_entity_categories}")
        sp_subject_id_request = ticket.saml_req.sp_entity_attributes.get(
            "urn:oasis:names:tc:SAML:profiles:subject-id:req", []
        )
        current_app.logger.debug(f"SP subject id request: {sp_subject_id_request}")
        saml_attribute_settings = SAMLAttributeSettings(
            default_eppn_scope=current_app.conf.default_eppn_scope,
            default_country=current_app.conf.default_country,
            default_country_code=current_app.conf.default_country_code,
            sp_entity_categories=sp_entity_categories,
            sp_subject_id_request=sp_subject_id_request,
            esi_ladok_prefix=current_app.conf.esi_ladok_prefix,
            authn_context_class=response_authn.class_ref,
            pairwise_id=self._get_pairwise_id(relying_party=sp_identifier, user_eppn=user.eppn),
        )
        attributes = user.to_saml_attributes(settings=saml_attribute_settings)

        # Generate eduPersonTargetedID
        if current_app.conf.eduperson_targeted_id_secret_key:
            attributes["eduPersonTargetedID"] = self._get_eptid(relying_party=sp_identifier, user_eppn=user.eppn)

        # Add a list of credentials used in a private attribute that will only be
        # released to the eduID authn component
        attributes["eduidIdPCredentialsUsed"] = [x.cred_id for x in ticket.pending_request.credentials_used.values()]

        # Add attributes from the authn process
        for k, v in response_authn.authn_attributes.items():
            if k in attributes:
                current_app.logger.debug(
                    f"Overwriting user attribute {k} ({attributes[k]!r}) with authn attribute value {v!r}"
                )
            else:
                current_app.logger.debug(f"Adding attribute {k} with value from authn process: {v}")
            attributes[k] = v
        return attributes

    @staticmethod
    def get_missing_attributes(ticket: LoginContextSAML, attributes: dict[str, Any]) -> list[dict[str, str]]:
        missing_attributes = []
        required_attributes = ticket.saml_req.get_required_attributes()
        current_app.logger.debug(f"Required attributes: {required_attributes}")
        for required_attribute in required_attributes:
            # Add attribute as missing if the attribute is missing from the attributes dict or evaluates falsy
            friendly_name = required_attribute.get("friendly_name")
            if friendly_name not in attributes or not attributes.get(friendly_name):
                missing_attributes.append(required_attribute)
        if missing_attributes:
            current_app.logger.info(f"Missing required attributes: {missing_attributes}")
        return missing_attributes

    def _make_saml_response(
        self,
        response_authn: AuthnInfo,
        resp_args: ResponseArgs,
        user: IdPUser,
        ticket: LoginContextSAML,
        attributes: dict[str, Any],
    ) -> SamlResponse:
        """
        Create the SAML response using pysaml2 create_authn_response().

        :param resp_args: pysaml2 response arguments
        :param user: IdP user
        :param ticket: Login process state

        :return: SAML response (string)
        """

        if current_app.conf.debug:
            # Only perform expensive parse/pretty-print if debugging
            pp = pprint.PrettyPrinter()
            current_app.logger.debug(
                f"Creating an AuthnResponse to SAML request {repr(ticket.saml_req.request_id)}:\nUser {user}\n\n"
                f"Attributes:\n{pp.pformat(attributes)},\n\n"
                f"Response args:\n{pp.pformat(resp_args)},\n\n"
                f"Authn:\n{pp.pformat(response_authn)}\n"
            )

        saml_response = ticket.saml_req.make_saml_response(attributes, user.eppn, response_authn, resp_args)
        self._kantara_log_assertion_id(saml_response, ticket)
        return saml_response

    @staticmethod
    def _kantara_log_assertion_id(saml_response: str, ticket: LoginContext) -> None:
        """
        Log the assertion id, which _might_ be required by Kantara.

        :param saml_response: authn response as a compact XML string
        :param ticket: Login process state

        :return: None
        """
        printed = False
        try:
            parser = DefusedElementTree.DefusedXMLParser()
            xml = DefusedElementTree.XML(str(saml_response), parser)

            # For debugging, it is very useful to get the full SAML response pretty-printed in the logfile directly
            current_app.logger.debug(f"Created AuthNResponse :\n\n{DefusedElementTree.tostring(xml)}\n\n")
            printed = True

            attrs = xml.attrib
            assertion = xml.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
            current_app.logger.info(
                "{!s}: id={!s}, in_response_to={!s}, assertion_id={!s}".format(
                    ticket.request_ref, attrs["ID"], attrs["InResponseTo"], assertion.get("ID")
                )
            )
        except Exception as exc:
            current_app.logger.debug(f"Could not parse message as XML: {exc!r}")
            if not printed:
                # Fall back to logging the whole response
                current_app.logger.info(f"{ticket.request_ref}: authn response: {saml_response}")

    @staticmethod
    def _fticks_log(relying_party: str, authn_method: str, user_id: str) -> None:
        """
        Perform SAML F-TICKS logging, for statistics in the SWAMID federation.

        :param relying_party: The entity id of the relying party (SP).
        :param authn_method: The URN of the authentication method used.
        :param user_id: Unique user id.
        """
        if not current_app.conf.fticks_secret_key:
            return
        # Default format string:
        #   'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#',  # noqa: ERA001
        _timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        _anon_userid = hmac.new(
            bytes(current_app.conf.fticks_secret_key, "ascii"), msg=bytes(user_id, "ascii"), digestmod=sha256
        ).hexdigest()
        msg = current_app.conf.fticks_format_string.format(
            ts=_timestamp,
            rp=relying_party,
            ap=current_app.IDP.config.entityid,
            pn=_anon_userid,
            am=authn_method,
        )
        current_app.logger.info(msg)

    @staticmethod
    def _get_rp_specific_unique_id(relying_party: str, user_eppn: str, secret_key: str) -> str:
        """
        Generate a unique id for a user for a specific relying party.
        """
        _sp_user_id = f"{relying_party}-{user_eppn}"
        return hmac.new(
            bytes(secret_key, "ascii"),
            msg=bytes(_sp_user_id, "ascii"),
            digestmod=sha256,
        ).hexdigest()

    def _get_eptid(self, relying_party: str, user_eppn: str) -> list[dict[str, str]]:
        """
        Generate eduPersonTargetedID

        eduPersonTargetedID value is a tuple consisting of an opaque identifier for the principal,
        a name for the source of the identifier, and a name for the intended audience of the identifier.

        Per the SAML format definition, the identifier portion MUST NOT exceed 256 characters, and the
        source and audience URI values MUST NOT exceed 1024 characters.

        :param relying_party: The entity id of the relying party (SP).
        :param user_eppn: Unique user identifier
        """
        _anon_sp_userid = self._get_rp_specific_unique_id(
            relying_party=relying_party,
            user_eppn=user_eppn,
            secret_key=current_app.conf.eduperson_targeted_id_secret_key,
        )
        return [
            {
                "text": _anon_sp_userid,
                "NameQualifier": current_app.IDP.config.entityid,
                "SPNameQualifier": relying_party,
            }
        ]

    def _get_pairwise_id(self, relying_party: str, user_eppn: str) -> str | None:
        """
        Given a particular relying party, a value (the unique ID and scope together) MUST be bound to only one subject,
        but the same unique ID given a different scope may refer to the same or (far more likely) a different subject.
        The same value provided to different relying parties MAY refer to different subjects, and indeed that is the
        primary distinguishing characteristic of this identifier Attribute.

        The value MUST NOT be mappable by a relying party into a non-pairwise identifier for the subject through
        ordinary effort.

        The value consists of two substrings (termed a “unique ID” and a “scope” in the remainder of this definition)
        separated by an @ symbol (ASCII 64) as an inline delimiter.

        The unique ID consists of 1 to 127 ASCII characters, each of which is either an alphanumeric ASCII character,
        an equals sign (ASCII 61), or a hyphen (ASCII 45). The first character MUST be alphanumeric.

        The scope consists of 1 to 127 ASCII characters, each of which is either an alphanumeric ASCII character, a
        hyphen (ASCII 45), or a period (ASCII 46). The first character MUST be alphanumeric.
        """
        if current_app.conf.pairwise_id_secret_key is None:
            return None
        _anon_sp_userid = self._get_rp_specific_unique_id(
            relying_party=relying_party,
            user_eppn=user_eppn,
            secret_key=current_app.conf.pairwise_id_secret_key,
        )
        return f"{_anon_sp_userid}@{current_app.conf.default_eppn_scope}"

    @staticmethod
    def _validate_login_request(ticket: LoginContextSAML) -> ResponseArgs:
        """
        Validate the validity of the SAML request we are going to answer with
        an assertion.

        Checks that the SP is known through metadata.

        Figures out how to respond to this request. Return a dictionary like

          {'destination': 'https://sp.example.org/saml2/acs/',
           'name_id_policy': <saml2.samlp.NameIDPolicy object>,
           'sp_entity_id': 'https://sp.example.org/saml2/metadata/',
           'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
           'in_response_to': 'id-4c45b079f571c57aef34aaaaac4295c9'
           }

        but we dress it up as a ResponseArgs to allow type checking to ensure
        it is used with the right functions later.

        :param ticket: State for this request
        :return: pysaml2 response creation data
        """
        assert isinstance(ticket, LoginContext)
        current_app.logger.debug(f"Validate login request :\n{ticket}")
        current_app.logger.debug(f"AuthnRequest from ticket: {ticket.saml_req!r}")
        return ticket.saml_req.get_response_args(ticket.request_ref, current_app.conf)


# ----------------------------------------------------------------------------
def _add_saml_request_to_session(info: SAMLQueryParams, binding: str) -> RequestRef:
    if info.request_ref:
        # Already present
        return info.request_ref
    if not info.SAMLRequest or binding is None:
        raise ValueError(f"Can't add incomplete query params to session: {info}, binding {binding}")
    request_ref = RequestRef(str(uuid4()))
    session.idp.pending_requests[request_ref] = IdP_SAMLPendingRequest(
        request=info.SAMLRequest, binding=binding, relay_state=info.RelayState
    )
    return request_ref


def get_ticket(info: SAMLQueryParams, binding: str | None) -> LoginContext | None:
    """
    Get the SSOLoginData from the eduid.webapp.common session, or from query parameters.
    """
    logger = current_app.logger

    if info.SAMLRequest:
        if binding is None:
            raise ValueError("Binding must be supplied to add SAML request to session")
        info.request_ref = _add_saml_request_to_session(info, binding)
        logger.debug(f"Added SAML request to session, got reference {info.request_ref}")

    if not info.request_ref:
        raise BadRequest("Bad request, please re-initiate login")

    if info.request_ref not in session.idp.pending_requests:
        logger.debug(f"Ref {info.request_ref} not found in pending requests: {session.idp.pending_requests.keys()}")
        logger.debug(f"Extra debug, full pending requests: {session.idp.pending_requests}")
        return None

    pending = session.idp.pending_requests[info.request_ref]
    if isinstance(pending, IdP_SAMLPendingRequest):
        return LoginContextSAML(request_ref=info.request_ref)
    elif isinstance(pending, IdP_OtherDevicePendingRequest):
        logger.debug(f"get_ticket: Loading IdP_OtherDevicePendingRequest (state_id {pending.state_id})")
        state = None
        if pending.state_id:
            state = current_app.other_device_db.get_state_by_id(pending.state_id)
        if not state:
            current_app.logger.debug(f"Other device: Login id {pending.state_id} not found")
            return None
        current_app.logger.debug(f"Loaded other device state: {pending.state_id}")
        current_app.logger.debug(f"Extra debug: Full other device state:\n{state.to_json()}")

        return LoginContextOtherDevice(request_ref=info.request_ref, other_device_req=state)
    else:
        current_app.logger.warning(f"Can't parse pending request {info.request_ref}: {pending}")

    return None
