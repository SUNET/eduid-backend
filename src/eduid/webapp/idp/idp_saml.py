import logging
import typing
from base64 import b64encode
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha1
from typing import Any, NewType

import saml2.server
from pydantic import BaseModel
from saml2 import samlp
from saml2.s_utils import UnknownPrincipal, UnknownSystemEntity, UnravelError, UnsupportedBinding
from saml2.saml import Issuer
from saml2.samlp import RequestedAuthnContext
from saml2.sigver import verify_redirect_signature
from saml2.typing import SAMLBinding
from werkzeug.exceptions import BadRequest

from eduid.webapp.idp.assurance_data import AuthnInfo
from eduid.webapp.idp.mischttp import HttpArgs
from eduid.webapp.idp.settings.common import IdPConfig

if typing.TYPE_CHECKING:
    from eduid.webapp.idp.login_context import LoginContextSAML

ResponseArgs = NewType("ResponseArgs", dict[str, Any])

logger = logging.getLogger(__name__)


class SAMLParseError(Exception):
    pass


class SAMLValidationError(Exception):
    pass


ReqSHA1 = NewType("ReqSHA1", str)


@dataclass
class SAMLResponseParams:
    url: str
    post_params: Mapping[str, str | bool | None]
    binding: str
    http_args: HttpArgs
    missing_attributes: list[dict[str, str]] = field(default_factory=list)


def gen_key(something: str | bytes) -> ReqSHA1:
    """
    Generate a unique (not strictly guaranteed) key based on `something'.

    :param something: String or bytes
    :return: SHA1 digest
    """
    if not isinstance(something, bytes):
        something = something.encode("UTF-8")
    _digest = sha1(something).hexdigest()
    return ReqSHA1(_digest)


SamlResponse = NewType("SamlResponse", str)


class ServiceInfo(BaseModel):
    """Info about the service (SAML SP) where the user is logging in"""

    display_name: dict[str, str]  # locale ('sv', 'en', ...) to display_name

    def to_dict(self) -> dict[str, Any]:
        return self.dict()


class IdP_SAMLRequest:
    def __init__(
        self,
        request: str,
        binding: str,
        idp: saml2.server.Server,
        debug: bool = False,
    ):
        self._request = request
        self._binding = binding
        self._idp = idp
        self._debug = debug
        self._service_info: dict[str, Any] | None = None

        try:
            self._req_info = idp.parse_authn_request(request, binding)
        except UnravelError as exc:
            logger.info(f"Failed parsing SAML request ({len(request)} bytes)")
            logger.debug(f"Failed parsing SAML request:\n{request}\nException {exc}")
            raise SAMLParseError("Failed parsing SAML request")

        if not self._req_info:
            # Either there was no request, or pysaml2 found it to be unacceptable.
            # For example, the IssueInstant might have been out of bounds.
            logger.debug("No valid SAMLRequest returned by pysaml2")
            raise SAMLValidationError("No valid SAMLRequest returned by pysaml2")

        # Only perform expensive parse/pretty-print if debugging
        if debug:
            # Local import to avoid circular imports
            from eduid.webapp.idp.util import maybe_xml_to_string

            xmlstr = maybe_xml_to_string(self._req_info.xmlstr)
            logger.debug(f"Decoded SAMLRequest into AuthnRequest {repr(self._req_info.message)}:\n\n{xmlstr}\n\n")

    @property
    def binding(self) -> str:
        return self._binding

    def verify_signature(self, sig_alg: str, signature: str) -> bool:
        info = {
            "SigAlg": sig_alg,
            "Signature": signature,
            "SAMLRequest": self.request,
        }
        _certs = self._idp.metadata.certs(self.sp_entity_id, "any", "signing")
        verified_ok = False
        # Make sure at least one certificate verifies the signature
        for cert in _certs:
            if verify_redirect_signature(info, cert):
                verified_ok = True
                break
        if not verified_ok:
            _key = gen_key(info["SAMLRequest"])
            logger.info(f"{_key!s}: SAML request signature verification failure")
        return verified_ok

    @property
    def request(self) -> str:
        """The original SAMLRequest XML string."""
        return self._request

    @property
    def raw_requested_authn_context(self) -> RequestedAuthnContext | None:
        return self._req_info.message.requested_authn_context

    def get_requested_authn_contexts(self) -> list[str]:
        """SAML requested authn context."""
        if self.raw_requested_authn_context:
            res = [x.text for x in self.raw_requested_authn_context.authn_context_class_ref]
            for this in res:
                if not isinstance(this, str):
                    raise ValueError(f"Invalid authnContextClassRef value ({repr(this)})")
            return res
        return []

    def get_required_attributes(self) -> list[dict[str, str]]:
        sp_attribute_spec = self._idp.metadata.attribute_requirement(self.sp_entity_id)
        if sp_attribute_spec:
            required = sp_attribute_spec.get("required", [])
            return [{"name": item.get("name"), "friendly_name": item.get("friendly_name")} for item in required]
        return []

    @property
    def raw_sp_entity_id(self) -> Issuer:
        _res = self._req_info.message.issuer
        if not isinstance(_res, Issuer):
            raise ValueError(f"Unknown issuer type ({type(_res)})")
        return _res

    @property
    def sp_entity_id(self) -> str:
        """The entity ID of the service provider as a string."""
        _res = self.raw_sp_entity_id.text
        if not isinstance(_res, str):
            raise ValueError(f"Unknown SP entity id type ({type(_res)})")
        return _res

    @property
    def force_authn(self) -> bool:
        """
        True if the initiator of the request request the IdP to force authentication.

        ForceAuthn in specified as a boolean, and booleans in XML schema can be either 'true', 'false', '1' or '0'.

           https://www.w3.org/TR/xmlschema-2/#boolean
        """
        _res = self._req_info.message.force_authn
        if _res is None:
            return False
        if not isinstance(_res, str):
            raise ValueError(f"Unknown force authn type ({type(_res)})")
        return _res == "1" or _res.lower() == "true"

    @property
    def request_id(self) -> str:
        _res = self._req_info.message.id
        if not isinstance(_res, str):
            raise ValueError(f"Unknown request id type ({type(_res)})")
        return _res

    @property
    def login_subject(self) -> str | None:
        """Get information about who the SP thinks should log in.

        This is used by the IdPProxy when doing MFA Step-up authentication, to signal
        who must log in for the process to continue.

        Most ordinary AuthnRequests don't have a subject.
        """
        try:
            _subject = self._req_info.subject_id()
            if not isinstance(_subject.text, str):
                logger.debug(f"Invalid Subject ID in AuthnRequest (not a string): {_subject.text}")
                return None
            return _subject.text.strip()
        except AttributeError:
            # pysaml trips over itself here if there is no Subject ID: 'NoneType' object has no attribute 'keys'
            logger.debug("No Subject ID in AuthnRequest")
        except Exception as exc:
            logger.debug(f"Could not get Subject ID from AuthnRequest: {exc}")
        return None

    @property
    def sp_entity_attributes(self) -> Mapping[str, Any]:
        """Return the entity attributes for the SP that made the request from the metadata."""
        res: dict[str, Any] = {}
        try:
            _attrs = self._idp.metadata.entity_attributes(self.sp_entity_id)
            for k, v in _attrs.items():
                if not isinstance(k, str):
                    raise ValueError(f"Unknown entity attribute type ({type(k)})")
                res[k] = v
        except KeyError:
            return {}
        return res

    @property
    def service_info(self) -> dict[str, Any] | None:
        """Information about the service where the user is logging in"""
        if self._service_info is None:
            res: dict[str, Any] = {}
            logger.debug(f"Looking up MDUI info in metadata for entity id {self.sp_entity_id}")
            for uiinfo in self._idp.metadata.mdui_uiinfo(self.sp_entity_id):
                if "display_name" in uiinfo:
                    res["display_name"] = {}
                    for item in uiinfo["display_name"]:
                        if "lang" in item and "text" in item:
                            res["display_name"][item["lang"]] = item["text"]
                        self._service_info = res
            if not res:
                logger.debug(f"No MDUI display_name found for entity id {self.sp_entity_id}")
        return self._service_info

    @property
    def sp_digest_algs(self) -> list[str]:
        """Return the best signing algorithm that both the IdP and SP supports"""
        res: list[str] = []
        try:
            _algs = self._idp.metadata.supported_algorithms(self.sp_entity_id)["digest_methods"]
            for this in _algs:
                if not isinstance(this, str):
                    raise ValueError(f"Unknown digest_methods type ({type(this)})")
                res += [this]
        except KeyError:
            return []
        return res

    @property
    def sp_sign_algs(self) -> list[str]:
        """Return the best signing algorithm that both the IdP and SP supports"""
        res: list[str] = []
        try:
            _algs = self._idp.metadata.supported_algorithms(self.sp_entity_id)["signing_methods"]
            for this in _algs:
                if not isinstance(this, str):
                    raise ValueError(f"Unknown signing_methods type ({type(this)})")
                res += [this]
        except KeyError:
            return []
        return res

    def get_response_args(self, log_prefix: str, conf: IdPConfig) -> ResponseArgs:
        try:
            resp_args = self._idp.response_args(self._req_info.message)
        except UnknownPrincipal as excp:
            logger.info(f"{log_prefix}: Unknown service provider: {excp}")
            raise BadRequest("Don't know the SP that referred you here")
        except UnsupportedBinding as excp:
            logger.info(f"{log_prefix}: Unsupported SAML binding: {excp}")
            raise BadRequest("Don't know how to reply to the SP that referred you here")
        except UnknownSystemEntity as exc:
            # TODO: Validate refactoring didn't move this exception handling to the wrong place.
            #       Used to be in an exception handler in _redirect_or_post around perform_login().
            logger.info(f"{log_prefix}: Service provider not known: {exc}")
            raise BadRequest("SAML_UNKNOWN_SP")

        # Set digest_alg and sign_alg to a good default value
        if conf.supported_digest_algorithms:
            resp_args["digest_alg"] = conf.supported_digest_algorithms[0]
            # Try to pick best signing and digest algorithms from what the SP supports
            for digest_alg in conf.supported_digest_algorithms:
                if digest_alg in self.sp_digest_algs:
                    resp_args["digest_alg"] = digest_alg
                    break

        if conf.supported_signing_algorithms:
            resp_args["sign_alg"] = conf.supported_signing_algorithms[0]

            for sign_alg in conf.supported_signing_algorithms:
                if sign_alg in self.sp_sign_algs:
                    resp_args["sign_alg"] = sign_alg
                    break

        return ResponseArgs(resp_args)

    def make_saml_response(
        self, attributes: Mapping[str, Any], userid: str, response_authn: AuthnInfo, resp_args: ResponseArgs
    ) -> SamlResponse:
        # Create pysaml2 dict with the authn information
        authn = dict(class_ref=response_authn.class_ref, authn_instant=int(response_authn.instant.timestamp()))
        saml_response = self._idp.create_authn_response(
            identity=attributes, userid=userid, authn=authn, sign_response=True, **resp_args
        )
        if not isinstance(saml_response, str):
            raise ValueError(f"Unknown saml_response type ({type(saml_response)})")
        return SamlResponse(saml_response)

    def make_cancel_response(self, resp_args: ResponseArgs) -> SamlResponse:
        info = (samlp.STATUS_AUTHN_FAILED, "Request cancelled by user")
        return self.make_error_response(info, resp_args)

    def make_authn_context_class_not_supported_response(self, resp_args: ResponseArgs) -> SamlResponse:
        info = (samlp.STATUS_AUTHN_FAILED, "Authentication context class not supported")
        return self.make_error_response(info, resp_args)

    def make_error_response(self, info: tuple[str, str], resp_args: ResponseArgs) -> SamlResponse:
        saml_response = self._idp.create_error_response(info=info, sign=True, **resp_args)
        logger.debug(f"Cancel SAML response:\n{saml_response}")
        if not isinstance(saml_response, str):
            raise ValueError(f"Unknown saml_response type ({type(saml_response)})")
        return SamlResponse(saml_response)

    def apply_binding(self, resp_args: ResponseArgs, relay_state: str, saml_response: SamlResponse) -> HttpArgs:
        """Create the Javascript self-posting form that will take the user back to the SP with a SAMLResponse."""
        binding = resp_args.get("binding")
        destination = resp_args.get("destination")
        if not binding or not destination:
            raise ValueError(f"Invalid binding or destination: {binding}, {destination}")
        logger.debug(f"Applying binding {binding}, destination {destination}, relay_state {relay_state}")
        _args = self._idp.apply_binding(
            binding=SAMLBinding(binding),
            msg_str=str(saml_response),
            destination=destination,
            relay_state=relay_state,
            response=True,
        )
        # _args is one of these pysaml2 dicts with HTML data, e.g.:
        #  {'headers': [('Content-type', 'text/html')],
        #   'data': '...<body onload="document.forms[0].submit()">, # noqa: ERA001
        #   'url': 'https://sp.example.edu/saml2/acs/',             # noqa: ERA001
        #   'method': 'POST'
        #  }                                                        # noqa: ERA001
        return HttpArgs.from_pysaml2_dict(_args)


def make_saml_response_params(
    saml_response: SamlResponse, resp_args: ResponseArgs, ticket: "LoginContextSAML"
) -> SAMLResponseParams:
    http_args = ticket.saml_req.apply_binding(resp_args, ticket.RelayState, saml_response)
    params = {
        "SAMLResponse": b64encode(str(saml_response).encode("utf-8")).decode("ascii"),
        "RelayState": ticket.RelayState,
    }
    binding = resp_args["binding"]
    saml_params = SAMLResponseParams(url=http_args.url, post_params=params, binding=binding, http_args=http_args)
    return saml_params


def cancel_saml_request(ticket: "LoginContextSAML", conf: IdPConfig) -> "SAMLResponseParams":
    resp_args = ticket.saml_req.get_response_args(ticket.request_ref, conf)
    saml_response = ticket.saml_req.make_cancel_response(resp_args=resp_args)
    return make_saml_response_params(saml_response=saml_response, resp_args=resp_args, ticket=ticket)


def authn_context_class_not_supported(ticket: "LoginContextSAML", conf: IdPConfig) -> "SAMLResponseParams":
    resp_args = ticket.saml_req.get_response_args(ticket.request_ref, conf)
    saml_response = ticket.saml_req.make_authn_context_class_not_supported_response(resp_args=resp_args)
    return make_saml_response_params(saml_response=saml_response, resp_args=resp_args, ticket=ticket)
