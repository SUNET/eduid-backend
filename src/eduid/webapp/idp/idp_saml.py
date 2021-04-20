import logging
from dataclasses import dataclass
from hashlib import sha1
from typing import Any, AnyStr, Dict, List, Mapping, NewType, Optional, Type

import six
from werkzeug.exceptions import HTTPException

import saml2.server
from eduid.webapp.idp.mischttp import HttpArgs
from saml2.s_utils import UnknownPrincipal, UnknownSystemEntity, UnravelError, UnsupportedBinding
from saml2.saml import Issuer
from saml2.samlp import RequestedAuthnContext
from saml2.sigver import verify_redirect_signature

ResponseArgs = NewType('ResponseArgs', Dict[str, Any])

logger = logging.getLogger(__name__)


class SAMLParseError(Exception):
    pass


class SAMLValidationError(Exception):
    pass


def gen_key(something: AnyStr) -> str:
    """
    Generate a unique (not strictly guaranteed) key based on `something'.

    :param something: object
    :return:
    """
    if isinstance(something, six.binary_type):
        return sha1(something).hexdigest()
    return sha1(something.encode('UTF-8')).hexdigest()


@dataclass
class AuthnInfo(object):
    """ Information about what AuthnContextClass etc. to put in SAML Authn responses."""

    class_ref: str
    authn_attributes: Dict[str, Any]  # these are added to the user attributes
    instant: Optional[int] = None


SamlResponse = NewType('SamlResponse', str)


class IdP_SAMLRequest(object):
    def __init__(
        self, request: str, binding: str, idp: saml2.server.Server, debug: bool = False,
    ):
        self._request = request
        self._binding = binding
        self._idp = idp
        self._debug = debug

        try:
            self._req_info = idp.parse_authn_request(request, binding)
        except UnravelError as exc:
            logger.info(f'Failed parsing SAML request ({len(request)} bytes)')
            logger.debug(f'Failed parsing SAML request:\n{request}\nException {exc}')
            raise SAMLParseError('Failed parsing SAML request')

        if not self._req_info:
            # Either there was no request, or pysaml2 found it to be unacceptable.
            # For example, the IssueInstant might have been out of bounds.
            logger.debug('No valid SAMLRequest returned by pysaml2')
            raise SAMLValidationError('No valid SAMLRequest returned by pysaml2')

        # Only perform expensive parse/pretty-print if debugging
        if debug:
            # Local import to avoid circular imports
            from eduid.webapp.idp.util import maybe_xml_to_string

            xmlstr = maybe_xml_to_string(self._req_info.xmlstr)
            logger.debug(f'Decoded SAMLRequest into AuthnRequest {repr(self._req_info.message)}:\n\n{xmlstr}\n\n')

    @property
    def binding(self) -> str:
        return self._binding

    def verify_signature(self, sig_alg: str, signature: str) -> bool:
        info = {
            'SigAlg': sig_alg,
            'Signature': signature,
            'SAMLRequest': self.request,
        }
        _certs = self._idp.metadata.certs(self.sp_entity_id, 'any', 'signing')
        verified_ok = False
        # Make sure at least one certificate verifies the signature
        for cert in _certs:
            if verify_redirect_signature(info, cert):
                verified_ok = True
                break
        if not verified_ok:
            _key = gen_key(info['SAMLRequest'])
            logger.info('{!s}: SAML request signature verification failure'.format(_key))
        return verified_ok

    @property
    def request(self) -> str:
        """The original SAMLRequest XML string."""
        return self._request

    @property
    def raw_requested_authn_context(self) -> Optional[RequestedAuthnContext]:
        return self._req_info.message.requested_authn_context

    def get_requested_authn_contexts(self) -> List[str]:
        """ SAML requested authn context. """
        if self.raw_requested_authn_context:
            res = [x.text for x in self.raw_requested_authn_context.authn_context_class_ref]
            for this in res:
                if not isinstance(this, str):
                    raise ValueError(f'Invalid authnContextClassRef value ({repr(this)})')
            return res
        return []

    @property
    def raw_sp_entity_id(self) -> Issuer:
        _res = self._req_info.message.issuer
        if not isinstance(_res, Issuer):
            raise ValueError(f'Unknown issuer type ({type(_res)})')
        return _res

    @property
    def sp_entity_id(self) -> str:
        """The entity ID of the service provider as a string."""
        _res = self.raw_sp_entity_id.text
        if not isinstance(_res, str):
            raise ValueError(f'Unknown SP entity id type ({type(_res)})')
        return _res

    @property
    def force_authn(self) -> bool:
        _res = self._req_info.message.force_authn
        if _res is None:
            return False
        if not isinstance(_res, str):
            raise ValueError(f'Unknown force authn type ({type(_res)})')
        return _res.lower() == 'true'

    @property
    def request_id(self) -> str:
        _res = self._req_info.message.id
        if not isinstance(_res, str):
            raise ValueError(f'Unknown request id type ({type(_res)})')
        return _res

    @property
    def login_subject(self) -> Optional[str]:
        """ Get information about who the SP thinks should log in.

        This is used by the IdPProxy when doing MFA Step-up authentication, to signal
        who must log in for the process to continue.

        Most ordinary AuthnRequests don't have a subject.
        """
        try:
            _subject = self._req_info.subject_id()
            return _subject.text.strip()
        except Exception as exc:
            logger.debug(f'Could not get Subject ID from AuthnRequest: {exc}')
        return None

    @property
    def sp_entity_attributes(self) -> Mapping[str, Any]:
        """Return the entity attributes for the SP that made the request from the metadata."""
        res: Dict[str, Any] = {}
        try:
            _attrs = self._idp.metadata.entity_attributes(self.sp_entity_id)
            for k, v in _attrs.items():
                if not isinstance(k, str):
                    raise ValueError(f'Unknown entity attribute type ({type(k)})')
                _attrs[k] = v
        except KeyError:
            return {}
        return res

    @property
    def sp_digest_algs(self) -> List[str]:
        """Return the best signing algorithm that both the IdP and SP supports"""
        res: List[str] = []
        try:
            _algs = self._idp.metadata.supported_algorithms(self.sp_entity_id)['digest_methods']
            for this in _algs:
                if not isinstance(this, str):
                    raise ValueError(f'Unknown digest_methods type ({type(this)})')
                res += [this]
        except KeyError:
            return []
        return res

    @property
    def sp_sign_algs(self) -> List[str]:
        """Return the best signing algorithm that both the IdP and SP supports"""
        res: List[str] = []
        try:
            _algs = self._idp.metadata.supported_algorithms(self.sp_entity_id)['signing_methods']
            for this in _algs:
                if not isinstance(this, str):
                    raise ValueError(f'Unknown signing_methods type ({type(this)})')
                res += [this]
        except KeyError:
            return []
        return res

    def get_response_args(self, bad_request: Type[HTTPException], key: str) -> ResponseArgs:
        try:
            resp_args = self._idp.response_args(self._req_info.message)
            # not sure if we need to call pick_binding again (already done in response_args()),
            # but it is what we've always done
            binding_out, destination = self._idp.pick_binding('assertion_consumer_service', entity_id=self.sp_entity_id)
            logger.debug(f'Binding: {binding_out}, destination: {destination}')

            resp_args['binding_out'] = binding_out
            resp_args['destination'] = destination
        except UnknownPrincipal as excp:
            logger.info(f'{key}: Unknown service provider: {excp}')
            raise bad_request('Don\'t know the SP that referred you here')
        except UnsupportedBinding as excp:
            logger.info(f'{key}: Unsupported SAML binding: {excp}')
            raise bad_request('Don\'t know how to reply to the SP that referred you here')
        except UnknownSystemEntity as exc:
            # TODO: Validate refactoring didn't move this exception handling to the wrong place.
            #       Used to be in an exception handler in _redirect_or_post around perform_login().
            logger.info(f'{key}: Service provider not known: {exc}')
            raise bad_request('SAML_UNKNOWN_SP')

        return ResponseArgs(resp_args)

    def make_saml_response(
        self, attributes: Mapping[str, Any], userid: str, response_authn: AuthnInfo, resp_args: ResponseArgs
    ) -> SamlResponse:
        # Create pysaml2 dict with the authn information
        authn = dict(class_ref=response_authn.class_ref, authn_instant=response_authn.instant,)
        saml_response = self._idp.create_authn_response(
            attributes, userid=userid, authn=authn, sign_response=True, **resp_args
        )
        if not isinstance(saml_response, str):
            raise ValueError(f'Unknown saml_response type ({type(saml_response)})')
        return SamlResponse(saml_response)

    def apply_binding(self, resp_args: ResponseArgs, relay_state: str, saml_response: SamlResponse) -> HttpArgs:
        """ Create the Javascript self-posting form that will take the user back to the SP with a SAMLResponse.
        """
        binding_out = resp_args.get('binding_out')
        destination = resp_args.get('destination')
        logger.debug(
            'Applying binding_out {!r}, destination {!r}, relay_state {!r}'.format(
                binding_out, destination, relay_state
            )
        )
        _args = self._idp.apply_binding(binding_out, str(saml_response), destination, relay_state, response=True)
        # _args is one of these pysaml2 dicts with HTML data, e.g.:
        #  {'headers': [('Content-type', 'text/html')],
        #   'data': '...<body onload="document.forms[0].submit()">,
        #   'url': 'https://sp.example.edu/saml2/acs/',
        #   'method': 'POST'
        #  }
        return HttpArgs.from_pysaml2_dict(_args)
