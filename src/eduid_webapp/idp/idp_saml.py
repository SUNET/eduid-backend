import logging
import warnings
from dataclasses import dataclass
from hashlib import sha1
from typing import Any, AnyStr, Dict, List, Mapping, NewType, Optional, Type

import saml2.server
import six
from saml2.s_utils import UnknownPrincipal, UnknownSystemEntity, UnravelError, UnsupportedBinding
from saml2.saml import Issuer
from saml2.samlp import RequestedAuthnContext
from saml2.sigver import verify_redirect_signature
from werkzeug.exceptions import HTTPException

ResponseArgs = NewType('ResponseArgs', Dict[str, Any])

# TODO: Rename to logger
module_logger = logging.getLogger(__name__)


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
        self,
        request: str,
        binding: str,
        idp: saml2.server.Server,
        logger: Optional[logging.Logger] = None,
        debug: bool = False,
    ):
        self._request = request
        self._binding = binding
        self._idp = idp
        self._logger = logger
        self._debug = debug

        if self._logger is not None:
            warnings.warn('Object logger deprecated, using module_logger', DeprecationWarning)

        try:
            self._req_info = idp.parse_authn_request(request, binding)
        except UnravelError as exc:
            module_logger.info(f'Failed parsing SAML request ({len(request)} bytes)')
            module_logger.debug(f'Failed parsing SAML request:\n{request}\nException {exc}')
            raise SAMLParseError('Failed parsing SAML request')

        if not self._req_info:
            # Either there was no request, or pysaml2 found it to be unacceptable.
            # For example, the IssueInstant might have been out of bounds.
            module_logger.debug('No valid SAMLRequest returned by pysaml2')
            raise SAMLValidationError('No valid SAMLRequest returned by pysaml2')

        # Only perform expensive parse/pretty-print if debugging
        if debug:
            # Local import to avoid circular imports
            from eduid_webapp.idp.util import maybe_xml_to_string

            xmlstr = maybe_xml_to_string(self._req_info.xmlstr)
            module_logger.debug(
                f'Decoded SAMLRequest into AuthnRequest {repr(self._req_info.message)}:\n\n{xmlstr}\n\n'
            )

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
            module_logger.info('{!s}: SAML request signature verification failure'.format(_key))
        return verified_ok

    @property
    def request(self) -> str:
        """The original SAMLRequest XML string."""
        return self._request

    @property
    def raw_requested_authn_context(self) -> Optional[RequestedAuthnContext]:
        return self._req_info.message.requested_authn_context

    def get_requested_authn_context(self) -> Optional[str]:
        """
        SAML requested authn context.

        TODO: Don't just return the first one, but the most relevant somehow.
        """
        if self.raw_requested_authn_context:
            _res = self.raw_requested_authn_context.authn_context_class_ref[0].text
            if not isinstance(_res, str):
                raise ValueError(f'Unknown class_ref text type ({type(_res)})')
            return _res
        return None

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
    def force_authn(self) -> Optional[bool]:
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
    def sp_entity_attributes(self) -> Mapping[str, Any]:
        """Return the entity attributes for the SP that made the request from the metadata."""
        res: Dict[str, Any] = {}
        try:
            _attrs = self._idp.metadata.entity_attributes(self.sp_entity_id)
            for k, v in _attrs:
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
            module_logger.debug(f'Binding: {binding_out}, destination: {destination}')

            resp_args['binding_out'] = binding_out
            resp_args['destination'] = destination
        except UnknownPrincipal as excp:
            module_logger.info(f'{key}: Unknown service provider: {excp}')
            raise bad_request('Don\'t know the SP that referred you here')
        except UnsupportedBinding as excp:
            module_logger.info(f'{key}: Unsupported SAML binding: {excp}')
            raise bad_request('Don\'t know how to reply to the SP that referred you here')
        except UnknownSystemEntity as exc:
            # TODO: Validate refactoring didn't move this exception handling to the wrong place.
            #       Used to be in an exception handler in _redirect_or_post around perform_login().
            module_logger.info(f'{key}: Service provider not known: {exc}')
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

    def apply_binding(self, resp_args: ResponseArgs, relay_state: str, saml_response: SamlResponse):
        """ Create the Javascript self-posting form that will take the user back to the SP
        with a SAMLResponse.
        """
        binding_out = resp_args.get('binding_out')
        destination = resp_args.get('destination')
        module_logger.debug(
            'Applying binding_out {!r}, destination {!r}, relay_state {!r}'.format(
                binding_out, destination, relay_state
            )
        )
        http_args = self._idp.apply_binding(binding_out, str(saml_response), destination, relay_state, response=True)
        return http_args
