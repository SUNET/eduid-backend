#!/usr/bin/python
#
# Copyright (c) 2014 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#
import base64
import logging
from typing import Optional, Sequence, Union

from eduid.webapp.common.session.logindata import SSOLoginData
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import EduidAuthnContextClass

logger = logging.getLogger(__name__)


def b64encode(source: Union[str, bytes]) -> str:
    if isinstance(source, str):
        _source = bytes(source, 'utf-8')
    else:
        _source = source
    return base64.b64encode(_source).decode('utf-8')


def maybe_xml_to_string(message: Union[str, bytes]) -> str:
    """
    Try to parse message as an XML string, and then return it pretty-printed.

    If message couldn't be parsed, return string representation of it instead.

    This is used to (debug-)log SAML requests/responses in a readable way.

    :param message: XML string typically
    :return: something ready for logging
    """
    if isinstance(message, bytes):
        # message is returned as binary from pysaml2 in python3
        message = message.decode('utf-8')
    try:
        from defusedxml import ElementTree as DefusedElementTree

        parser = DefusedElementTree.DefusedXMLParser()
        xml = DefusedElementTree.XML(message, parser)
        _xml = DefusedElementTree.tostring(xml)
        if not isinstance(_xml, bytes):
            # how odd for a function called tostring to not return a string...
            raise ValueError('DefusedElementTree.tostring() did not return bytes')
        return _xml.decode('utf-8')
    except Exception:
        current_app.logger.exception(f'Could not parse message of type {type(message)!r} as XML')
        return message


def get_requested_authn_context(ticket: SSOLoginData) -> Optional[EduidAuthnContextClass]:
    """
    Check if the SP has explicit Authn preferences in the metadata (some SPs are not
    capable of conveying this preference in the RequestedAuthnContext)

    TODO: Don't just return the first one, but the most relevant somehow.
    """
    _accrs = ticket.saml_req.get_requested_authn_contexts()

    res = _pick_authn_context(_accrs, ticket.key)

    attributes = ticket.saml_req.sp_entity_attributes
    if 'http://www.swamid.se/assurance-requirement' in attributes:
        # TODO: This is probably obsolete and not present anywhere in SWAMID metadata anymore
        new_authn = _pick_authn_context(attributes['http://www.swamid.se/assurance-requirement'], ticket.key)
        current_app.logger.debug(
            f'Entity {ticket.saml_req.sp_entity_id} has AuthnCtx preferences in metadata. '
            f'Overriding {res} -> {new_authn}'
        )
        try:
            res = EduidAuthnContextClass(new_authn)
        except ValueError:
            logger.debug(f'Ignoring unknown authnContextClassRef found in metadata: {new_authn}')
    return res


def _pick_authn_context(accrs: Sequence[str], log_tag: str) -> Optional[EduidAuthnContextClass]:
    if len(accrs) > 1:
        logger.warning(f'{log_tag}: More than one authnContextClassRef, using the first recognised: {accrs}')
    # first, select the ones recognised by this IdP
    known = []
    for x in accrs:
        try:
            known += [EduidAuthnContextClass(x)]
        except ValueError:
            logger.debug(f'Ignoring unknown authnContextClassRef: {x}')
    if not known:
        return None
    # TODO: Pick the most applicable somehow, not just the first one in the list
    return known[0]
