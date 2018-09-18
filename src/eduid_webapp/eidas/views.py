# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app, jsonify
from flask import request, session, redirect, abort, make_response

from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import verify_relay_state
from eduid_common.authn.utils import get_location
from eduid_common.authn.eduid_saml2 import BadSAMLResponse

from eduid_webapp.eidas.helpers import create_authn_request, parse_authn_response, create_metadata

__author__ = 'lundberg'

eidas_views = Blueprint('eidas', __name__, url_prefix='', template_folder='templates')


#@eidas_views.route('/index', methods=['GET'])
#@UnmarshalWith()
#@MarshalWith()
#@require_user
#def index(user):
#    pass

@eidas_views.route('/authn')
def authn(force_authn=False):
    redirect_url = current_app.config.get('SAML2_LOGIN_REDIRECT_URL', '/')
    relay_state = verify_relay_state(request.args.get('next', redirect_url), redirect_url)
    idp = request.args.get('idp')
    idps = current_app.saml2_config.metadata.identity_providers()
    current_app.logger.debug('IdPs from metadata: {}'.format(idps))
    required_loa = 'loa3'
    if idp in idps:
        authn_request = create_authn_request(relay_state, idp, required_loa, force_authn=force_authn)

        current_app.logger.info('Redirecting the user to {} for authn'.format(idp))
        return redirect(get_location(authn_request))
    abort(make_response('IdP ({}) not found in metadata'.format(idp), 404))


@eidas_views.route('/saml2-acs', methods=['POST'])
def assertion_consumer_service():
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """

    if 'SAMLResponse' not in request.form:
        abort(400)

    saml_response = request.form['SAMLResponse']
    try:
        authn_response = parse_authn_response(saml_response)
        current_app.logger.debug('Verified authn response: {}'.format(authn_response))

        session_info = authn_response.session_info()

        current_app.logger.debug('Auth response:\n{!s}\n\n'.format(authn_response))
        current_app.logger.debug('Session info:\n{!s}\n\n'.format(session_info))

        return str(session_info)
    except BadSAMLResponse as e:
        return make_response(str(e), 404)



@eidas_views.route('/saml2-metadata')
def metadata():
    """
    Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the saml2_settings.py file.
    """
    data = create_metadata(current_app.saml2_config)
    response = make_response(data.to_string(), 200)
    response.headers['Content-Type'] = "text/xml; charset=utf8"
    return response
