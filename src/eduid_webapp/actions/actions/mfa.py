#
# Copyright (c) 2017 NORDUnet A/S
# Copyright (c) 2018 SUNET
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

from flask import request

from eduid_common.authn import fido_tokens
from eduid_common.session import session

from eduid_webapp.actions.action_abc import ActionPlugin
from eduid_webapp.actions.app import current_actions_app as current_app
from eduid_webapp.actions.helpers import ActionsMsg

__author__ = 'ft'


class Plugin(ActionPlugin):

    PLUGIN_NAME = 'mfa'
    PACKAGE_NAME = 'eduid_webapp.actions.actions.mfa'
    steps = 1

    @classmethod
    def includeme(cls, app):
        mandatory_config_keys = ['u2f_app_id', 'u2f_valid_facets', 'fido2_rp_id', 'eidas_url', 'mfa_authn_idp']

        for item in mandatory_config_keys:
            if not getattr(app.config, item):
                app.logger.error(f'The "{item}" configuration option is required')

        app.config.mfa_testing = False

    def get_config_for_bundle(self, action):
        if action.old_format:
            userid = action.user_id
            user = current_app.central_userdb.get_user_by_id(userid, raise_on_missing=False)
        else:
            eppn = action.eppn
            user = current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=False)
        current_app.logger.debug('Loaded User {} from db'.format(user))
        if not user:
            raise self.ActionError(ActionsMsg.user_not_found)

        config = fido_tokens.start_token_verification(user, self.PACKAGE_NAME)

        # Explicit check for boolean True
        if current_app.config.mfa_testing is True:
            current_app.logger.info('MFA test mode is enabled')
            config['testing'] = True
        else:
            config['testing'] = False

        # Add config for external mfa auth
        config['eidas_url'] = current_app.config.eidas_url
        config['mfa_authn_idp'] = current_app.config.mfa_authn_idp

        return config

    def perform_step(self, action):
        current_app.logger.debug('Performing MFA step')
        if current_app.config.mfa_testing:
            current_app.logger.debug('Test mode is on, faking authentication')
            return {
                'success': True,
                'testing': True,
            }

        if action.old_format:
            userid = action.user_id
            user = current_app.central_userdb.get_user_by_id(userid, raise_on_missing=False)
        else:
            eppn = action.eppn
            user = current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=False)
        current_app.logger.debug('Loaded User {} from db (in perform_action)'.format(user))

        # Third party service MFA
        if session.mfa_action.success is True:  # Explicit check that success is the boolean True
            issuer = session.mfa_action.issuer
            authn_instant = session.mfa_action.authn_instant
            authn_context = session.mfa_action.authn_context
            current_app.logger.info('User {} logged in using external mfa service {}'.format(user, issuer))
            action.result = {
                'success': True,
                'issuer': issuer,
                'authn_instant': authn_instant,
                'authn_context': authn_context,
            }
            current_app.actions_db.update_action(action)
            # Clear mfa_action from session
            del session.mfa_action
            return action.result

        req_json = request.get_json()
        if not req_json:
            current_app.logger.error('No data in request to authn {}'.format(user))
            raise self.ActionError(ActionsMsg.no_data)

        # Process POSTed data
        if 'tokenResponse' in req_json:
            # CTAP1/U2F
            token_response = request.get_json().get('tokenResponse', '')
            current_app.logger.debug('U2F token response: {}'.format(token_response))

            challenge = session.get(self.PACKAGE_NAME + '.u2f.challenge')
            current_app.logger.debug('Challenge: {!r}'.format(challenge))

            result = fido_tokens.verify_u2f(user, challenge, token_response)

            if result is not None:
                action.result = result
                current_app.actions_db.update_action(action)
                return action.result

        elif 'authenticatorData' in req_json:
            # CTAP2/Webauthn
            try:
                result = fido_tokens.verify_webauthn(user, req_json, self.PACKAGE_NAME)
            except fido_tokens.VerificationProblem as exc:
                raise self.ActionError(exc.msg)

            action.result = result
            current_app.actions_db.update_action(action)
            return action.result

        else:
            current_app.logger.error('Neither U2F nor Webauthn data in request to authn {}'.format(user))
            current_app.logger.debug('Request: {}'.format(req_json))
            raise self.ActionError(ActionsMsg.no_response)

        raise self.ActionError(ActionsMsg.unknown_token)
