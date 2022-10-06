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
from typing import Any, Mapping

from flask import request

from eduid.userdb.actions import Action
from eduid.userdb.actions.action import ActionResult, ActionResultMFA, ActionResultTesting, ActionResultThirdPartyMFA
from eduid.webapp.actions.action_abc import ActionPlugin
from eduid.webapp.actions.app import ActionsApp
from eduid.webapp.actions.app import current_actions_app as current_app
from eduid.webapp.actions.helpers import ActionsMsg
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.session import session

__author__ = "ft"


class Plugin(ActionPlugin):

    PLUGIN_NAME = "mfa"
    steps = 1

    @classmethod
    def includeme(cls, app: ActionsApp):
        if not app.conf.eidas_url:
            app.logger.error(f"The configuration option eidas_url is required with plugin MFA")
        if not app.conf.mfa_authn_idp:
            app.logger.error(f"The configuration option mfa_authn_idp is required with plugin MFA")

        app.conf.mfa_testing = False

    def get_config_for_bundle(self, action: Action) -> Mapping[str, Any]:
        eppn = action.eppn
        user = current_app.central_userdb.get_user_by_eppn(eppn)
        current_app.logger.debug("Loaded User {} from db".format(user))
        if not user:
            raise self.ActionError(ActionsMsg.user_not_found)

        config = fido_tokens.start_token_verification(
            user=user,
            fido2_rp_id=current_app.conf.fido2_rp_id,
            fido2_rp_name=current_app.conf.fido2_rp_name,
            state=session.mfa_action,
        )

        # Explicit check for boolean True
        if current_app.conf.mfa_testing is True:
            current_app.logger.info("MFA test mode is enabled")
            config["testing"] = True
        else:
            config["testing"] = False

        # Add config for external mfa auth
        config["eidas_url"] = current_app.conf.eidas_url
        config["mfa_authn_idp"] = current_app.conf.mfa_authn_idp

        return config

    def perform_step(self, action: Action) -> ActionResult:
        current_app.logger.debug("Performing MFA step")
        if current_app.conf.mfa_testing:
            current_app.logger.debug("Test mode is on, faking authentication")
            return ActionResultTesting(success=True, testing=True)

        eppn = action.eppn
        user = current_app.central_userdb.get_user_by_eppn(eppn)
        if not user:
            raise self.ActionError(ActionsMsg.user_not_found)
        current_app.logger.debug(f"Loaded User {user} from db (in perform_action)")

        # Third party service MFA
        if session.mfa_action.success is True:  # Explicit check that success is the boolean True
            issuer = session.mfa_action.issuer
            authn_instant = session.mfa_action.authn_instant
            authn_context = session.mfa_action.authn_context
            current_app.logger.info(f"User {user} logged in using external MFA service {issuer}")
            action.result = ActionResultThirdPartyMFA(
                success=True,
                issuer=issuer,
                authn_instant=authn_instant,
                authn_context=authn_context,
            )
            current_app.actions_db.update_action(action)
            # Clear mfa_action from session
            del session.mfa_action
            return action.result

        req_json = request.get_json(
            silent=True
        )  # silent=True lets get_json return None even if mime-type is not application/json
        if not req_json:
            current_app.logger.error(f"No data in request to authn {user}")
            raise self.ActionError(ActionsMsg.no_data)

        # Process POSTed data
        if "authenticatorData" in req_json:
            # CTAP2/Webauthn
            if not session.mfa_action.webauthn_state:
                current_app.logger.error(f"No webauthn state in session")
                raise self.ActionError(ActionsMsg.no_data)

            try:
                result = fido_tokens.verify_webauthn(
                    user=user,
                    request_dict=req_json,
                    rp_id=current_app.conf.fido2_rp_id,
                    rp_name=current_app.conf.fido2_rp_name,
                    state=session.mfa_action,
                )
            except fido_tokens.VerificationProblem as exc:
                raise self.ActionError(exc.msg)
            finally:
                # reset webauthn_state to avoid challenge reuse
                session.mfa_action.webauthn_state = None

            action.result = ActionResultMFA(
                success=result.success,
                touch=result.touch,
                user_present=result.user_present,
                user_verified=result.user_verified,
                counter=result.counter,
                cred_key=result.credential_key,
            )
            current_app.actions_db.update_action(action)
            return action.result

        current_app.logger.error(f"No Thirdparty-MFA/Webauthn data in request to authn {user}")
        current_app.logger.debug(f"Request: {req_json}")
        raise self.ActionError(ActionsMsg.no_response)
