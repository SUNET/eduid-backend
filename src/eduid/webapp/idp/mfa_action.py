#
# Copyright (c) 2017 NORDUnet A/S
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
from typing import List, Optional

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.actions import Action
from eduid.userdb.actions.action import ActionResultMFA, ActionResultThirdPartyMFA
from eduid.userdb.credentials import U2F, FidoCredential, Webauthn
from eduid.userdb.idp.user import IdPUser
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import ExternalMfaData, SSOLoginData
from eduid.webapp.common.session.namespaces import OnetimeCredential, OnetimeCredType, ReqSHA1, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance import EduidAuthnContextClass, get_requested_authn_context
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.sso_session import SSOSession

__author__ = 'ft'


def add_actions(user: IdPUser, ticket: SSOLoginData, sso_session: SSOSession) -> Optional[Action]:
    """
    Add an action requiring the user to login using one or more additional
    authentication factors.

    This function is called by the IdP when it iterates over all the registered
    action plugins entry points.

    :param user: the authenticating user
    :param ticket: the in-memory login request context
    :param sso_session: The SSO data persisted in mongodb
    """
    if not current_app.actions_db:
        current_app.logger.warning('No actions_db - aborting MFA action')
        return None

    require_mfa = False
    requested_authn_context = get_requested_authn_context(ticket)
    if requested_authn_context in [
        EduidAuthnContextClass.REFEDS_MFA,
        EduidAuthnContextClass.FIDO_U2F,
    ]:
        require_mfa = True

    # Security Keys
    u2f_tokens = user.credentials.filter(U2F).to_list()
    webauthn_tokens = user.credentials.filter(Webauthn).to_list()
    tokens = u2f_tokens + webauthn_tokens

    if not tokens and not require_mfa:
        current_app.logger.debug('User does not have any FIDO tokens registered and SP did not require MFA')
        return None

    existing_actions = current_app.actions_db.get_actions(user.eppn, ticket.request_ref, action_type='mfa')
    if existing_actions and len(existing_actions) > 0:
        current_app.logger.debug('User has existing MFA actions - checking them')
        if check_authn_result(user, ticket, existing_actions, sso_session):
            return None
        current_app.logger.error('User returned without MFA credentials')

    current_app.logger.debug('Checking for previous MFA authentication for this request')

    for cred_key in ticket.saml_data.credentials_used:
        cred = user.credentials.find(cred_key)
        if isinstance(cred, FidoCredential):
            current_app.logger.debug(f'User has authenticated for this request with FIDO token {cred_key}')
            return None

    current_app.logger.debug(f'User must authenticate with a token (has {len(tokens)} token(s))')
    return current_app.actions_db.add_action(
        user.eppn, action_type='mfa', preference=1, session=ticket.request_ref, params={}
    )


def check_authn_result(user: IdPUser, ticket: SSOLoginData, actions: List[Action], sso_session: SSOSession) -> bool:
    """
    The user returned to the IdP after being sent to actions. Check if actions has
    added the results of authentication to the action in the database.

    :param user: the authenticating user
    :param ticket: the SSO login data
    :param actions: Actions in the ActionDB matching this user and session
    :param sso_session: The SSO data persisted in mongodb

    :return: MFA action with proof of completion found
    """
    if not current_app.actions_db:
        raise RuntimeError('check_authn_result called without actions_db')

    res = False
    _save = False

    for this in actions:
        current_app.logger.debug(f'Processing authn action result:\n{this}')
        if this.result is None:
            continue

        if this.session != ticket.request_ref:
            current_app.logger.warning(
                f'Got action result for another session {this.session} (expected {ticket.request_ref})'
            )

        # TODO: Use timestamp from action result rather than timestamp when we get here
        _utc_now = utc_now()
        if this.result.success is True:
            if isinstance(this.result, ActionResultThirdPartyMFA):
                # External MFA authentication
                sso_session.external_mfa = ExternalMfaData(
                    issuer=this.result.issuer, authn_context=this.result.authn_context, timestamp=_utc_now
                )
                if this.session:
                    # Remember the MFA credential used for this particular request
                    otc = OnetimeCredential(
                        type=OnetimeCredType.external_mfa,
                        issuer=this.result.issuer,
                        authn_context=this.result.authn_context,
                        timestamp=_utc_now,
                    )
                    session.idp.log_credential_used(RequestRef(this.session), otc, _utc_now)
                # TODO: Should we persistently log external MFA usage with log_authn() like we do below?
                current_app.logger.debug(f'Removing MFA action completed with external issuer {this.result.issuer}')
                current_app.actions_db.remove_action_by_id(this.action_id)
                res = True
                continue
            elif isinstance(this.result, ActionResultMFA):
                cred = user.credentials.find(this.result.cred_key)
                if not cred:
                    current_app.logger.error(f'MFA action completed with unknown credential {this.result.cred_key}')
                    continue

                current_app.logger.debug(f'Removing MFA action completed with {cred}')
                current_app.actions_db.remove_action_by_id(this.action_id)

                if not this.result.success:
                    current_app.logger.debug(f'Authentication with credential {cred} was not successful')
                    continue

                authn = AuthnData(cred_id=cred.key, timestamp=_utc_now)
                sso_session.add_authn_credential(authn)
                _save = True

                current_app.authn.log_authn(user, success=[cred.key], failure=[])

                if this.session:
                    # Remember the MFA credential used for this particular request
                    session.idp.log_credential_used(RequestRef(this.session), cred, _utc_now)

                res = True
            else:
                current_app.logger.error(f'Ignoring unknown action result: {type(this.result)}')
    if _save:
        current_app.logger.debug(f'Saving SSO session {sso_session}')
        current_app.sso_sessions.save(sso_session)

    return res
