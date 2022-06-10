# -*- coding: utf-8 -*-

import logging
from dataclasses import dataclass
from enum import unique
from typing import Any, Dict, List, Optional, Union

from dateutil.parser import parse as dt_parse
from flask import redirect, request, url_for, abort, make_response

from eduid.webapp.common.api.errors import goto_errors_response, EduidErrorsContext
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.metadata import entity_descriptor
from saml2.request import AuthnRequest
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.exceptions import AmTaskFailed, MsgTaskFailed, NoNavetData
from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.common.utils import urlappend
from eduid.userdb import User
from eduid.userdb.credentials import Credential, FidoCredential
from eduid.userdb.credentials.external import SwedenConnectCredential, TrustFramework
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import EIDASIdentity, EIDASLoa, IdentityType, PridPersistence
from eduid.userdb.logs import MFATokenProofing, SwedenConnectProofing
from eduid.userdb.logs.element import MFATokenEIDASProofing, SwedenConnectEIDASProofing
from eduid.userdb.proofing import NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.webapp.authn.helpers import credential_used_to_authenticate
from eduid.webapp.common.api.helpers import (
    ProofingNavetData,
    check_magic_cookie,
    get_proofing_log_navet_data,
    verify_nin_for_user,
)
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg, redirect_with_msg
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.authn.cache import OutstandingQueriesCache
from eduid.webapp.common.authn.session_info import SessionInfo
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import AuthnRequestRef
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.saml_session_info import BaseSessionInfo, ForeignEidSessionInfo, NinSessionInfo

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


@unique
class EidasMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # LOA 3 not needed
    authn_context_mismatch = 'eidas.authn_context_mismatch'
    # re-authentication expired
    reauthn_expired = 'eidas.reauthn_expired'
    # the token was not used to authenticate this session
    token_not_in_creds = 'eidas.token_not_in_credentials_used'
    # the personalIdentityNumber from Sweden Connect does not correspond
    # to a verified nin in the user's account
    nin_not_matching = 'eidas.nin_not_matching'
    # prid does not correspond to the verified foreign eid
    foreign_eid_not_matching = 'eidas.foreign_eid_not_matching'
    # successfully verified the token
    verify_success = 'eidas.token_verify_success'
    # The user already has a verified NIN
    nin_already_verified = 'eidas.nin_already_verified'
    # The user already has a verified EIDAS identity
    foreign_eid_already_verified = 'eidas.foreign_eid_already_verified'
    # Successfully verified the NIN
    nin_verify_success = 'eidas.nin_verify_success'
    # Successfully verified the foreign eid
    foreign_eid_verify_success = 'eidas.foreign_eid_verify_success'
    # missing redirect URL for mfa authn
    no_redirect_url = 'eidas.no_redirect_url'
    # Action completed, redirect to actions app
    action_completed = 'actions.action-completed'
    # Token not found on the credentials in the user's account
    token_not_found = 'eidas.token_not_found'
    # Attribute missing from IdP
    attribute_missing = 'eidas.attribute_missing'


@dataclass
class VerifyUserResult:
    user: Optional[ProofingUser] = None
    error_message: Optional[TranslatableMsg] = None


def create_authn_request(
    authn_ref: AuthnRequestRef,
    framework: TrustFramework,
    selected_idp: str,
    required_loa: List[str],
    force_authn: bool = False,
) -> AuthnRequest:

    if framework not in [TrustFramework.SWECONN, TrustFramework.EIDAS]:
        raise ValueError(f'Unrecognised trust framework: {framework}')

    kwargs: Dict[str, Any] = {
        "force_authn": str(force_authn).lower(),
    }

    # LOA
    logger.debug('Requesting AuthnContext {}'.format(required_loa))
    loa_uris = [current_app.conf.authentication_context_map[loa] for loa in required_loa]
    kwargs['requested_authn_context'] = {'authn_context_class_ref': loa_uris, 'comparison': 'exact'}

    client = Saml2Client(current_app.saml2_config)
    try:
        session_id, info = client.prepare_for_authenticate(
            entityid=selected_idp,
            relay_state=authn_ref,
            binding=BINDING_HTTP_REDIRECT,
            sigalg=current_app.conf.authn_sign_alg,
            digest_alg=current_app.conf.authn_digest_alg,
            **kwargs,
        )
    except TypeError:
        logger.error('Unable to know which IdP to use')
        raise

    oq_cache = OutstandingQueriesCache(session.eidas.sp.pysaml2_dicts)
    oq_cache.set(session_id, authn_ref)
    return info


def is_required_loa(session_info: SessionInfo, required_loa: List[str]) -> bool:
    parsed_session_info = BaseSessionInfo(**session_info)
    if not required_loa:
        logger.debug(f'No LOA required, allowing {parsed_session_info.authn_context}')
        return True
    loa_uris = [current_app.conf.authentication_context_map.get(loa) for loa in required_loa]
    if not loa_uris:
        logger.error(f'LOA {required_loa} not found in configuration (authentication_context_map), disallowing')
        return False
    if parsed_session_info.authn_context in loa_uris:
        logger.debug(f'Asserted authn context {parsed_session_info.authn_context} matches required {required_loa}')
        return True
    logger.error('Asserted authn context class does not match required class')
    logger.error(f'Asserted: {parsed_session_info.authn_context}')
    logger.error(f'Required: {loa_uris} ({required_loa})')
    return False


def authn_context_class_to_loa(session_info: BaseSessionInfo) -> Optional[str]:
    for key, value in current_app.conf.authentication_context_map.items():
        if value == session_info.authn_context:
            return key
    return None


def is_valid_reauthn(session_info: SessionInfo, max_age: int = 60) -> bool:
    """
    :param session_info: The SAML2 session_info
    :param max_age: Max time (in seconds) since authn that is to be allowed
    :return: True if authn instant is no older than max_age
    """
    parsed_session_info = BaseSessionInfo(**session_info)
    now = utc_now()
    age = now - parsed_session_info.authn_instant
    if age.total_seconds() <= max_age:
        logger.debug(
            f'Re-authn is valid, authn instant {parsed_session_info.authn_instant}, age {age}, max_age {max_age}s'
        )
        return True
    logger.error(f'Authn instant {parsed_session_info.authn_instant} too old (age {age}, max_age {max_age} seconds)')
    return False


def create_nin_proofing_element(
    proofing_user: ProofingUser, session_info: NinSessionInfo, navet_proofing_data: ProofingNavetData
) -> SwedenConnectProofing:
    return SwedenConnectProofing(
        eppn=proofing_user.eppn,
        created_by=current_app.conf.app_name,
        nin=session_info.attributes.nin,
        issuer=session_info.issuer,
        authn_context_class=session_info.authn_context,
        user_postal_address=navet_proofing_data.user_postal_address,
        deregistration_information=navet_proofing_data.deregistration_information,
        proofing_version=current_app.conf.nin_proofing_version,
    )


def verify_nin_from_external_mfa(proofing_user: ProofingUser, session_info: NinSessionInfo) -> VerifyUserResult:

    if check_magic_cookie(current_app.conf):
        # change asserted nin to nin from the integration test cookie
        magic_cookie_nin = request.cookies.get('nin')
        if magic_cookie_nin is None:
            current_app.logger.error("Bad nin cookie")
            return VerifyUserResult(error_message=CommonMsg.nin_invalid)
        # verify nin with bogus data and without Navet interaction for integration test
        return nin_verify_BACKDOOR(proofing_user=proofing_user, asserted_nin=magic_cookie_nin)

    # Create a proofing log
    try:
        navet_proofing_data = get_proofing_log_navet_data(nin=session_info.attributes.nin)
    except NoNavetData:
        current_app.logger.exception('No data returned from Navet')
        return VerifyUserResult(error_message=CommonMsg.no_navet_data)
    except MsgTaskFailed:
        current_app.logger.exception('Navet lookup failed')
        current_app.stats.count('navet_error')
        return VerifyUserResult(error_message=CommonMsg.navet_error)

    proofing_log_entry = create_nin_proofing_element(
        proofing_user=proofing_user, session_info=session_info, navet_proofing_data=navet_proofing_data
    )
    # Verify NIN for user
    try:
        nin_element = NinProofingElement(
            number=session_info.attributes.nin, created_by=current_app.conf.app_name, is_verified=False
        )
        proofing_state = NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)
        if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry):
            current_app.logger.error(f'Failed verifying NIN for user {proofing_user}')
            return VerifyUserResult(error_message=CommonMsg.temp_problem)
    except AmTaskFailed:
        current_app.logger.exception('Verifying NIN for user failed')
        return VerifyUserResult(error_message=CommonMsg.temp_problem)

    current_app.stats.count(name='nin_verified')
    # load the user from central db before returning
    user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
    assert user is not None  # please mypy
    return VerifyUserResult(user=ProofingUser.from_user(user, current_app.private_userdb))


def create_eidas_mfa_proofing_element(
    proofing_user: ProofingUser, session_info: ForeignEidSessionInfo, token_to_verify: Credential
) -> MFATokenEIDASProofing:
    return MFATokenEIDASProofing(
        eppn=proofing_user.eppn,
        created_by=current_app.conf.app_name,
        issuer=session_info.issuer,
        authn_context_class=session_info.authn_context,
        prid=session_info.attributes.prid,
        prid_persistence=session_info.attributes.prid_persistence,
        eidas_person_identifier=session_info.attributes.eidas_person_identifier,
        given_name=session_info.attributes.given_name,
        surname=session_info.attributes.surname,
        date_of_birth=session_info.attributes.date_of_birth.strftime('%Y-%m-%d'),
        country_code=session_info.attributes.country_code,
        transaction_identifier=session_info.attributes.transaction_identifier,
        proofing_version=current_app.conf.security_key_foreign_eid_proofing_version,
        key_id=token_to_verify.key,
    )


def create_eidas_proofing_element(
    proofing_user: ProofingUser, session_info: ForeignEidSessionInfo
) -> SwedenConnectEIDASProofing:
    return SwedenConnectEIDASProofing(
        eppn=proofing_user.eppn,
        created_by=current_app.conf.app_name,
        issuer=session_info.issuer,
        authn_context_class=session_info.authn_context,
        prid=session_info.attributes.prid,
        prid_persistence=session_info.attributes.prid_persistence,
        eidas_person_identifier=session_info.attributes.eidas_person_identifier,
        given_name=session_info.attributes.given_name,
        surname=session_info.attributes.surname,
        date_of_birth=session_info.attributes.date_of_birth.strftime('%Y-%m-%d'),
        country_code=session_info.attributes.country_code,
        transaction_identifier=session_info.attributes.transaction_identifier,
        proofing_version=current_app.conf.foreign_eid_proofing_version,
    )


def verify_eidas_from_external_mfa(
    proofing_user: ProofingUser, session_info: ForeignEidSessionInfo
) -> VerifyUserResult:

    existing_identity = proofing_user.identities.eidas
    locked_identity = proofing_user.locked_identity.eidas

    # check if the identity type already is verified
    if existing_identity is not None and existing_identity.is_verified:
        current_app.logger.info('User already has a verified EIDAS identity')
        current_app.logger.debug(f'EIDAS identity: {existing_identity}')
        return VerifyUserResult(user=proofing_user)

    loa = EIDASLoa(authn_context_class_to_loa(session_info=session_info))
    date_of_birth = session_info.attributes.date_of_birth
    new_identity = EIDASIdentity(
        created_by=current_app.conf.app_name,
        prid=session_info.attributes.prid,
        prid_persistence=session_info.attributes.prid_persistence,
        loa=loa,
        date_of_birth=datetime(year=date_of_birth.year, month=date_of_birth.month, day=date_of_birth.day),
        country_code=session_info.attributes.country_code,
        verified_by=current_app.conf.app_name,
        is_verified=True,
    )

    # check if the just verified identity matches the locked identity
    if locked_identity is not None:
        if locked_identity.prid != new_identity.prid and locked_identity.prid_persistence is PridPersistence.A:
            # identity is persistent and can not be replaced
            return VerifyUserResult(error_message=CommonMsg.locked_identity_not_matching)

        # replace the locked identity as the users identity has changed
        # TODO: Should we do anything else here? Is there a point to try to match things like date of birth or names?
        proofing_user.locked_identity.replace(element=new_identity)

    # the existing identity is not verified, just remove it
    if existing_identity is not None:
        proofing_user.identities.remove(key=ElementKey(IdentityType.EIDAS))

    # everything seems to check out, add the new identity to the user
    proofing_user.identities.add(element=new_identity)

    # update the users names from the verified identity
    proofing_user.given_name = session_info.attributes.given_name
    proofing_user.surname = session_info.attributes.surname
    proofing_user.display_name = f'{proofing_user.given_name} {proofing_user.surname}'

    # Create a proofing log
    proofing_log_entry = create_eidas_proofing_element(proofing_user=proofing_user, session_info=session_info)
    # Verify EIDAS identity for user
    if not current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.error('Failed to save EIDAS identity proofing log for user')
        return VerifyUserResult(error_message=CommonMsg.temp_problem)
    try:
        # Save user to private db
        current_app.private_userdb.save(proofing_user)
        # Ask am to sync user to central db
        current_app.logger.info(f'Request sync for user')
        result = current_app.am_relay.request_user_sync(proofing_user)
        current_app.logger.info(f'Sync result for user: {result}')
    except AmTaskFailed:
        current_app.logger.exception('Verifying EIDAS identity for user failed')
        return VerifyUserResult(error_message=CommonMsg.temp_problem)

    current_app.stats.count(name='eidas_verified')
    # load the user from central db before returning
    user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
    assert user is not None  # please mypy
    return VerifyUserResult(user=ProofingUser.from_user(user, current_app.private_userdb))


def verify_identity_from_external_mfa(
    proofing_user: ProofingUser, session_info: Union[NinSessionInfo, ForeignEidSessionInfo]
) -> VerifyUserResult:
    if isinstance(session_info, NinSessionInfo):
        return verify_nin_from_external_mfa(proofing_user=proofing_user, session_info=session_info)
    elif isinstance(session_info, ForeignEidSessionInfo):
        return verify_eidas_from_external_mfa(proofing_user=proofing_user, session_info=session_info)
    else:
        raise NotImplementedError(f'verify identity from {type(session_info)} not implemented')


def match_identity_for_mfa(
    user: User, session_info: Union[NinSessionInfo, ForeignEidSessionInfo]
) -> Optional[TranslatableMsg]:
    if isinstance(session_info, NinSessionInfo):
        identity_type = IdentityType.NIN
        asserted_unique_value = session_info.attributes.nin
    elif isinstance(session_info, ForeignEidSessionInfo):
        identity_type = IdentityType.EIDAS
        asserted_unique_value = session_info.attributes.prid
    else:
        raise NotImplementedError(f'MFA matching for {type(session_info)} not implemented')

    user_identity = user.identities.find(identity_type)
    user_locked_identity = user.locked_identity.find(identity_type)

    if user_identity and (user_identity.unique_value == asserted_unique_value and user_identity.is_verified):
        # asserted identity matched verified identity
        mfa_success = True
    elif user_locked_identity and user_locked_identity.unique_value == asserted_unique_value:
        # previously verified identity that the user just showed possession of
        mfa_success = True
        # and we can verify it again
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
        res = verify_identity_from_external_mfa(proofing_user=proofing_user, session_info=session_info)
        if res.error_message is not None:
            # If a message was returned, verifying the identity failed and we abort
            return res.error_message
    elif user_identity is None and user_locked_identity is None:
        # TODO: we _could_ allow the user to give consent to just adding this identity to the user here,
        #       with a request parameter passed from frontend to /mfa-authentication for example.
        mfa_success = False
    else:
        mfa_success = False

    # update session
    session.mfa_action.success = mfa_success
    if mfa_success is True:
        # add metadata if the authentication was a success
        session.mfa_action.issuer = session_info.issuer
        session.mfa_action.authn_instant = session_info.authn_instant.isoformat()
        session.mfa_action.authn_context = session_info.authn_context
        session.mfa_action.credential_used = _find_or_add_credential(
            user, session.mfa_action.framework, session.mfa_action.required_loa
        )
    return None


def _find_or_add_credential(
    user: User, framework: Optional[TrustFramework], required_loa: List[str]
) -> Optional[ElementKey]:
    if framework != TrustFramework.SWECONN:
        current_app.logger.info(f'Not recording credential used for unknown trust framework: {framework}')
        return None

    if not required_loa:
        # mainly keep mypy calm
        current_app.logger.debug(f'Not recording credential used without required_loa')
        return None

    for this in user.credentials.filter(SwedenConnectCredential):
        if this.level == required_loa:
            current_app.logger.debug(f'Found suitable credential on user: {this}')
            return this.key

    cred = SwedenConnectCredential(level=required_loa[0])
    cred.created_by = current_app.conf.app_name
    if required_loa == "loa3":
        # TODO: proof token as SWAMID_AL2_MFA_HI?
        pass

    # Reload the user from the central database, to not overwrite any earlier NIN proofings
    _user = current_app.central_userdb.get_user_by_eppn(user.eppn)
    if _user is None:
        # Please mypy
        raise RuntimeError(f'Could not reload user {user}')

    proofing_user = ProofingUser.from_user(_user, current_app.private_userdb)

    proofing_user.credentials.add(cred)

    current_app.logger.info(f'Adding new credential to proofing_user: {cred}')

    # Save proofing_user to private db
    current_app.private_userdb.save(proofing_user)

    # Ask am to sync proofing_user to central db
    current_app.logger.info(f'Request sync for proofing_user {proofing_user}')
    result = current_app.am_relay.request_user_sync(proofing_user)
    current_app.logger.info(f'Sync result for proofing_user {proofing_user}: {result}')

    return cred.key


def create_metadata(config):
    return entity_descriptor(config)


def staging_nin_remap(session_info: SessionInfo) -> SessionInfo:
    """
    Remap from known test nins to users correct nins.

    :param session_info: the SAML session info
    :return: SAML session info with new nin mapped
    """
    attributes = session_info['ava']
    asserted_test_nin = attributes['personalIdentityNumber'][0]
    user_nin = current_app.conf.staging_nin_map.get(asserted_test_nin, None)
    if user_nin:
        attributes['personalIdentityNumber'] = [user_nin]
    return session_info


def nin_verify_BACKDOOR(proofing_user: ProofingUser, asserted_nin: str) -> VerifyUserResult:
    """
    Mock using a Sweden Connect federation IdP assertion to verify a users identity
    when the request carries a magic cookie.

    :param proofing_user: Proofing user
    :param asserted_nin: nin to verify
    :return: redirect response
    """
    # Create a proofing log
    issuer = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'
    authn_context = 'http://id.elegnamnden.se/loa/1.0/loa3'

    user_address = FullPostalAddress(
        **{
            'Name': {'GivenNameMarking': '20', 'GivenName': 'Magic Cookie', 'Surname': 'Testsson'},
            'OfficialAddress': {'Address2': 'MAGIC COOKIE', 'PostalCode': '12345', 'City': 'LANDET'},
        }
    )

    proofing_log_entry = SwedenConnectProofing(
        eppn=proofing_user.eppn,
        created_by='eduid-eidas',
        nin=asserted_nin,
        issuer=issuer,
        authn_context_class=authn_context,
        user_postal_address=user_address,
        proofing_version='2018v1',
    )

    # Verify NIN for user
    try:
        nin_element = NinProofingElement(number=asserted_nin, created_by='eduid-eidas', is_verified=False)
        proofing_state = NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)
        if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry):
            current_app.logger.error(f'Failed verifying NIN for user {proofing_user}')
            return VerifyUserResult(error_message=CommonMsg.temp_problem)
    except AmTaskFailed:
        current_app.logger.exception('Verifying NIN for user failed')
        return VerifyUserResult(error_message=CommonMsg.temp_problem)
    current_app.stats.count(name='nin_verified')

    # load the user from central db before returning
    user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
    assert user is not None  # please mypy
    return VerifyUserResult(user=ProofingUser.from_user(user, current_app.private_userdb))


def token_verify_BACKDOOR(
    proofing_user: ProofingUser, asserted_nin: str, token_to_verify: Credential, redirect_url: str
) -> WerkzeugResponse:
    """
    Backdoor for verifying a token using the magic cookie. Used for integration tests.
    """
    # Create a proofing log
    issuer = 'MAGIC COOKIE'
    authn_context = 'MAGIC COOKIE'

    user_address = FullPostalAddress(
        **{
            'Name': {'GivenNameMarking': '20', 'GivenName': 'Magic Cookie', 'Surname': 'Testsson'},
            'OfficialAddress': {'Address2': 'MAGIC COOKIE', 'PostalCode': '12345', 'City': 'LANDET'},
        }
    )

    proofing_log_entry = MFATokenProofing(
        eppn=proofing_user.eppn,
        created_by='eduid-eidas',
        nin=asserted_nin,
        issuer=issuer,
        authn_context_class=authn_context,
        key_id=token_to_verify.key,
        user_postal_address=user_address,
        proofing_version='2018v1',
    )

    # Set token as verified
    token_to_verify.is_verified = True
    token_to_verify.proofing_method = current_app.conf.security_key_proofing_method
    token_to_verify.proofing_version = current_app.conf.security_key_proofing_version

    # Save proofing log entry and save user
    if current_app.proofing_log.save(proofing_log_entry):
        current_app.logger.info('Recorded MFA token verification in the proofing log')
        try:
            save_and_sync_user(proofing_user)
        except AmTaskFailed as e:
            current_app.logger.error('Verifying token for user failed')
            current_app.logger.error('{}'.format(e))
            return redirect_with_msg(redirect_url, CommonMsg.temp_problem)
        current_app.stats.count(name='fido_token_verified')

    return redirect_with_msg(redirect_url, EidasMsg.verify_success, error=False)


def check_credential_to_verify(user: User, credential_id: str, redirect_url: str) -> Optional[WerkzeugResponse]:
    # Check if requested key id is a mfa token and if the user used that to log in
    token_to_verify = user.credentials.find(credential_id)
    if not isinstance(token_to_verify, FidoCredential):
        current_app.logger.error(f'Credential {token_to_verify} is not a FidoCredential')
        return redirect_with_msg(redirect_url, EidasMsg.token_not_found)

    # Check if the credential was just now (within 60s) used to log in
    credential_already_used = credential_used_to_authenticate(token_to_verify, max_age=60)
    current_app.logger.debug(f'Credential {credential_id} recently used for login: {credential_already_used}')
    if not credential_already_used:
        # If token was not used for login, ask authn to authenticate the user again,
        # and then return to this endpoint with the same credential_id. Better luck next time I guess.
        current_app.logger.info(f'Started proofing of token {token_to_verify.key}, redirecting to authn')
        reauthn_url = urlappend(current_app.conf.token_service_url, 'reauthn')
        next_url = url_for('eidas.verify_token', credential_id=token_to_verify.key, _external=True)
        # Add idp arg to next_url if set
        idp = request.args.get('idp')
        if idp and idp not in current_app.saml2_config.metadata.identity_providers():
            if not current_app.conf.errors_url_template:
                abort(make_response('Requested IdP not found in metadata', 404))
            return goto_errors_response(
                errors_url=current_app.conf.errors_url_template,
                ctx=EduidErrorsContext.SAML_REQUEST_MISSING_IDP,
                rp=current_app.saml2_config.entityid,
            )

        if idp:
            next_url = f'{next_url}?idp={idp}'
        redirect_url = f'{reauthn_url}?next={next_url}'
        current_app.logger.debug(f'Redirecting user to {redirect_url}')
        return redirect(redirect_url)
    return None
