from abc import ABC
from dataclasses import dataclass
from datetime import datetime
from typing import Generic, List, Optional, TypeVar, Union

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.rpc.exceptions import AmTaskFailed, MsgTaskFailed, NoNavetData
from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.userdb import EIDASIdentity, User
from eduid.userdb.credentials import Credential
from eduid.userdb.credentials.external import SwedenConnectCredential, TrustFramework
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import EIDASLoa, IdentityElement, IdentityType, PridPersistence
from eduid.userdb.logs.element import (
    MFATokenEIDASProofing,
    MFATokenProofing,
    SwedenConnectEIDASProofing,
    SwedenConnectProofing,
)
from eduid.userdb.proofing import NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.webapp.common.api.helpers import (
    ProofingNavetData,
    get_proofing_log_navet_data,
    set_user_names_from_foreign_eid,
    verify_nin_for_user,
)
from eduid.webapp.common.api.messages import CommonMsg, TranslatableMsg
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.proofing.methods import ProofingMethod
from eduid.webapp.common.session import session
from eduid.webapp.eidas.app import current_eidas_app as current_app
from eduid.webapp.eidas.helpers import (
    authn_context_class_to_loa,
)
from eduid.webapp.eidas.saml_session_info import ForeignEidSessionInfo, NinSessionInfo

SessionInfoVar = TypeVar('SessionInfoVar')


@dataclass
class MatchResult:
    error: Optional[TranslatableMsg] = None
    matched: bool = False
    credential_used: Optional[ElementKey] = None


@dataclass
class VerifyUserResult:
    user: Optional[User] = None
    error_message: Optional[TranslatableMsg] = None


@dataclass()
class ProofingFunctions(ABC, Generic[SessionInfoVar]):

    session_info: SessionInfoVar
    app_name: str
    config: ProofingConfigMixin
    backdoor: bool

    def get_identity(self, user: User) -> Optional[IdentityElement]:
        raise NotImplementedError('Subclass must implement get_identity')

    def verify_identity(self, user: User) -> VerifyUserResult:
        raise NotImplementedError("Subclass must implement verify_identity")

    def verify_credential(self, user: User, credential: Credential) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        # Create a proofing log
        try:
            proofing_log_entry = self.credential_proofing_element(user=user, credential=credential)
        except NoNavetData:
            current_app.logger.exception('No data returned from Navet')
            return VerifyUserResult(error_message=CommonMsg.no_navet_data)
        except MsgTaskFailed:
            current_app.logger.exception('Navet lookup failed')
            current_app.stats.count('navet_error')
            return VerifyUserResult(error_message=CommonMsg.navet_error)

        # Set token as verified
        credential.is_verified = True
        credential.proofing_method = self.config.security_key_proofing_method
        credential.proofing_version = self.config.security_key_proofing_version

        # Save proofing log entry and save user
        if current_app.proofing_log.save(proofing_log_entry):
            current_app.logger.info('Recorded MFA token verification in the proofing log')
            try:
                save_and_sync_user(proofing_user)
            except AmTaskFailed:
                current_app.logger.exception('Verifying token for user failed')
                return VerifyUserResult(error_message=CommonMsg.temp_problem)
            current_app.stats.count(name='fido_token_verified')

        # re-load the user from central db before returning
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        assert _user is not None  # please mypy
        return VerifyUserResult(user=_user)

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        raise NotImplementedError("Subclass must implement match_identity")

    def _match_identity_for_mfa(
        self, user: User, identity_type: IdentityType, asserted_unique_value: str, proofing_method: ProofingMethod
    ) -> MatchResult:
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
            res = self.verify_identity(user=proofing_user)
            if res.error_message is not None:
                # If a message was returned, verifying the identity failed, and we abort
                return MatchResult(error=res.error_message)
        elif user_identity is None and user_locked_identity is None:
            # TODO: we _could_ allow the user to give consent to just adding this identity to the user here,
            #       with a request parameter passed from frontend to /mfa-authentication for example.
            mfa_success = False
        else:
            mfa_success = False

        credential_used = None
        if mfa_success:
            credential_used = _find_or_add_credential(user, proofing_method.framework, proofing_method.required_loa)

        # OLD way - remove as soon as possible
        # update session
        session.mfa_action.success = mfa_success
        if mfa_success is True:
            # add metadata if the authentication was a success
            session.mfa_action.issuer = self.session_info.issuer  # type: ignore
            session.mfa_action.authn_instant = self.session_info.authn_instant.isoformat()  # type: ignore
            session.mfa_action.authn_context = self.session_info.authn_context  # type: ignore
            session.mfa_action.credential_used = credential_used

        if not mfa_success:
            current_app.logger.error('Asserted identity not matching user verified identity')
            current_app.logger.debug(f'Current identity: {self.get_identity(user)}')
            current_app.logger.debug(f'Asserted attributes: {self.session_info.attributes}')  # type: ignore

        return MatchResult(matched=mfa_success, credential_used=credential_used)

    def credential_proofing_element(self, user: User, credential: Credential):
        raise NotImplementedError("Subclass must implement credential_proofing_element")


@dataclass()
class FrejaProofingFunctions(ProofingFunctions[NinSessionInfo]):
    def get_identity(self, user: User) -> Optional[IdentityElement]:
        return user.identities.nin

    def verify_identity(self, user: User) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        # Create a proofing log
        try:
            proofing_log_entry = self.identity_proofing_element(user=user)
        except NoNavetData:
            current_app.logger.exception('No data returned from Navet')
            return VerifyUserResult(error_message=CommonMsg.no_navet_data)
        except MsgTaskFailed:
            current_app.logger.exception('Navet lookup failed')
            current_app.stats.count('navet_error')
            return VerifyUserResult(error_message=CommonMsg.navet_error)

        # Verify NIN for user
        try:
            nin_element = NinProofingElement(
                number=self.session_info.attributes.nin, created_by=current_app.conf.app_name, is_verified=False
            )
            proofing_state = NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)
            if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry):
                current_app.logger.error(f'Failed verifying NIN for user {proofing_user}')
                return VerifyUserResult(error_message=CommonMsg.temp_problem)
        except AmTaskFailed:
            current_app.logger.exception('Verifying NIN for user failed')
            return VerifyUserResult(error_message=CommonMsg.temp_problem)

        current_app.stats.count(name='nin_verified')
        # re-load the user from central db before returning
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        assert _user is not None  # please mypy
        return VerifyUserResult(user=ProofingUser.from_user(_user, current_app.private_userdb))

    def identity_proofing_element(self, user: User):
        issuer: Optional[str]
        authn_context: Optional[str]

        if self.backdoor:
            proofing_version = '1999v1'
            # TODO: Used to use these values when backdoor was in use, but is that really wise?
            #       issuer = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'
            #       authn_context = 'http://id.elegnamnden.se/loa/1.0/loa3'
            #
            issuer = 'MAGIC COOKIE'
            authn_context = 'MAGIC COOKIE'
        else:
            proofing_version = self.config.security_key_proofing_version
            issuer = self.session_info.issuer
            authn_context = self.session_info.authn_context

        _nin = self.session_info.attributes.nin
        navet_proofing_data = self._get_navet_data(nin=_nin)

        return SwedenConnectProofing(
            authn_context_class=authn_context,
            created_by=current_app.conf.app_name,
            deregistration_information=navet_proofing_data.deregistration_information,
            eppn=user.eppn,
            issuer=issuer,
            nin=_nin,
            proofing_version=proofing_version,
            user_postal_address=navet_proofing_data.user_postal_address,
        )

    def credential_proofing_element(self, user: User, credential: Credential):
        issuer: Optional[str]
        authn_context: Optional[str]

        if self.backdoor:
            proofing_version = '1999v1'
            issuer = 'MAGIC COOKIE'
            authn_context = 'MAGIC COOKIE'
        else:
            proofing_version = self.config.security_key_proofing_version
            issuer = self.session_info.issuer
            authn_context = self.session_info.authn_context

        # please type checking
        assert user.identities.nin

        navet_proofing_data = self._get_navet_data(nin=user.identities.nin.number)

        return MFATokenProofing(
            authn_context_class=authn_context,
            created_by=self.app_name,
            deregistration_information=navet_proofing_data.deregistration_information,
            eppn=user.eppn,
            issuer=issuer,
            key_id=credential.key,
            nin=user.identities.nin.number,
            proofing_version=proofing_version,
            user_postal_address=navet_proofing_data.user_postal_address,
        )

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        identity_type = IdentityType.NIN
        asserted_unique_value = self.session_info.attributes.nin
        return self._match_identity_for_mfa(
            user=user,
            identity_type=identity_type,
            asserted_unique_value=asserted_unique_value,
            proofing_method=proofing_method,
        )

    def _get_navet_data(self, nin: str) -> ProofingNavetData:
        """
        Fetch data such as official registered address from Navet (Skatteverket).
        """
        if self.backdoor:
            # verify with bogus data and without Navet interaction for integration test
            user_postal_address = FullPostalAddress(
                **{
                    'Name': {'GivenNameMarking': '20', 'GivenName': 'Magic Cookie', 'Surname': 'Testsson'},
                    'OfficialAddress': {'Address2': 'MAGIC COOKIE', 'PostalCode': '12345', 'City': 'LANDET'},
                }
            )
            navet_proofing_data = ProofingNavetData(
                user_postal_address=user_postal_address,
                deregistration_information=None,
            )
        else:
            navet_proofing_data = get_proofing_log_navet_data(nin=nin)

        return navet_proofing_data


@dataclass()
class EidasProofingFunctions(ProofingFunctions[ForeignEidSessionInfo]):
    def get_identity(self, user: User) -> Optional[IdentityElement]:
        return user.identities.eidas

    def verify_identity(self, user: User) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        existing_identity = user.identities.eidas
        locked_identity = user.locked_identity.eidas

        loa = EIDASLoa(authn_context_class_to_loa(session_info=self.session_info))
        date_of_birth = self.session_info.attributes.date_of_birth
        new_identity = EIDASIdentity(
            created_by=current_app.conf.app_name,
            prid=self.session_info.attributes.prid,
            prid_persistence=self.session_info.attributes.prid_persistence,
            loa=loa,
            date_of_birth=datetime(year=date_of_birth.year, month=date_of_birth.month, day=date_of_birth.day),
            country_code=self.session_info.attributes.country_code,
            verified_by=current_app.conf.app_name,
            is_verified=True,
        )

        # check if the just verified identity matches the locked identity
        if locked_identity is not None and locked_identity.prid != new_identity.prid:
            if not self._can_replace_identity(proofing_user=proofing_user):
                # asserted identity did not match the locked identity
                return VerifyUserResult(error_message=CommonMsg.locked_identity_not_matching)
            # replace the locked identity as the users asserted prid has changed,
            # and we are sure enough that it is the same person
            proofing_user.locked_identity.replace(element=new_identity)

        # the existing identity is not verified, just remove it
        if existing_identity is not None:
            proofing_user.identities.remove(key=ElementKey(IdentityType.EIDAS))

        # everything seems to check out, add the new identity to the user
        proofing_user.identities.add(element=new_identity)

        # Create a proofing log
        proofing_log_entry = self.identity_proofing_element(user=proofing_user)

        # update the users names from the verified identity
        proofing_user = set_user_names_from_foreign_eid(proofing_user, proofing_log_entry)

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
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        assert _user is not None  # please mypy
        return VerifyUserResult(user=_user)

    def identity_proofing_element(self, user: User):
        return SwedenConnectEIDASProofing(
            authn_context_class=self.session_info.authn_context,
            country_code=self.session_info.attributes.country_code,
            created_by=current_app.conf.app_name,
            date_of_birth=self.session_info.attributes.date_of_birth.strftime('%Y-%m-%d'),
            eidas_person_identifier=self.session_info.attributes.eidas_person_identifier,
            eppn=user.eppn,
            given_name=self.session_info.attributes.given_name,
            issuer=self.session_info.issuer,
            prid=self.session_info.attributes.prid,
            prid_persistence=self.session_info.attributes.prid_persistence,
            proofing_version=current_app.conf.foreign_eid_proofing_version,
            surname=self.session_info.attributes.surname,
            transaction_identifier=self.session_info.attributes.transaction_identifier,
        )

    def credential_proofing_element(self, user: User, credential: Credential):
        return MFATokenEIDASProofing(
            authn_context_class=self.session_info.authn_context,
            country_code=self.session_info.attributes.country_code,
            created_by=current_app.conf.app_name,
            date_of_birth=self.session_info.attributes.date_of_birth.strftime('%Y-%m-%d'),
            eidas_person_identifier=self.session_info.attributes.eidas_person_identifier,
            eppn=user.eppn,
            given_name=self.session_info.attributes.given_name,
            issuer=self.session_info.issuer,
            key_id=credential.key,  # DIFF
            prid=self.session_info.attributes.prid,
            prid_persistence=self.session_info.attributes.prid_persistence,
            proofing_version=current_app.conf.security_key_foreign_eid_proofing_version,  # DIFF
            surname=self.session_info.attributes.surname,
            transaction_identifier=self.session_info.attributes.transaction_identifier,
        )

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        identity_type = IdentityType.EIDAS
        asserted_unique_value = self.session_info.attributes.prid
        return self._match_identity_for_mfa(
            user=user,
            identity_type=identity_type,
            asserted_unique_value=asserted_unique_value,
            proofing_method=proofing_method,
        )

    def _can_replace_identity(self, proofing_user: ProofingUser) -> bool:
        locked_identity = proofing_user.locked_identity.eidas
        if locked_identity is None:
            return True
        if locked_identity.prid_persistence is PridPersistence.A:
            # identity is persistent and can not be replaced
            return False
        # the locked identity for this account has prid persistence B or C these change over time.
        # try to verify that it is the same person with a new eid
        date_of_birth_matches = locked_identity.date_of_birth.date() == self.session_info.attributes.date_of_birth
        given_name_matches = proofing_user.given_name == self.session_info.attributes.given_name
        surname_matches = proofing_user.surname == self.session_info.attributes.surname
        if date_of_birth_matches and given_name_matches and surname_matches:
            return True
        return False


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

    # Ask AM to sync proofing_user to central db
    current_app.logger.info(f'Request sync for proofing_user {proofing_user}')
    result = current_app.am_relay.request_user_sync(proofing_user)
    current_app.logger.info(f'Sync result for proofing_user {proofing_user}: {result}')

    return cred.key


def get_proofing_functions(
    session_info: Union[NinSessionInfo, ForeignEidSessionInfo],
    app_name: str,
    config: ProofingConfigMixin,
    backdoor: bool,
) -> ProofingFunctions:
    if isinstance(session_info, NinSessionInfo):
        return FrejaProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    elif isinstance(session_info, ForeignEidSessionInfo):
        return EidasProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    else:
        raise NotImplementedError(f'MFA matching for {type(session_info)} not implemented')
