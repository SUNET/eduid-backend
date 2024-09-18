from dataclasses import dataclass

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.models.saml_models import BaseSessionInfo
from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.credentials import Credential
from eduid.userdb.credentials.external import BankIDCredential, ExternalCredential, TrustFramework
from eduid.userdb.element import ElementKey
from eduid.userdb.exceptions import LockedIdentityViolation
from eduid.userdb.identity import IdentityElement, IdentityType
from eduid.userdb.logs.element import BankIDProofing, MFATokenBankIDProofing, NinProofingLogElement
from eduid.userdb.proofing import NinProofingElement, ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.webapp.bankid.app import current_bankid_app as current_app
from eduid.webapp.bankid.helpers import BankIDMsg
from eduid.webapp.bankid.saml_session_info import BankIDSessionInfo
from eduid.webapp.common.api.helpers import verify_nin_for_user
from eduid.webapp.common.api.messages import CommonMsg
from eduid.webapp.common.proofing.base import (
    MatchResult,
    ProofingElementResult,
    ProofingFunctions,
    VerifyCredentialResult,
    VerifyUserResult,
)
from eduid.webapp.common.proofing.methods import ProofingMethod, ProofingMethodSAML
from eduid.webapp.common.session import session


@dataclass
class BankIDProofingFunctions(ProofingFunctions[BankIDSessionInfo]):
    def get_identity(self, user: User) -> IdentityElement | None:
        return user.identities.nin

    def verify_identity(self, user: User) -> VerifyUserResult:
        proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

        # Create a proofing log
        proofing_log_entry = self.identity_proofing_element(user=user)
        if proofing_log_entry.error:
            return VerifyUserResult(error=proofing_log_entry.error)
        assert isinstance(proofing_log_entry.data, NinProofingLogElement)  # please type checking

        # Verify NIN for user
        nin_element = NinProofingElement(
            number=self.session_info.attributes.nin, created_by=current_app.conf.app_name, is_verified=False
        )
        proofing_state = NinProofingState(id=None, modified_ts=None, eppn=proofing_user.eppn, nin=nin_element)
        try:
            if not verify_nin_for_user(proofing_user, proofing_state, proofing_log_entry.data):
                current_app.logger.error(f"Failed verifying NIN for user {proofing_user}")
                return VerifyUserResult(error=CommonMsg.temp_problem)
        except AmTaskFailed:
            current_app.logger.exception("Verifying NIN for user failed")
            return VerifyUserResult(error=CommonMsg.temp_problem)
        except LockedIdentityViolation:
            current_app.logger.exception("Verifying NIN for user failed")
            return VerifyUserResult(error=CommonMsg.locked_identity_not_matching)

        current_app.stats.count(name="nin_verified")
        # re-load the user from central db before returning
        _user = current_app.central_userdb.get_user_by_eppn(proofing_user.eppn)
        return VerifyUserResult(user=ProofingUser.from_user(_user, current_app.private_userdb))

    def identity_proofing_element(self, user: User) -> ProofingElementResult:
        if self.backdoor:
            proofing_version = "1999v1"
            # TODO: Used to use these values when backdoor was in use, but is that really wise?
            #       issuer = 'https://idp.example.com/simplesaml/saml2/idp/metadata.php'
            #       authn_context = 'http://id.elegnamnden.se/loa/1.0/loa3'
            #
        else:
            proofing_version = self.config.bankid_proofing_version

        _nin = self.session_info.attributes.nin

        data = BankIDProofing(
            created_by=current_app.conf.app_name,
            eppn=user.eppn,
            nin=_nin,
            given_name=self.session_info.attributes.given_name,
            surname=self.session_info.attributes.surname,
            proofing_version=proofing_version,
            transaction_id=self.session_info.attributes.transaction_id,
        )
        return ProofingElementResult(data=data)

    def credential_proofing_element(self, user: User, credential: Credential) -> ProofingElementResult:
        if self.backdoor:
            proofing_version = "1999v1"
        else:
            proofing_version = self.config.security_key_proofing_version

        # please type checking
        assert user.identities.nin

        data = MFATokenBankIDProofing(
            created_by=self.app_name,
            eppn=user.eppn,
            key_id=credential.key,
            nin=user.identities.nin.number,
            given_name=self.session_info.attributes.given_name,
            surname=self.session_info.attributes.surname,
            proofing_version=proofing_version,
            transaction_id=self.session_info.attributes.transaction_id,
        )
        return ProofingElementResult(data=data)

    def match_identity(self, user: User, proofing_method: ProofingMethod) -> MatchResult:
        identity_type = IdentityType.NIN
        asserted_unique_value = self.session_info.attributes.nin
        return self._match_identity_for_mfa(
            user=user,
            identity_type=identity_type,
            asserted_unique_value=asserted_unique_value,
            proofing_method=proofing_method,
        )

    def _match_identity_for_mfa(
        self, user: User, identity_type: IdentityType, asserted_unique_value: str, proofing_method: ProofingMethod
    ) -> MatchResult:
        user_identity = user.identities.find(identity_type)
        user_locked_identity = user.locked_identity.find(identity_type)

        if user_identity and (user_identity.unique_value == asserted_unique_value and user_identity.is_verified):
            # asserted identity matched verified identity
            mfa_success = True
            current_app.logger.debug(f"Current identity {user_identity} matched asserted identity")
        elif user_locked_identity and user_locked_identity.unique_value == asserted_unique_value:
            # previously verified identity that the user just showed possession of
            mfa_success = True
            current_app.logger.debug(f"Locked identity {user_locked_identity} matched asserted identity")
            # and we can verify it again
            proofing_user = ProofingUser.from_user(user, current_app.private_userdb)
            res = self.verify_identity(user=proofing_user)
            if res.error is not None:
                # If a message was returned, verifying the identity failed, and we abort
                return MatchResult(error=res.error)
        elif user_identity is None and user_locked_identity is None:
            # TODO: we _could_ allow the user to give consent to just adding this identity to the user here,
            #       with a request parameter passed from frontend to /mfa-authentication for example.
            mfa_success = False
            current_app.logger.debug("No identity or locked identity found for user")
        else:
            mfa_success = False
            current_app.logger.debug("No matching identity found for user")

        credential_used = None
        if mfa_success:
            assert isinstance(proofing_method, ProofingMethodSAML)  # please mypy
            credential_used = _find_or_add_credential(user, proofing_method.framework, proofing_method.required_loa)
            current_app.logger.debug(f"Found or added credential {credential_used}")

        # OLD way - remove as soon as possible
        # update session
        session.mfa_action.success = mfa_success
        if mfa_success is True:
            # add metadata if the authentication was a success
            session.mfa_action.issuer = self.session_info.issuer
            session.mfa_action.authn_instant = self.session_info.authn_instant.isoformat()
            session.mfa_action.authn_context = self.session_info.authn_context
            session.mfa_action.credential_used = credential_used

        if not mfa_success:
            current_app.logger.error("Asserted identity not matching user verified identity")
            current_identity = self.get_identity(user)
            current_unique_value = None
            if current_identity:
                current_unique_value = current_identity.unique_value
            current_app.logger.debug(f"Current identity: {current_identity}")
            current_app.logger.debug(
                f"Current identity unique value: {current_unique_value}. Asserted unique value: {asserted_unique_value}"
            )
            current_app.logger.debug(f"Asserted attributes: {self.session_info.attributes}")

        return MatchResult(matched=mfa_success, credential_used=credential_used)

    def mark_credential_as_verified(self, credential: Credential, loa: str | None) -> VerifyCredentialResult:
        if loa != "uncertified-loa3":
            return VerifyCredentialResult(error=BankIDMsg.authn_context_mismatch)

        credential.is_verified = True
        credential.proofing_method = self.config.security_key_proofing_method
        credential.proofing_version = self.config.security_key_proofing_version

        return VerifyCredentialResult(credential=credential)


def _find_or_add_credential(user: User, framework: TrustFramework | None, required_loa: list[str]) -> ElementKey | None:
    if not required_loa:
        # mainly keep mypy calm
        current_app.logger.debug("Not recording credential used without required_loa")
        return None

    cred: ExternalCredential
    this: ExternalCredential
    if framework == TrustFramework.BANKID:
        for this in user.credentials.filter(BankIDCredential):
            if this.level in required_loa:
                current_app.logger.debug(f"Found suitable credential on user: {this}")
                return this.key

        cred = BankIDCredential(level=required_loa[0])
        cred.created_by = current_app.conf.app_name
    else:
        current_app.logger.info(f"Not recording credential used for unknown trust framework: {framework}")
        return None

    # Reload the user from the central database, to not overwrite any earlier NIN proofings
    _user = current_app.central_userdb.get_user_by_eppn(user.eppn)

    proofing_user = ProofingUser.from_user(_user, current_app.private_userdb)

    proofing_user.credentials.add(cred)

    current_app.logger.info(f"Adding new credential to proofing_user: {cred}")

    # Save proofing_user to private db
    current_app.private_userdb.save(proofing_user)

    # Ask AM to sync proofing_user to central db
    current_app.logger.info(f"Request sync for proofing_user {proofing_user}")
    result = current_app.am_relay.request_user_sync(proofing_user)
    current_app.logger.info(f"Sync result for proofing_user {proofing_user}: {result}")

    return cred.key


def get_proofing_functions(
    session_info: BaseSessionInfo,
    app_name: str,
    config: ProofingConfigMixin,
    backdoor: bool,
) -> ProofingFunctions:
    if isinstance(session_info, BankIDSessionInfo):
        return BankIDProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    else:
        raise NotImplementedError(f"Proofing functions for {type(session_info)} not implemented")
