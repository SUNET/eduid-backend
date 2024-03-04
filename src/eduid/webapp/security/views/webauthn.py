import base64
from typing import Optional, Sequence, List, Set, Union
from uuid import UUID
from dataclasses import dataclass, field
from datetime import datetime

from fido2 import cbor
from fido2.server import Fido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorAttachment,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)
from fido_mds.models.fido_mds import AuthenticatorStatus
from fido_mds.models.webauthn import AttestationFormat
from fido_mds.exceptions import AttestationVerificationError, MetadataValidationError
from flask import Blueprint, jsonify

from eduid.common.rpc.exceptions import AmTaskFailed
from eduid.userdb import User
from eduid.userdb.credentials import Webauthn
from eduid.userdb.credentials.fido import U2F, FidoCredential
from eduid.userdb.security import SecurityUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import WebauthnRegistration
from eduid.webapp.security.app import current_security_app as current_app
from eduid.webapp.security.helpers import SecurityMsg, compile_credential_list
from eduid.webapp.security.schemas import (
    RemoveWebauthnTokenRequestSchema,
    SecurityResponseSchema,
    WebauthnRegisterBeginSchema,
    WebauthnRegisterRequestSchema,
)
from eduid.webapp.security.webauthn_proofing import (
    OtherAuthenticatorStatus,
    get_authenticator_information,
    is_authenticator_mfa_approved,
    save_webauthn_proofing_log,
)


def get_webauthn_server(
    rp_id: str, rp_name: str, attestation: Optional[AttestationConveyancePreference] = None
) -> Fido2Server:
    rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    return Fido2Server(rp, attestation=attestation)


def make_credentials(creds: Sequence[FidoCredential]) -> list[AttestedCredentialData]:
    credentials = []
    for cred in creds:
        if isinstance(cred, Webauthn):
            cred_data = base64.urlsafe_b64decode(cred.credential_data.encode("ascii"))
            credential_data, rest = AttestedCredentialData.unpack_from(cred_data)
            if rest:
                continue
        elif isinstance(cred, U2F):
            # cred is of type U2F (legacy registration)
            credential_data = AttestedCredentialData.from_ctap1(
                cred.keyhandle.encode("ascii"), cred.public_key.encode("ascii")
            )
        else:
            raise ValueError(f"Unknown credential {repr(cred)}")
        credentials.append(credential_data)
    return credentials


webauthn_views = Blueprint("webauthn", __name__, url_prefix="/webauthn", template_folder="templates")


@webauthn_views.route("/register/begin", methods=["POST"])
@UnmarshalWith(WebauthnRegisterBeginSchema)
@MarshalWith(FluxStandardAction)
@require_user
def registration_begin(user: User, authenticator: str) -> FluxData:
    try:
        _auth_enum = AuthenticatorAttachment(authenticator)
    except ValueError:
        return error_response(message=SecurityMsg.invalid_authenticator)
    user_webauthn_tokens = user.credentials.filter(FidoCredential)
    if len(user_webauthn_tokens) >= current_app.conf.webauthn_max_allowed_tokens:
        current_app.logger.error(
            f"User tried to register more than {current_app.conf.webauthn_max_allowed_tokens} tokens."
        )
        return error_response(message=SecurityMsg.max_webauthn)

    creds = make_credentials(user_webauthn_tokens)
    server = get_webauthn_server(
        rp_id=current_app.conf.fido2_rp_id,
        rp_name=current_app.conf.fido2_rp_name,
        attestation=current_app.conf.webauthn_attestation,
    )
    if user.given_name is None or user.surname is None or user.display_name is None:
        return error_response(message=SecurityMsg.no_pdata)
    user_entity = PublicKeyCredentialUserEntity(
        id=bytes(user.eppn, "utf-8"), name=f"{user.given_name} {user.surname}", display_name=user.display_name
    )
    registration_data, state = server.register_begin(
        user=user_entity,
        credentials=creds,
        user_verification=UserVerificationRequirement.DISCOURAGED,
        authenticator_attachment=_auth_enum,
    )
    session.security.webauthn_registration = WebauthnRegistration(webauthn_state=state, authenticator=_auth_enum)

    current_app.logger.info(f"User {user} has started registration of a webauthn token")
    current_app.logger.debug(f"Webauthn Registration data: {registration_data}.")

    if not check_magic_cookie(current_app.conf):  # no stats for automatic tests
        current_app.stats.count(name="webauthn_register_begin")

    encoded_data = base64.urlsafe_b64encode(cbor.encode(registration_data)).decode("ascii")
    encoded_data = encoded_data.rstrip("=")
    return success_response({"csrf_token": session.new_csrf_token(), "registration_data": encoded_data})


def urlsafe_b64decode(data: str) -> bytes:
    data += "=" * (len(data) % 4)
    return base64.urlsafe_b64decode(data)


@webauthn_views.route("/register/complete", methods=["POST"])
@UnmarshalWith(WebauthnRegisterRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def registration_complete(
    user: User, credential_id: str, attestation_object: str, client_data: str, description: str
) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    server = get_webauthn_server(rp_id=current_app.conf.fido2_rp_id, rp_name=current_app.conf.fido2_rp_name)
    att_obj = AttestationObject(urlsafe_b64decode(attestation_object))
    cdata_obj = CollectedClientData(urlsafe_b64decode(client_data))
    if not session.security.webauthn_registration:
        current_app.logger.info("Found no webauthn registration state in the session")
        return error_response(message=SecurityMsg.missing_registration_state)

    # verify attestation and gather authenticator information from metadata
    try:
        authenticator_info = get_authenticator_information(attestation=attestation_object, client_data=client_data)
    except (AttestationVerificationError, NotImplementedError, ValueError):
        current_app.logger.exception(f"attestation verification failed")
        current_app.logger.info(f"attestation_object: {attestation_object}")
        current_app.logger.info(f"client_data: {client_data}")
        return error_response(message=SecurityMsg.webauthn_attestation_fail)
    except MetadataValidationError:
        current_app.logger.exception(f"metadata validation failed")
        current_app.logger.info(f"attestation_object: {attestation_object}")
        current_app.logger.info(f"client_data: {client_data}")
        return error_response(message=SecurityMsg.webauthn_metadata_fail)

    # Move registration state from session to local variable to let users restart if something fails
    reg_state = session.security.webauthn_registration
    session.security.webauthn_registration = None

    auth_data: AuthenticatorData = server.register_complete(reg_state.webauthn_state, cdata_obj, att_obj)
    if auth_data.credential_data is None:
        raise RuntimeError("Authenticator data does not contain credential data")
    credential_data = base64.urlsafe_b64encode(auth_data.credential_data).decode("ascii")
    current_app.logger.debug(f"Processed Webauthn credential data: {credential_data}")
    mfa_approved = is_authenticator_mfa_approved(authenticator_info=authenticator_info)
    current_app.logger.info(f"authenticator mfa approved: {mfa_approved}")

    credential = Webauthn(
        keyhandle=credential_id,
        authenticator_id=authenticator_info.authenticator_id,
        credential_data=credential_data,
        app_id=current_app.conf.fido2_rp_id,
        description=description,
        created_by="security",
        authenticator=reg_state.authenticator,
        mfa_approved=mfa_approved,
        webauthn_proofing_version=current_app.conf.webauthn_proofing_version,
        attestation_format=authenticator_info.attestation_format,
    )
    security_user.credentials.add(credential)

    if mfa_approved and not save_webauthn_proofing_log(user.eppn, authenticator_info):
        current_app.logger.info("Could not save webauthn proofing log")
        current_app.logger.debug(f"credential: {credential}")
        current_app.logger.debug(f"authenticator_info: {authenticator_info}")
        return error_response(message=CommonMsg.temp_problem)

    try:
        save_and_sync_user(security_user)
    except AmTaskFailed:
        current_app.logger.exception("User sync failed")
        return error_response(message=CommonMsg.temp_problem)

    # no stats for automatic tests
    if authenticator_info.status is not OtherAuthenticatorStatus.MAGIC_COOKIE:
        current_app.stats.count(name=f"webauthn_attestation_format_{authenticator_info.attestation_format.value}")
        current_app.stats.count(name="webauthn_register_complete")
        if mfa_approved:
            current_app.stats.count(name="webauthn_mfa_approved")
        else:
            current_app.stats.count(name="webauthn_not_mfa_approved")

    current_app.logger.info("User has completed registration of a webauthn token")
    credentials = compile_credential_list(security_user)
    return success_response(payload=dict(credentials=credentials), message=SecurityMsg.webauthn_success)


@webauthn_views.route("/remove", methods=["POST"])
@UnmarshalWith(RemoveWebauthnTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def remove(user: User, credential_key: str) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    tokens = security_user.credentials.filter(FidoCredential)
    if len(tokens) <= 1:
        current_app.logger.info(f"User {security_user} has tried to remove the last security token")
        return error_response(message=SecurityMsg.no_last)

    token_to_remove = security_user.credentials.find(credential_key)
    if token_to_remove:
        security_user.credentials.remove(token_to_remove.key)
        save_and_sync_user(security_user)
        current_app.stats.count(name="webauthn_token_remove")
        current_app.logger.info(f"User {security_user} has removed a security token: {credential_key}")
        message = SecurityMsg.rm_webauthn
    else:
        current_app.logger.info(f"User {security_user} has tried to remove a missing security token: {credential_key}")
        return error_response(message=SecurityMsg.no_webauthn)

    credentials = compile_credential_list(security_user)
    return success_response(message=message, payload={"credentials": credentials})


########################
# FROM HERE TEST
########################

@dataclass
class AuthenticatorInformation:
    authenticator_id: Union[UUID, str]
    attestation_formats: List[AttestationFormat]
    status: Optional[AuthenticatorStatus] = field(default=None)
    last_status_change: Optional[datetime] = field(default=None)
    icon: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    key_protection: list[str] = field(default_factory=list)
    user_verification_methods: list[str] = field(default_factory=list)

WEBAUTHN_ALLOWED_USER_VERIFICATION_METHODS: list[str] = [
    "faceprint_internal",
    "passcode_external",
    "passcode_internal",
    "handprint_internal",
    "pattern_internal",
    "voiceprint_internal",
    "fingerprint_internal",
    "eyeprint_internal",
]
WEBAUTHN_ALLOWED_KEY_PROTECTION: list[str] = ["remote_handle", "hardware", "secure_element", "tee"]

WEBAUTHN_ALLOWED_STATUS: list[AuthenticatorStatus] = [
    AuthenticatorStatus.FIDO_CERTIFIED,
    AuthenticatorStatus.FIDO_CERTIFIED_L1,
    AuthenticatorStatus.FIDO_CERTIFIED_L2,
    AuthenticatorStatus.FIDO_CERTIFIED_L3,
    AuthenticatorStatus.FIDO_CERTIFIED_L1plus,
    AuthenticatorStatus.FIDO_CERTIFIED_L2plus,
    AuthenticatorStatus.FIDO_CERTIFIED_L3plus,
]

def is_authenticator_mfa_approved_from_script(authenticator_info: AuthenticatorInformation) -> bool:
    """
    This is our current policy for determine if a FIDO2 authenticator can do multi-factor authentications.
    """
    #print(f"Checking mfa approved for {authenticator_info.description}")
    # If there is no attestation we can not trust the authenticator info
    if not authenticator_info.attestation_formats:
        return False

    # check status in metadata and disallow uncertified and incident statuses
    if authenticator_info.status not in WEBAUTHN_ALLOWED_STATUS:
        #print(f"status {authenticator_info.status} is not mfa capable")
        return False

    # true if the authenticator supports any of the user verification methods we allow
    is_accepted_user_verification = any(
        [
            method
            for method in authenticator_info.user_verification_methods
            if method in WEBAUTHN_ALLOWED_USER_VERIFICATION_METHODS
        ]
    )
    # a typical token has key protection ["hardware"] or ["hardware", "tee"] but some also support software, so
    # we have to check that all key protections supported is in our allow list
    is_accepted_key_protection = all(
        [
            protection
            for protection in authenticator_info.key_protection
            if protection in WEBAUTHN_ALLOWED_KEY_PROTECTION
        ]
    )
    #print(f"is_accepted_user_verification: {is_accepted_user_verification}")
    # if not is_accepted_user_verification:
    #     print(f"user verification methods: {authenticator_info.user_verification_methods}")
    # print(f"is_accepted_key_protection: {is_accepted_key_protection}")
    # if not is_accepted_key_protection:
    #     print(f"key protections: {authenticator_info.key_protection}")
    if is_accepted_user_verification and is_accepted_key_protection:
        return True
    return False


@webauthn_views.route("/test", methods=["GET"])
def test() -> FluxData:
    current_app.logger.info("DEBUG DEBUG DEBUG")
    # 1 - Gather the fido_list - from self.fido_mds - built in Security app? 
    # 2 - for each key in the fido_list
    # 2a - if is_authenticator_mfa_approved() == true, add to approved_list
    # 3 - return approved_list 

    # the list of keys in the fido_list, as AuthenticatorInformation format
    parsed_entries: List[AuthenticatorInformation] = []

    # Are those variable needed? seems more for statistics
    available_status: Set[str] = set()
    available_user_verification_methods: Set[str] = set()
    available_key_protections: Set[str] = set()

    #print(current_app.fido_mds.metadata.entries)

    for metadata_entry in current_app.fido_mds.metadata.entries:
        # debug, what is the whole list of fido keys?
        # print(metadata_entry)

        last_status_change = metadata_entry.time_of_last_status_change
        user_verification_methods = [
            detail.user_verification_method for detail in metadata_entry.metadata_statement.get_user_verification_details()
        ]
        available_status.add(metadata_entry.status_reports[0].status)
        available_user_verification_methods.update(user_verification_methods)
        available_key_protections.update(metadata_entry.metadata_statement.key_protection)

        authenticator_info = AuthenticatorInformation(
            attestation_formats=metadata_entry.metadata_statement.attestation_types,
            authenticator_id=metadata_entry.aaguid or metadata_entry.aaid,
            status=metadata_entry.status_reports[0].status,  # latest status reports status
            last_status_change=last_status_change,
            user_verification_methods=user_verification_methods,
            key_protection=metadata_entry.metadata_statement.key_protection,
            description=metadata_entry.metadata_statement.description,
            # icon=metadata_entry.metadata_statement.icon,
        )
        parsed_entries.append(authenticator_info)

    approved_list: List[AuthenticatorInformation] = []
    approved_names_list: List[str] = []
    for entry in parsed_entries:
        if is_authenticator_mfa_approved_from_script(entry):
            approved_list.append(entry)
            approved_names_list.append(entry.description)
    
    current_app.logger.info(f"{approved_list}")
    current_app.logger.info(f"{len(approved_list)} authenticators approved")

    # Serialize the approved_list to JSON

    return jsonify(approved_names_list)
