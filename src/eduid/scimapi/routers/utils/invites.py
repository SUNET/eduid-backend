from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime, timedelta
from os import environ
from typing import Any

from fastapi import Request, Response
from pymongo.errors import DuplicateKeyError

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.models.scim_base import Email, Meta, Name, PhoneNumber, SCIMResourceType, SCIMSchema, SearchRequest
from eduid.common.models.scim_invite import InviteCreateRequest, InviteResponse, NutidInviteExtensionV1
from eduid.common.models.scim_user import NutidUserExtensionV1, Profile
from eduid.common.utils import get_short_hash, make_etag
from eduid.queue.db import QueueItem, SenderInfo
from eduid.queue.db.message import EduidInviteEmail
from eduid.scimapi.exceptions import BadRequest
from eduid.scimapi.search import SearchFilter
from eduid.scimapi.utils import get_unique_hash
from eduid.userdb.scimapi.invitedb import ScimApiInvite
from eduid.userdb.signup import Invite as SignupInvite
from eduid.userdb.signup import InviteMailAddress, InvitePhoneNumber, InviteType, SCIMReference

__author__ = "lundberg"


def create_signup_invite(
    req: ContextRequest, create_request: InviteCreateRequest, db_invite: ScimApiInvite
) -> SignupInvite:
    invite_reference = SCIMReference(data_owner=req.context.data_owner, scim_id=db_invite.scim_id)

    if create_request.nutid_invite_v1.send_email is False:
        # Generate a shorter code if the code will reach the invitee on paper or other analog media
        invite_code = get_short_hash()
    else:
        invite_code = get_unique_hash()

    mails_addresses = [
        InviteMailAddress(email=email.value, primary=email.primary) for email in create_request.nutid_invite_v1.emails
    ]
    phone_numbers = [
        InvitePhoneNumber(number=number.value, primary=number.primary)
        for number in create_request.nutid_invite_v1.phone_numbers
    ]

    # please mypy (schema validation makes sure they are not None)
    assert create_request.nutid_invite_v1.inviter_name is not None
    assert create_request.nutid_invite_v1.send_email is not None

    signup_invite = SignupInvite(
        invite_code=invite_code,
        invite_type=InviteType.SCIM,
        invite_reference=invite_reference,
        given_name=create_request.nutid_invite_v1.name.given_name,
        surname=create_request.nutid_invite_v1.name.family_name,
        nin=create_request.nutid_invite_v1.national_identity_number,
        inviter_name=create_request.nutid_invite_v1.inviter_name,
        send_email=create_request.nutid_invite_v1.send_email,
        mail_addresses=mails_addresses,
        phone_numbers=phone_numbers,
        finish_url=create_request.nutid_invite_v1.finish_url,
        expires_at=datetime.utcnow() + timedelta(seconds=req.app.context.config.invite_expire),
    )
    return signup_invite


def db_invite_to_response(req: Request, resp: Response, db_invite: ScimApiInvite, signup_invite: SignupInvite):
    location = req.app.context.url_for("Invites", db_invite.scim_id)
    meta = Meta(
        location=location,
        last_modified=db_invite.last_modified,
        resource_type=SCIMResourceType.INVITE,
        created=db_invite.created,
        version=db_invite.version,
    )

    schemas = [SCIMSchema.NUTID_INVITE_CORE_V1, SCIMSchema.NUTID_INVITE_V1, SCIMSchema.NUTID_USER_V1]
    _profiles = {k: Profile(attributes=v.attributes, data=v.data) for k, v in db_invite.profiles.items()}

    # Only add invite url in parsed_response if no email should be sent to the invitee
    invite_url = None
    if signup_invite.send_email is False:
        invite_url = f"{req.app.context.config.invite_url}/{signup_invite.invite_code}"

    invite_extension = NutidInviteExtensionV1(
        completed=db_invite.completed,
        name=Name(**asdict(db_invite.name)),
        emails=[Email(**asdict(email)) for email in db_invite.emails],
        phone_numbers=[PhoneNumber(**asdict(number)) for number in db_invite.phone_numbers],
        national_identity_number=db_invite.nin,
        preferred_language=db_invite.preferred_language,
        groups=db_invite.groups,
        send_email=signup_invite.send_email,
        finish_url=signup_invite.finish_url,
        expires_at=signup_invite.expires_at,
        inviter_name=signup_invite.inviter_name,
        invite_url=invite_url,
    )

    scim_invite = InviteResponse(
        id=db_invite.scim_id,
        external_id=db_invite.external_id,
        meta=meta,
        schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
        nutid_invite_v1=invite_extension,
        nutid_user_v1=NutidUserExtensionV1(profiles=_profiles),
    )

    resp.headers["Location"] = location
    resp.headers["ETag"] = make_etag(db_invite.version)
    req.app.context.logger.debug(f"Extra debug: Response:\n{scim_invite.model_dump_json(exclude_none=True, indent=2)}")
    return scim_invite


def create_signup_ref(req: ContextRequest, db_invite: ScimApiInvite):
    return SCIMReference(data_owner=req.context.data_owner, scim_id=db_invite.scim_id)


def send_invite_mail(req: ContextRequest, signup_invite: SignupInvite):
    try:
        email = [email.email for email in signup_invite.mail_addresses if email.primary][0]
    except IndexError:
        # Primary not set
        email = signup_invite.mail_addresses[0].email
    link = f"{req.app.context.config.invite_url}/{signup_invite.invite_code}"
    payload = EduidInviteEmail(
        email=email,
        reference=str(signup_invite.invite_id),
        invite_link=link,
        invite_code=signup_invite.invite_code,
        inviter_name=signup_invite.inviter_name,
        language=signup_invite.preferred_language,
    )
    app_name = req.app.context.name
    system_hostname = environ.get("SYSTEM_HOSTNAME", "")  # Underlying hosts name for containers
    hostname = environ.get("HOSTNAME", "")  # Actual hostname or container id
    sender_info = SenderInfo(hostname=hostname, node_id=f"{app_name}@{system_hostname}")
    expires_at = datetime.utcnow() + timedelta(seconds=req.app.context.config.invite_expire)
    discard_at = expires_at + timedelta(days=7)
    message = QueueItem(
        version=1,
        expires_at=expires_at,
        discard_at=discard_at,
        sender_info=sender_info,
        payload_type=payload.get_type(),
        payload=payload,
    )
    req.app.context.messagedb.save(message)
    req.app.context.logger.info(f"Saved invite email to address {email} in message queue")
    return True


def invites_to_resources_dicts(query: SearchRequest, invites: Sequence[ScimApiInvite]) -> list[dict[str, Any]]:
    _attributes = query.attributes
    # TODO: include the requested attributes, not just id
    return [{"id": str(invite.scim_id)} for invite in invites]


def save_invite(
    req: ContextRequest,
    db_invite: ScimApiInvite,
    signup_invite: SignupInvite,
    db_invite_is_in_database: bool,
    signup_invite_is_in_database: bool,
) -> None:
    try:
        req.context.invitedb.save(db_invite)
    except DuplicateKeyError as e:
        assert e.details is not None  # please mypy
        if "external-id" in e.details["errmsg"]:
            raise BadRequest(detail="externalID must be unique")
        raise BadRequest(detail="Duplicated key error")

    try:
        req.app.context.signup_invitedb.save(signup_invite, is_in_database=signup_invite_is_in_database)
    except DuplicateKeyError as e:
        assert e.details is not None  # please mypy
        if "invite_code" in e.details["errmsg"]:
            raise BadRequest(detail="invite_code must be unique")
        raise BadRequest(detail="Duplicated key error")


def filter_lastmodified(
    req: ContextRequest, filter: SearchFilter, skip: int | None = None, limit: int | None = None
) -> tuple[list[ScimApiInvite], int]:
    if filter.op not in ["gt", "ge"]:
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported operator")
    if not isinstance(filter.val, str):
        raise BadRequest(scim_type="invalidFilter", detail="Invalid datetime")
    return req.context.invitedb.get_invites_by_last_modified(
        operator=filter.op, value=datetime.fromisoformat(filter.val), skip=skip, limit=limit
    )
