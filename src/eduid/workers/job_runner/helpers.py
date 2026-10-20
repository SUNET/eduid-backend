from collections.abc import Callable
from datetime import timedelta

from eduid.common.misc.timeutil import utc_now
from eduid.queue.client import enqueue_email
from eduid.queue.db.message.payload import EmailPayload
from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.userdb import CleanerUser
from eduid.workers.job_runner.context import Context


def save_and_sync_user(context: Context, user: User, original: User | None = None) -> bool:
    """
    Save to private userdb and propagate change to central user db.

    The AM sync $sets whole attributes (e.g. identities) in the central db without any modified_ts check, and
    the private db modified_ts check only protects against other writers to the private job runner collection.
    To not overwrite changes made in the central db after the user was loaded (e.g. by a webapp), pass the user
    as loaded (before modification) as `original`. The identities in the central db are then compared with it.

    May raise UserOutOfSync exception

    :param user: the modified user
    :param original: the user as loaded from the central db, before modification
    """
    if original is not None:
        central_user = context.central_db.get_user_by_eppn(user.eppn)
        if central_user.identities.to_list_of_dicts() != original.identities.to_list_of_dicts():
            raise UserOutOfSync(f"Identities of user {user.eppn} changed in central db since it was loaded")
    private_user = CleanerUser.from_user(user, context.private_db)
    context.private_db.save(private_user)
    context.logger.debug(
        f"Saving user {private_user} to private userdb {context.private_db} "
        f"(is_in_database: {user.meta.is_in_database})"
    )

    # Sync to central userdb
    context.logger.debug(f"Syncing {user} to central userdb")
    return context.am_relay.request_user_sync(user)


def send_mail_to_user(
    context: Context, user: User, make_payload: Callable[[str, str, str], EmailPayload], expires_in: timedelta
) -> int:
    """
    Queue a mail to all verified mail addresses of the user.

    Callers must handle dry run mode themselves, this function always queues. The identity age jobs do so.

    :param user: the user to mail
    :param make_payload: called with (email, language, reference) for each address, returns the payload to queue
    :param expires_in: how long the queued mails are valid
    :returns: number of mails queued. A failure to queue a mail to one address is logged and does not
        prevent mails to the other addresses.
    """
    language = user.language or context.config.default_language
    sent = 0
    for address in user.mail_addresses.verified:
        reference = f"eppn={user.eppn},mail={address.email},ts={utc_now()}"
        try:
            payload = make_payload(address.email, language, reference)
            enqueue_email(
                messagedb=context.messagedb,
                app_name=context.config.app_name,
                payload=payload,
                expires_in=expires_in,
            )
        except Exception:
            context.logger.exception(f"Failed to queue mail for user {user.eppn}")
            continue
        context.logger.info(f"Queued {payload.get_type()} mail for user {user.eppn}")
        sent += 1
    return sent
