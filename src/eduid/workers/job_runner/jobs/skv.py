from eduid.common.misc.timeutil import utc_now
from eduid.common.proofing_utils import set_user_names_from_official_address
from eduid.common.rpc.exceptions import MsgTaskFailed
from eduid.common.rpc.msg_relay import FullPostalAddress, NavetData
from eduid.userdb.logs.element import NameUpdateProofing
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.db import CleanerQueueUser
from eduid.workers.job_runner.context import Context
from eduid.workers.job_runner.helpers import save_and_sync_user


def gather_skv_users(context: Context) -> None:
    """ "
    Gather and queue all users that should be checked against SKV API:s

    """
    context.logger.debug("gathering users to check")
    users: list[User] = context.central_db.get_unterminated_users_with_nin()
    context.logger.debug(f"gathered {len(users)} users to check")
    for user in users:
        if context.cleaner_queue.user_in_queue(cleaner_type=CleanerType.SKV, eppn=user.eppn):
            context.cleaner_queue.get_user_by_eppn(user.eppn)
            context.logger.debug(f"{user.eppn} already in queue")
        else:
            queue_user: CleanerQueueUser = CleanerQueueUser(
                eppn=user.eppn, cleaner_type=CleanerType.SKV, identities=user.identities
            )
            context.cleaner_queue.save(queue_user)


def check_skv_users(context: Context) -> None:
    """
    Check all users that should be checked against SKV API:s
    """
    context.logger.debug("checking users")
    user = context.cleaner_queue.get_next_user(CleanerType.SKV)
    if user is None:
        context.logger.debug("Nothing to do")
        return None

    context.stats.count("skv_users_checked")
    context.logger.debug(f"Checking if user with eppn {user.eppn} should be terminated")
    assert user.identities.nin is not None  # Please mypy
    try:
        navet_data: NavetData = context.msg_relay.get_all_navet_data(
            nin=user.identities.nin.number, allow_deregistered=True
        )
        context.logger.debug(f"Navet data: {navet_data}")
    except MsgTaskFailed:
        context.logger.critical(f"Failed to get Navet data for user with eppn {user.eppn}")
        # The user will be requeued for a new check by the next run of gather_skv_users
        return None

    # check if user is deregistered
    user_terminated = check_user_deregistered(context=context, user=user, navet_data=navet_data)
    if user_terminated:
        # User terminated, no more checks necessary
        return None
    check_user_official_name(context=context, queue_user=user, navet_data=navet_data)


def check_user_deregistered(context: Context, user: CleanerQueueUser, navet_data: NavetData) -> bool:
    if not navet_data.person.is_deregistered():
        context.logger.debug(f"User with eppn {user.eppn} is still registered")
        return False

    cause = navet_data.person.deregistration_information.cause_code
    assert cause is not None  # Please mypy

    if cause in context.config.skv.termination_cause_codes:
        context.logger.info(f"User with eppn {user.eppn} should be terminated, cause: {cause.value} ({cause.name})")
        terminate_user(context, user)
        context.stats.count("skv_users_terminated")
        context.stats.count(f"skv_users_terminated_cause_code_{cause.value}")
        return True

    context.stats.count(f"skv_users_not_terminated_cause_code_{cause.value}")
    context.logger.debug(
        f"User with eppn {user.eppn} with cause {cause.value} ({cause.name}) and should NOT be terminated"
    )
    return False


def check_user_official_name(context: Context, queue_user: CleanerQueueUser, navet_data: NavetData) -> None:
    """
    Check if the user's official name in Navet matches the official name in the central database.
    If not, update the official name in the central database.
    """
    # Update the user from the central db as they might have updated their name since being placed in the queue.
    user = context.central_db.get_user_by_eppn(queue_user.eppn)

    # Compare current names with what we got from Navet and update if necessary.
    # If the names are the same, do nothing.
    if user.given_name == navet_data.person.name.given_name and user.surname == navet_data.person.name.surname:
        return None

    user_postal_address = FullPostalAddress(
        name=navet_data.person.name,
        official_address=navet_data.person.postal_addresses.official_address,
    )

    assert user.identities.nin is not None  #  please mypy

    # Create a proofing log entry
    proofing_log_entry = NameUpdateProofing(
        created_by="job_runner_skv",
        eppn=user.eppn,
        proofing_version="2021v1",
        nin=user.identities.nin.number,
        previous_given_name=user.given_name or None,  # default to None for empty string
        previous_surname=user.surname or None,  # default to None for empty string
        user_postal_address=user_postal_address,
    )
    # Update user names
    user = set_user_names_from_official_address(user, proofing_log_entry)

    # Do not save the user if proofing log write fails
    if not context.proofing_log.save(proofing_log_entry):
        context.logger.error("Proofing log write failed")
        context.logger.debug(f"proofing_log_entry: {proofing_log_entry}")
        return None

    context.logger.info("Recorded verification in the proofing log")
    save_and_sync_user(context, user)
    context.stats.count(name="skv_name_updated")
    return None


def terminate_user(context: Context, queue_user: CleanerQueueUser) -> None:
    """
    Terminate a user
    """
    if context.dry_run:
        context.logger.info(f"Dry run: Would terminate user with eppn {queue_user.eppn}")
        context.logger.debug(f"CleanerQueueUser: {repr(queue_user)}")
        return None
    user = context.central_db.get_user_by_eppn(queue_user.eppn)
    user.terminated = utc_now()
    save_and_sync_user(context, user)
    context.logger.info(f"User with eppn {queue_user.eppn} marked as terminated.")
