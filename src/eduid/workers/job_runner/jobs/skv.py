from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.exceptions import MsgTaskFailed
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, NavetData
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.db import CleanerQueueUser
from eduid.workers.job_runner.context import Context
from eduid.workers.job_runner.helpers import save_and_sync_user


def gather_skv_users(context: Context):
    """ "
    Gather and queue all users that should be checked against SKV API:s

    """
    context.logger.debug("gathering users to check")
    users: list[User] = context.db.get_unterminated_users_with_nin()
    context.logger.debug(f"gathered {len(users)} users to check")
    for user in users:
        try:
            context.cleaner_queue.get_user_by_eppn(user.eppn)
            context.logger.debug(f"{user.eppn} already in queue")
        except UserDoesNotExist:
            queue_user: CleanerQueueUser = CleanerQueueUser(
                eppn=user.eppn, cleaner_type=CleanerType.SKV, identities=user.identities
            )
            context.cleaner_queue.save(queue_user)


def check_skv_users(context: Context):
    """
    Check all users that should be checked against SKV API:s
    """
    context.logger.debug("checking users")
    user = context.cleaner_queue.get_next_user(CleanerType.SKV)
    if user is not None:
        context.logger.debug(f"Checking if user with eppn {user.eppn} should be terminated")
        assert user.identities.nin is not None  # Please mypy
        try:
            navet_data: NavetData = context.msg_relay.get_all_navet_data(
                nin=user.identities.nin.number, allow_deregistered=True
            )
            context.logger.debug(f"Navet data: {navet_data}")

            if navet_data.person.is_deregistered():
                cause = navet_data.person.deregistration_information.cause_code
                if cause is DeregisteredCauseCode.EMIGRATED:
                    context.logger.debug(f"User with eppn {user.eppn} has emigrated and should not be terminated")
                else:
                    context.logger.debug(f"User with eppn {user.eppn} should be terminated")
                    terminate_user(context, user)
            else:
                context.logger.debug(f"User with eppn {user.eppn} is still registered")
        except MsgTaskFailed:
            context.logger.error(f"Failed to get Navet data for user with eppn {user.eppn}")
            # The user will be requeued for a new check by the next run of gather_skv_users
    else:
        context.logger.debug("Nothing to do")


def terminate_user(context: Context, queue_user: CleanerQueueUser):
    """
    Terminate a user
    """
    user = context.db.get_user_by_eppn(queue_user.eppn)
    user.terminated = utc_now()
    save_and_sync_user(context, user)