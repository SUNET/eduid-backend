from eduid.common.models.amapi_user import Reason, Source, UserUpdateResponse, UserUpdateTerminateRequest
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, NavetData
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.userdb.meta import CleanerType
from eduid.userdb.user import User
from eduid.userdb.user_cleaner.db import CleanerQueueUser
from eduid.workers.job_runner.context import Context


def gather_skv_users(context: Context):
    """ "
    Gather and queue all users that should be checked against SKV API:s

    """
    context.logger.debug(f"gathering users to check")
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
    context.logger.debug(f"checking users")
    user = context.cleaner_queue.get_next_user()
    if user is not None:
        context.logger.debug(f"Checking if user with eppn {user.eppn} should be terminated")
        assert user.identities.nin is not None  # Please mypy
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
                reason = Reason.USER_DECEASED if cause == DeregisteredCauseCode.DECEASED else Reason.USER_DEREGISTERED
                terminate_user(context, user.eppn, reason)
        else:
            context.logger.debug(f"User with eppn {user.eppn} is still registered")

    else:
        context.logger.debug(f"Nothing to do")


def terminate_user(context: Context, eppn: str, reason: Reason):
    """
    Terminate a user
    """
    request_body: UserUpdateTerminateRequest = UserUpdateTerminateRequest(reason=reason, source=Source.SKV_NAVET_V2)
    response: UserUpdateResponse = context.amapi_client.update_user_terminate(user=eppn, body=request_body)
    context.logger.debug(f"Terminate user response: {response}")
