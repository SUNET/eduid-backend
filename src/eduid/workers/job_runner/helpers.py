from eduid.userdb.user import User
from eduid.userdb.user_cleaner.userdb import CleanerUser
from eduid.workers.job_runner.context import Context


def save_and_sync_user(context: Context, user: User) -> bool:
    """
    Save to private userdb and propagate change to central user db.

    May raise UserOutOfSync exception

    :param user: the modified user
    """
    private_user = CleanerUser.from_user(user, context.private_db)
    context.private_db.save(private_user)
    context.logger.debug(
        f"Saving user {private_user} to private userdb {context.private_db} "
        f"(is_in_database: {user.meta.is_in_database})"
    )

    # Sync to central userdb
    context.logger.debug(f"Syncing {user} to central userdb")
    return context.am_relay.request_user_sync(user)
