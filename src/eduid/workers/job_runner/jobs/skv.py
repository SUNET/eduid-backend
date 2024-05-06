from eduid.workers.job_runner.context import Context


def gather_skv_users(context: Context):
    """ "
    Gather and queue all users that should be checked against SKV API:s

    """
    context.logger.debug(f"gathering users to check")


def check_skv_users(context: Context):
    """
    Check all users that should be checked against SKV API:s
    """
    context.logger.debug(f"checking users")
