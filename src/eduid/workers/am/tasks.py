import bson
from billiard.einfo import ExceptionInfo
from celery import Task
from celery.utils.log import get_task_logger

from eduid.userdb import AmDB
from eduid.userdb.exceptions import DBConnectionError, LockedIdentityViolation, UserDoesNotExist
from eduid.workers.am.common import AmCelerySingleton
from eduid.workers.am.consistency_checks import check_locked_identity, unverify_duplicates

logger = get_task_logger(__name__)

app = AmCelerySingleton.celery


class AttributeManager(Task):
    """Singleton that stores reusable objects like the MongoDB database client"""

    abstract = True  # This means Celery won't register this as another task

    def __init__(self) -> None:
        self._userdb: AmDB | None = None

    @property
    def userdb(self) -> AmDB | None:
        if self._userdb:
            return self._userdb
        if AmCelerySingleton.worker_config.mongo_uri:
            # self.userdb is the UserDB to which AM will write the updated users. This setting will
            # be None when this class is instantiated on the 'client' side (e.g. in a microservice)
            self._userdb = AmDB(AmCelerySingleton.worker_config.mongo_uri, "eduid_am")
        return self._userdb

    def on_failure(self, exc: Exception, task_id: str, args: tuple, kwargs: dict, einfo: ExceptionInfo) -> None:
        # The most common problem when tasks raise exceptions is that mongodb has switched master,
        # but it is hard to accurately trap the right exception without importing pymongo here so
        # let's just reload all databases (self.userdb here and the plugins databases) when we
        # get an exception
        logger.exception("Task failed. Reloading db and plugins.")
        self._userdb = None
        AmCelerySingleton.af_registry.reset()


@app.task(bind=True, base=AttributeManager, name="eduid_am.tasks.update_attributes_keep_result")
def update_attributes_keep_result(self: AttributeManager, app_name: str, user_id: str) -> bool:
    """
    This task is exactly the same as update_attributes, except that
    it keeps the celery results so that it can be used synchronously.

    :param self: base class
    :param app_name: calling application name, like 'eduid_signup'
    :param user_id: id for the user that has been updated by the calling application
    """
    logger.debug(f"Update attributes called for {user_id} by {app_name}")

    try:
        _id = bson.ObjectId(user_id)
    except bson.errors.InvalidId as e:
        logger.error(f"Invalid user_id {user_id} from app {app_name}")
        raise ValueError("Invalid user_id") from e

    try:
        attribute_fetcher = AmCelerySingleton.af_registry.get_fetcher(app_name)
        logger.debug(f"Attribute fetcher for {app_name}: {attribute_fetcher!r}")
    except KeyError as e:
        logger.error(f"Attribute fetcher for {app_name} is not installed")
        raise RuntimeError(f"Missing attribute fetcher, {e}") from e

    if not self.userdb:
        raise RuntimeError("Task has no userdb")

    try:
        attributes = attribute_fetcher.fetch_attrs(_id)
        replace_locked = attribute_fetcher.get_replace_locked(_id)
    except UserDoesNotExist as e:
        logger.error(f"The user {_id} does not exist in the database for plugin {app_name}: {e}")
        raise e
    except ValueError as e:
        logger.error(f"Error syncing user {_id}:  {e}")
        raise e

    try:
        logger.debug(f"Checking locked identity during sync attempt from {app_name}")
        attributes = check_locked_identity(self.userdb, _id, attributes, app_name, replace_locked)
    except LockedIdentityViolation as e:
        logger.error(e)
        raise e

    # TODO: Update mongodb to >3.2 (partial index support) so we can optimistically update a user and run this check
    # TODO: if the update fails
    logger.debug(f"Checking other users for already verified elements during sync attempt from {app_name}")
    unverify_duplicates(self.userdb, _id, attributes)

    logger.debug(f"Attributes fetched from app {app_name} for user {_id}: {attributes}")
    try:
        self.userdb.update_user(_id, attributes)
    except DBConnectionError as e:
        logger.error(f"update_attributes_keep_result connection error: {e}", exc_info=True)
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    return True


@app.task(bind=True, base=AttributeManager, name="eduid_am.tasks.pong")
def pong(self: AttributeManager, app_name: str) -> str:
    """
    eduID webapps periodically ping workers as a part of their health assessment.
    """
    _userdb = self.userdb
    if _userdb and _userdb.is_healthy():
        return f"pong for {app_name}"
    raise DBConnectionError("Database not healthy")
