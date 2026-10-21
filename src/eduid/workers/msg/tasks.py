import json
import logging
from collections import OrderedDict
from http import HTTPStatus
from typing import Any, ClassVar

from billiard.einfo import ExceptionInfo
from celery.utils.log import get_task_logger
from hammock import Hammock  # type: ignore[import-untyped]

from eduid.userdb.exceptions import DBConnectionError
from eduid.workers.celery_typing import Task
from eduid.workers.msg.cache import CacheMDB
from eduid.workers.msg.common import MsgCelerySingleton
from eduid.workers.msg.exceptions import NavetAPIException
from eduid.workers.msg.utils import (
    navet_get_all_data,
    navet_get_name_and_official_address,
)

logger: logging.Logger = get_task_logger(__name__)

app = MsgCelerySingleton.celery


class MessageSender(Task[Any, Any]):
    """
    Singleton that stores reusable objects.
    """

    abstract = True

    _navet_api: Hammock | None = None
    _cache_store: ClassVar[dict[str, CacheMDB]] = {}

    @property
    def navet_api(self) -> Hammock:
        if self._navet_api is None:
            config = MsgCelerySingleton.worker_config
            auth = None
            if config.navet_api_user and config.navet_api_pw:
                auth = (config.navet_api_user, config.navet_api_pw)
            self._navet_api = Hammock(config.navet_api_uri, auth=auth, verify=config.navet_api_verify_ssl)
        return self._navet_api

    @classmethod
    def cache(cls, cache_name: str, ttl: int = 7200) -> CacheMDB:
        db_uri = MsgCelerySingleton.worker_config.mongo_uri
        db_name = MsgCelerySingleton.worker_config.mongo_dbname
        if db_uri is None:
            raise ValueError("db_uri not supplied")

        if cache_name not in cls._cache_store:
            cls._cache_store[cache_name] = CacheMDB(db_uri=db_uri, db_name=db_name, collection=cache_name, ttl=ttl)
        return cls._cache_store[cache_name]

    @classmethod
    def reload_db(cls) -> None:
        # Remove initiated cache dbs
        cls._cache_store = {}

    def on_failure(
        self, exc: Exception, task_id: str, args: tuple[Any, ...], kwargs: dict[str, Any], einfo: ExceptionInfo
    ) -> None:
        # Try to reload the db on connection failures (mongodb has probably switched master)
        if isinstance(exc, DBConnectionError):
            logger.error("Task failed with db exception ConnectionError. Reloading db.")
            self.reload_db()

    def get_postal_address(self, identity_number: str) -> OrderedDict[str, Any] | None:
        """
        Fetch name and postal address from NAVET

        :param identity_number: Swedish national identity number
        :return: dict containing name and postal address
        """
        data = self._get_navet_data(identity_number)
        # Filter name and address from the Navet lookup results
        return navet_get_name_and_official_address(data)

    @staticmethod
    def get_devel_postal_address() -> OrderedDict[str, Any]:
        """
        Return a OrderedDict just as we would get from navet.
        """
        result = OrderedDict(
            [
                (
                    "Name",
                    OrderedDict([("GivenNameMarking", "20"), ("GivenName", "Testaren Test"), ("Surname", "Testsson")]),
                ),
                (
                    "OfficialAddress",
                    OrderedDict([("Address2", "\xd6RGATAN 79 LGH 10"), ("PostalCode", "12345"), ("City", "LANDET")]),
                ),
            ]
        )
        return result

    def get_all_navet_data(self, identity_number: str) -> OrderedDict[str, Any] | None:
        data = self._get_navet_data(identity_number)
        return navet_get_all_data(data)

    @staticmethod
    def get_devel_all_navet_data(identity_number: str = "190102031234") -> OrderedDict[str, Any]:
        """
        Return a dict with devel data
        Birthdates preceding 1900 are shown as deceased for testing purposes
        """
        DEVEL_BREAKOFF_YEAR = 1900

        deregistration_information = {}
        birth_year = int(identity_number[0:4])
        if birth_year < DEVEL_BREAKOFF_YEAR:
            deregistration_information = {"date": "20220315", "causeCode": "AV"}

        result = OrderedDict(
            {
                "CaseInformation": {"lastChanged": "20170904141659"},
                "Person": {
                    "PersonId": {"NationalIdentityNumber": identity_number},
                    "ReferenceNationalIdentityNumber": "",
                    "DeregistrationInformation": deregistration_information,
                    "Name": {"GivenNameMarking": "20", "GivenName": "Testaren Test", "Surname": "Testsson"},
                    "PostalAddresses": {
                        "OfficialAddress": {"Address2": "ÖRGATAN 79 LGH 10", "PostalCode": "12345", "City": "LANDET"}
                    },
                    "Relations": [
                        {
                            "RelationType": "VF",
                            "RelationId": {"NationalIdentityNumber": "200202025678"},
                            "RelationStartDate": "20020202",
                        },
                        {
                            "RelationType": "VF",
                            "RelationId": {"NationalIdentityNumber": "200101014567"},
                            "RelationStartDate": "20010101",
                        },
                        {"RelationType": "FA", "RelationId": {"NationalIdentityNumber": "194004048989"}},
                        {"RelationType": "MO", "RelationId": {"NationalIdentityNumber": "195010106543"}},
                        {"RelationType": "B", "RelationId": {"NationalIdentityNumber": "200202025678"}},
                        {"RelationType": "B", "RelationId": {"NationalIdentityNumber": "200101014567"}},
                        {"RelationType": "M", "RelationId": {"NationalIdentityNumber": "197512125432"}},
                    ],
                },
            }
        )
        return result

    def _get_navet_data(self, identity_number: str) -> dict[str, Any] | None:
        """
        Fetch all data about a NIN from Navet.

        :param identity_number: Swedish national identity number
        :return: Loaded JSON
        """
        json_data = self.cache("navet_cache").get_cache_item(identity_number)
        if json_data is None:
            post_data = json.dumps({"identity_number": identity_number})
            response = self.navet_api.personpost.navetnotification.POST(data=post_data)
            if response.status_code != HTTPStatus.OK:
                raise NavetAPIException(repr(response))
            json_data = response.json()
            if not json_data.get("PopulationItems", False):
                logger.info("No PopulationItems returned")
                logger.debug(f"for nin: {identity_number}")
                return None
            self.cache("navet_cache").add_cache_item(identity_number, json_data)
        return json_data

    def pong(self, app_name: str | None) -> str:
        # Leverage cache to test mongo db health
        if self.cache("pong", 0).is_healthy():
            if app_name:
                return f"pong for {app_name}"
            # Old clients don't send app_name, and text-match the response to be exactly 'pong' in the health checks
            return "pong"
        raise DBConnectionError("Database not healthy")


@app.task(bind=True, base=MessageSender, name="eduid_msg.tasks.get_all_navet_data")
def get_all_navet_data(self: MessageSender, identity_number: str) -> OrderedDict[str, Any] | None:
    """
    Retrieve all data about the person from the Swedish population register using a Swedish national
    identity number.

    :param self: base class
    :param identity_number: Swedish national identity number
    :return: Ordered dict
    """
    try:
        return self.get_all_navet_data(identity_number)
    except Exception as e:
        logger.exception("get_all_navet_data task error")
        raise self.retry(countdown=1, max_retries=3, exc=e) from e


@app.task(bind=True, base=MessageSender, name="eduid_msg.tasks.get_postal_address")
def get_postal_address(self: MessageSender, identity_number: str) -> OrderedDict[str, Any] | None:
    """
    Retrieve name and postal address from the Swedish population register using a Swedish national
    identity number.

    :param self: base class
    :param identity_number: Swedish national identity number
    :return: Ordered dict
    """
    try:
        return self.get_postal_address(identity_number)
    except Exception as e:
        logger.exception("get_postal_address task error")
        raise self.retry(countdown=1, max_retries=3, exc=e) from e


@app.task(bind=True, base=MessageSender, name="eduid_msg.tasks.pong")
def pong(self: MessageSender, app_name: str | None = None) -> str:
    """
    eduID webapps periodically ping workers as a part of their health assessment.

    TODO: Make app_name non-optional when all clients are updated.
    """
    return self.pong(app_name)
