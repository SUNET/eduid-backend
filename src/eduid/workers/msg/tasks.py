import json
import logging
import smtplib
from collections import OrderedDict
from http import HTTPStatus
from typing import Any

from billiard.einfo import ExceptionInfo
from celery import Task
from celery.utils.log import get_task_logger
from hammock import Hammock
from smscom import SMSClient

from eduid.common.config.base import EduidEnvironment
from eduid.common.decorators import deprecated
from eduid.userdb.exceptions import ConnectionError
from eduid.workers.msg.cache import CacheMDB
from eduid.workers.msg.common import MsgCelerySingleton
from eduid.workers.msg.decorators import TransactionAudit
from eduid.workers.msg.exceptions import NavetAPIException
from eduid.workers.msg.utils import (
    load_template,
    navet_get_all_data,
    navet_get_name_and_official_address,
    navet_get_relations,
)

TRANSACTION_AUDIT_DB = "eduid_msg"
TRANSACTION_AUDIT_COLLECTION = "transaction_audit"


logger: logging.Logger = get_task_logger(__name__)
_CACHE: dict[str, CacheMDB] = {}

app = MsgCelerySingleton.celery


class MessageSender(Task):
    """
    Singleton that stores reusable objects.
    """

    abstract = True

    _sms: SMSClient | None = None
    _navet_api: Hammock | None = None

    @property
    def sms(self) -> SMSClient:
        if self._sms is None:
            self._sms = SMSClient(MsgCelerySingleton.worker_config.sms_acc, MsgCelerySingleton.worker_config.sms_key)
        return self._sms

    @property
    def smtp(self) -> smtplib.SMTP:
        config = MsgCelerySingleton.worker_config
        _smtp = smtplib.SMTP(config.mail_host, config.mail_port)
        if config.mail_starttls:
            _smtp.starttls()
        if config.mail_username and config.mail_password:
            _smtp.login(config.mail_username, config.mail_password)
        return _smtp

    @property
    def navet_api(self) -> Hammock:
        if self._navet_api is None:
            config = MsgCelerySingleton.worker_config
            auth = None
            if config.navet_api_user and config.navet_api_pw:
                auth = (config.navet_api_user, config.navet_api_pw)
            self._navet_api = Hammock(config.navet_api_uri, auth=auth, verify=config.navet_api_verify_ssl)
        return self._navet_api

    @staticmethod
    def cache(cache_name: str, ttl: int = 7200) -> CacheMDB:
        db_uri = MsgCelerySingleton.worker_config.mongo_uri
        db_name = MsgCelerySingleton.worker_config.mongo_dbname
        if db_uri is None:
            raise ValueError("db_uri not supplied")

        global _CACHE
        if cache_name not in _CACHE:
            _CACHE[cache_name] = CacheMDB(db_uri=db_uri, db_name=db_name, collection=cache_name, ttl=ttl)
        return _CACHE[cache_name]

    @staticmethod
    def reload_db() -> None:
        global _CACHE
        # Remove initiated cache dbs
        _CACHE = {}

    def on_failure(self, exc: Exception, task_id: str, args: tuple, kwargs: dict, einfo: ExceptionInfo) -> None:
        # Try to reload the db on connection failures (mongodb has probably switched master)
        if isinstance(exc, ConnectionError):
            logger.error("Task failed with db exception ConnectionError. Reloading db.")
            self.reload_db()

    @TransactionAudit()
    def send_message(
        self,
        message_type: str,
        reference: str,
        message_dict: dict,
        recipient: str,
        template: str,
        language: str,
        subject: str | None = None,
    ) -> str | None:
        """
        :param message_type: Message notification type (sms or mm)
        :param reference: Unique reference id
        :param message_dict: A dict of key value pairs used in the template of choice
        :param recipient: Recipient mobile phone number or social security number (depends on the choice of
                          message_type)
        :param template: Name of the message template to use
        :param language: Preferred language for the template.
        :param subject: (Optional) Subject used in my messages service or email deliveries
        :return: For type 'sms' a message id is returned if successful, if unsuccessful an error message is returned.
                 For type 'mm' a message id is returned if successful, the message id can be used to verify if that the
                 message has been delivered to the users mailbox service by calling
                 check_distribution_status(message_id), if unsuccessful an error message is returned.
        """
        conf = MsgCelerySingleton.worker_config

        msg = load_template(conf.template_dir, template, message_dict, language)

        # Only log the message if devel_mode is enabled
        if conf.devel_mode is True:
            logger.debug(
                f"\nType: {message_type}\nReference: {reference}\nRecipient: {recipient}"
                f"\nLang: {language}\nSubject: {subject}\nMessage:\n {msg}"
            )
            return "devel_mode"

        if message_type == "sms":
            logger.debug(f"Sending SMS to {recipient} using template {template} and language {language}")
            try:
                msg_bytes = msg.encode("utf-8")
                status = self.sms.send(msg_bytes, MsgCelerySingleton.worker_config.sms_sender, recipient, prio=2)
            except Exception as e:  # XXX: smscom only raises Exception right now
                logger.error(f"SMS task failed: {e}")
                raise e
        else:
            logger.error(f"Unknown message type: {message_type}")
            raise NotImplementedError(f"message_type {message_type} is not implemented")

        logger.debug(f"send_message result: {status}")
        return status

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

    def get_relations(self, identity_number: str) -> OrderedDict[str, Any] | None:
        """
        Fetch information about someones relatives from NAVET

        :param identity_number: Swedish national identity number
        :return: dict containing name and postal address
        """
        data = self._get_navet_data(identity_number)
        # Filter relations from the Navet lookup results
        return navet_get_relations(data)

    @staticmethod
    def get_devel_relations() -> OrderedDict[str, Any]:
        """
        Return a OrderedDict just as we would get from navet.
        """
        result = OrderedDict(
            [
                (
                    "Relations",
                    {
                        "Relation": [
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
                        ]
                    },
                )
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

    @TransactionAudit()
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

    @deprecated("This function seems unused")
    def set_audit_log_postal_address(self, audit_reference: str) -> bool:
        from eduid.userdb import MongoDB

        conn = MongoDB(self.MONGODB_URI)
        db = conn.get_database(TRANSACTION_AUDIT_DB)
        log_entry = db[TRANSACTION_AUDIT_COLLECTION].find_one({"data.audit_reference": audit_reference})
        if log_entry and log_entry.get("data", {}).get("recipient", None):
            result = get_postal_address(log_entry["data"]["recipient"])
            if result:
                address_dict = dict(result)
                log_entry["data"]["navet_response"] = address_dict
                db[TRANSACTION_AUDIT_COLLECTION].update({"_id": log_entry["_id"]}, log_entry)
                return True
        return False

    @TransactionAudit()
    def sendmail(self, sender: str, recipients: list, message: str, reference: str) -> dict:
        """
        Send mail

        :param sender: the From of the email
        :param recipients: the recipients of the email
        :param message: email.mime.multipart.MIMEMultipart message as a string
        :param reference: Audit reference to help cross reference audit log and events

        :return Dict of errors
        """

        # Just log the mail if in development mode
        # TODO: remove self.conf.devel_mode, use environment instead
        if (
            MsgCelerySingleton.worker_config.devel_mode is True
            or MsgCelerySingleton.worker_config.testing
            or MsgCelerySingleton.worker_config.environment == EduidEnvironment.dev
        ):
            logger.debug("sendmail task:")
            logger.debug(
                f"\nType: email\nReference: {reference}\nSender: {sender}\nRecipients: {recipients}\n"
                f"Message:\n{message}"
            )
            return {"devel_mode": True}

        return self.smtp.sendmail(sender, recipients, message)

    @TransactionAudit()
    def sendsms(self, recipient: str, message: str, reference: str) -> str:
        """
        Send sms

        :param recipient: the recipient of the sms
        :param message: message as a string (160 chars per sms)
        :param reference: Audit reference to help cross reference audit log and events

        :return Transaction ID
        """

        # Just log the sms if in development mode
        if (
            MsgCelerySingleton.worker_config.environment is EduidEnvironment.dev
            or MsgCelerySingleton.worker_config.devel_mode is True
        ):
            logger.debug("sendsms task:")
            logger.debug(f"\nType: sms\nReference: {reference}\nRecipient: {recipient}\nMessage:\n{message}")
            return "devel_mode"

        #  0701740605-0701740699 is a unused range from PTS
        #  https://www.pts.se/sv/bransch/telefoni/nummer-och-adressering/
        #  telefonnummer-for-anvandning-i-bocker-och-filmer-etc/
        UNUSED_RANGE_LOWER_END = 5
        UNUSED_RANGE_UPPER_END = 99
        if (
            recipient.startswith("+467017406")
            and UNUSED_RANGE_LOWER_END <= int(recipient.removeprefix("+467017406")) <= UNUSED_RANGE_UPPER_END
        ):
            logger.debug("sendsms task:")
            logger.debug(f"\nType: sms\nReference: {reference}\nRecipient: {recipient}\nMessage:\n{message}")
            return "no_op_number"

        return self.sms.send(message, MsgCelerySingleton.worker_config.sms_sender, recipient, prio=2)

    def pong(self, app_name: str | None) -> str:
        # Leverage cache to test mongo db health
        if self.cache("pong", 0).is_healthy():
            if app_name:
                return f"pong for {app_name}"
            # Old clients don't send app_name, and text-match the response to be exactly 'pong' in the health checks
            return "pong"
        raise ConnectionError("Database not healthy")


@app.task(bind=True, base=MessageSender, name="eduid_msg.tasks.sendmail")
def sendmail(
    self: MessageSender,
    sender: str,
    recipients: list,
    message: str,
    reference: str,
) -> dict:
    """
    :param self: base class
    :param sender: the From of the email
    :param recipients: the recipients of the email
    :param message: email.mime.multipart.MIMEMultipart message as a string
    :param reference: Audit reference to help cross reference audit log and events
    """
    try:
        return self.sendmail(sender, recipients, message, reference)
    except Exception as e:
        logger.error(f"sendmail task error: {e}", exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@app.task(bind=True, base=MessageSender, name="eduid_msg.tasks.sendsms")
def sendsms(self: MessageSender, recipient: str, message: str, reference: str) -> str:
    """
    :param self: base class
    :param recipient: the recipient of the sms
    :param message: message as a string (160 chars per sms)
    :param reference: Audit reference to help cross reference audit log and events
    """
    try:
        return self.sendsms(recipient, message, reference)
    except Exception as e:
        logger.error(f"sendsms task error: {e}", exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


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
        logger.error(f"get_all_navet_data task error: {e}", exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


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
        logger.error(f"get_postal_address task error: {e}", exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@app.task(bind=True, base=MessageSender, name="eduid_msg.tasks.get_relations_to")
def get_relations_to(self: MessageSender, identity_number: str, relative_nin: str) -> list[str]:
    """
    Get the relative status between identity_number and relative_nin.

    What is returned is a list of Navet codes. Known codes:
      M = spouse (make/maka)
      B = child (barn)
      FA = father
      MO = mother
      VF = some kind of legal guardian status. Childs typically have ['B', 'VF'] it seems.

    :param self: base class
    :param identity_number: Swedish national identity number
    :param relative_nin: Swedish national identity number
    """
    try:
        relations = self.get_relations(identity_number)
        if not relations:
            return []
        result = []
        # Entrys in relations['Relations']['Relation'] (a list) look like this:
        #
        #    {                                                      # noqa: ERA001
        #        "RelationId" : {                                   # noqa: ERA001
        #                "NationalIdentityNumber" : "200001011234
        #        },
        #        "RelationType" : "B",                              # noqa: ERA001
        #        "RelationStartDate" : "20000101"
        #    },
        #
        # (I wonder what other types of Relations than Relation that NAVET can come up with...)
        import pprint

        logger.debug(
            f"Looking for relations between {identity_number} and {relative_nin} in: {pprint.pformat(relations)}"
        )
        for d in relations["Relations"]["Relation"]:
            if d.get("RelationId", {}).get("NationalIdentityNumber") == relative_nin:
                if "RelationType" in d:
                    result.append(d["RelationType"])
        return result
    except Exception as e:
        logger.error(f"get_relations_to task error: {e}", exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@app.task(bind=True, base=MessageSender)
@deprecated("This task seems unused")
def set_audit_log_postal_address(self: MessageSender, audit_reference: str) -> bool:
    """
    Looks in the transaction audit collection for the audit reference and make a postal address lookup and adds the
    result to the transaction audit document.
    """
    try:
        return self.set_audit_log_postal_address(audit_reference)
    except Exception as e:
        logger.error(f"set_audit_log_postal_address task error: {e}", exc_info=True)
        raise e


@app.task(bind=True, base=MessageSender, name="eduid_msg.tasks.pong")
def pong(self: MessageSender, app_name: str | None = None) -> str:
    """
    eduID webapps periodically ping workers as a part of their health assessment.

    TODO: Make app_name non-optional when all clients are updated.
    """
    return self.pong(app_name)
