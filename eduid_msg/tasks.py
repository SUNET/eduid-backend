# -*- encoding: utf-8 -*-

import json
import smtplib
from collections import OrderedDict
from datetime import datetime, timedelta
from time import time
from typing import List, Optional, Union

from celery import Task
from celery.task import periodic_task, task
from celery.utils.log import get_task_logger

from eduid_userdb.exceptions import ConnectionError

from eduid_msg.cache import CacheMDB
from eduid_msg.common import celery
from eduid_msg.decorators import TransactionAudit
from eduid_msg.exceptions import NavetAPIException, NavetException
from eduid_msg.utils import load_template, navet_get_name_and_official_address, navet_get_relations
from eduid_msg.worker import worker_config
from hammock import Hammock

if celery is None:
    raise RuntimeError('Must call eduid_msg.init_app before importing tasks')


DEFAULT_MONGODB_HOST = 'localhost'
DEFAULT_MONGODB_PORT = 27017
DEFAULT_MONGODB_NAME = 'eduid_msg'
DEFAULT_MONGODB_URI = 'mongodb://%s:%d/%s' % (DEFAULT_MONGODB_HOST, DEFAULT_MONGODB_PORT, DEFAULT_MONGODB_NAME)

TRANSACTION_AUDIT_DB = 'eduid_msg'
TRANSACTION_AUDIT_COLLECTION = 'transaction_audit'

DEFAULT_MM_API_HOST = 'eduid-mm-service.docker'
DEFAULT_MM_API_PORT = 8080
DEFAULT_MM_API_URI = 'http://{0}:{1}'.format(DEFAULT_MM_API_HOST, DEFAULT_MM_API_PORT)

DEFAULT_NAVET_API_HOST = 'eduid-navet-service.docker'
DEFAULT_NAVET_API_PORT = 8080
DEFAULT_NAVET_API_URI = 'http://{0}:{1}'.format(DEFAULT_NAVET_API_HOST, DEFAULT_NAVET_API_PORT)


logger = get_task_logger(__name__)
_CACHE: dict = {}
MESSAGE_RATE_LIMIT = worker_config.message_rate_limit


class MessageRelay(Task):
    """
    Singleton that stores reusable objects.
    """

    abstract = True
    _sms = None
    _sms_sender = None
    _mm_api = None
    _navet_api = None
    _config = worker_config
    MONGODB_URI = _config.mongo_uri
    MM_API_URI = _config['MM_API_URI'] if 'MM_API_URI' in _config else DEFAULT_MM_API_URI
    NAVET_API_URI = _config.navet_api_uri
    if _config.audit == 'true':
        TransactionAudit.enable()

    @property
    def sms(self):
        if self._sms is None:
            from smscom import SMSClient

            self._sms = SMSClient(self._config.sms_acc, self._config.sms_key)
            self._sms_sender = self._config.sms_sender
        return self._sms

    @property
    def smtp(self):
        host = self._config.mail_host
        port = self._config.mail_port
        _smtp = smtplib.SMTP(host, port)
        starttls = self._config.mail_starttls
        if starttls:
            keyfile = self._config.mail_keyfile
            certfile = self._config.mail_certfile
            if keyfile and certfile:
                _smtp.starttls(keyfile, certfile)
            else:
                _smtp.starttls()
        username = self._config.mail_username
        password = self._config.mail_password
        if username and password:
            _smtp.login(username, password)
        return _smtp

    @property
    def mm_api(self):
        if self._mm_api is None:
            verify_ssl = True
            auth = None
            if self._config.mm_api_verify_ssl == 'false':
                verify_ssl = False
            if self._config.mm_api_user and self._config.mm_api_pw:
                auth = (self._config.mm_api_user, self._config.mm_api_pw)
            self._mm_api = Hammock(self.MM_API_URI, auth=auth, verify=verify_ssl)
        return self._mm_api

    @property
    def navet_api(self):
        if self._navet_api is None:
            verify_ssl = True
            auth = None
            if self._config.navet_api_verify_ssl == 'false':
                verify_ssl = False
            if self._config.navet_api_user and self._config.navet_api_pw:
                auth = (self._config.navet_api_user, self._config.navet_api_pw)
            self._navet_api = Hammock(self.NAVET_API_URI, auth=auth, verify=verify_ssl)
        return self._navet_api

    def cache(self, cache_name, ttl=7200):
        global _CACHE
        if cache_name not in _CACHE:
            _CACHE[cache_name] = CacheMDB(
                self._config.mongo_uri, self._config.mongo_dbname, cache_name, ttl=ttl, expiration_freq=120
            )
        return _CACHE[cache_name]

    @staticmethod
    def reload_db():
        global _CACHE
        # Remove initiated cache dbs
        _CACHE = {}

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        # Try to reload the db on connection failures (mongodb has probably switched master)
        if isinstance(exc, ConnectionError):
            logger.error('Task failed with db exception ConnectionError. Reloading db.')
            self.reload_db()

    def is_reachable(self, identity_number: str) -> Union[bool, str]:
        """
        Check if the user is registered with Swedish government mailbox service.

        :param identity_number: User social security number
        :return: True if the user is reachable, False if the user is not registered with the government mailbox service.
                 'Anonymous' if the user is registered but has not confirmed their identity with the government mailbox
                  service.
                 'Sender_not' if the sender (you) is blocked by the recipient.
        """
        result = self.cache('recipient_cache', 7200).get_cache_item(identity_number)

        if result is None:
            result = self._get_is_reachable(identity_number)
            if result['AccountStatus']['Type'] == 'Secure' and result['SenderAccepted']:
                self.cache('recipient_cache').add_cache_item(identity_number, result)

        if result['AccountStatus']['Type'] == 'Secure':
            if result['SenderAccepted']:
                return True
            else:
                return 'Sender_not'
        elif result['AccountStatus']['Type'] == 'Not':
            return False
        elif result['AccountStatus']['Type'] == 'Anonymous':
            return 'Anonymous'
        return False

    def get_mailbox_url(self, identity_number: str) -> Optional[str]:
        """
        :param identity_number: User social security number
        :return: Returns mailbox URL if the user exist and accept messages from the sender.
        """
        result = self.cache('recipient_cache', 7200).get_cache_item(identity_number)
        if result is None:
            result = self._get_is_reachable(identity_number)
            if result['AccountStatus']['Type'] == 'Secure' and result['SenderAccepted']:
                self.cache('recipient_cache').add_cache_item(identity_number, result)

        if result['AccountStatus']['Type'] == 'Secure':
            if result['SenderAccepted']:
                return result['AccountStatus']['ServiceSupplier']['ServiceAddress']
        return None

    @TransactionAudit(MONGODB_URI)
    def _get_is_reachable(self, identity_number: str) -> dict:
        # Users always reachable in devel mode
        conf = self._config
        if conf.devel_mode is True:
            logger.debug(f"Faking that NIN {identity_number} is reachable")
            return {
                'AccountStatus': {'Type': 'Secure', 'ServiceSupplier': 'devel_mode'},
                'SenderAccepted': 'devel_mode',
            }
        data = json.dumps({'identity_number': identity_number})
        response = self.mm_api.user.reachable.POST(data=data)
        if response.status_code == 200:
            return response.json()
        error = 'MM API is_reachable response: {0} {1}'.format(
            response.status_code, response.json().get('message', 'No message')
        )
        logger.error(error)
        raise RuntimeError(error)

    @TransactionAudit(MONGODB_URI)
    def send_message(
        self,
        message_type: str,
        reference: str,
        message_dict: dict,
        recipient: str,
        template: str,
        language: str,
        subject: Optional[str] = None,
    ) -> Optional[str]:
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
        conf = self._config

        msg = load_template(conf.template_dir, template, message_dict, language)

        # Only log the message if devel_mode is enabled
        if conf.devel_mode is True:
            logger.debug(
                f"\nType: {message_type}\nReference: {reference}\nRecipient: {recipient}"
                f"\nLang: {language}\nSubject: {subject}\nMessage:\n {msg}"
            )
            return 'devel_mode'

        if message_type == 'sms':
            logger.debug(f"Sending SMS to {recipient} using template {template} and language {language}")
            try:
                msg_bytes = msg.encode('utf-8')
                status = self.sms.send(msg_bytes, self._sms_sender, recipient, prio=2)
            except Exception as e:  # XXX: smscom only raises Exception right now
                logger.error(f'SMS task failed: {e}')
                raise e

        elif message_type == 'mm':
            logger.debug("Sending MM to '%s' using language '%s'" % (recipient, language))
            reachable = self.is_reachable(recipient)

            if reachable is not True:
                logger.debug(f"User not reachable - reason: {reachable}")
                if isinstance(reachable, str):
                    return reachable
                return None

            if subject is None:
                subject = f'{conf.mm_default_subject}'  # make mypy happy

            status = self._send_mm_message(recipient, subject, 'text/html', language.replace('_', ''), msg)
        else:
            logger.error(f'Unknown message type: {message_type}')
            raise NotImplementedError(f'message_type {message_type} is not implemented')

        logger.debug(f'send_message result: {status}')
        return status

    def _send_mm_message(self, recipient: str, subject: str, content_type: str, language: str, message: str) -> str:
        data = json.dumps(
            {
                'recipient': recipient,
                'subject': subject,
                'content_type': content_type,
                'language': language,
                'message': message,
            }
        )
        response = self.mm_api.message.send.POST(data=data)
        logger.debug(f"_send_mm_message response for recipient '{recipient}': '{repr(response)}'")
        if response.status_code == 200:
            return response.json()['transaction_id']
        error = f"MM API send message response: {response.status_code} {response.json().get('message', 'No message')}"
        logger.error(error)
        raise RuntimeError(error)

    def get_postal_address(self, identity_number: str) -> Optional[OrderedDict]:
        """
        Fetch name and postal address from NAVET

        :param identity_number: Swedish national identity number
        :return: dict containing name and postal address
        """
        # Only log the message if devel_mode is enabled
        conf = self._config
        if conf.devel_mode is True:
            return self.get_devel_postal_address()

        data = self._get_navet_data(identity_number)
        # Filter name and address from the Navet lookup results
        return navet_get_name_and_official_address(data)

    @staticmethod
    def get_devel_postal_address() -> OrderedDict:
        """
        Return a OrderedDict just as we would get from navet.
        """
        result = OrderedDict(
            [
                (
                    u'Name',
                    OrderedDict(
                        [(u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'), (u'Surname', u'Testsson')]
                    ),
                ),
                (
                    u'OfficialAddress',
                    OrderedDict(
                        [(u'Address2', u'\xd6RGATAN 79 LGH 10'), (u'PostalCode', u'12345'), (u'City', u'LANDET')]
                    ),
                ),
            ]
        )
        return result

    def get_relations(self, identity_number: str) -> Optional[OrderedDict]:
        """
        Fetch information about someones relatives from NAVET

        :param identity_number: Swedish national identity number
        :return: dict containing name and postal address
        """
        # Only log the message if devel_mode is enabled
        conf = self._config
        if conf.devel_mode is True:
            return self.get_devel_relations()

        data = self._get_navet_data(identity_number)
        # Filter relations from the Navet lookup results
        return navet_get_relations(data)

    @staticmethod
    def get_devel_relations() -> OrderedDict:
        """
        Return a OrderedDict just as we would get from navet.
        """
        result = OrderedDict(
            [
                (
                    u'Relations',
                    {
                        u'Relation': [
                            {
                                u'RelationType': u'VF',
                                u'RelationId': {u'NationalIdentityNumber': u'200202025678'},
                                u'RelationStartDate': u'20020202',
                            },
                            {
                                u'RelationType': u'VF',
                                u'RelationId': {u'NationalIdentityNumber': u'200101014567'},
                                u'RelationStartDate': u'20010101',
                            },
                            {u'RelationType': u'FA', u'RelationId': {u'NationalIdentityNumber': u'194004048989'}},
                            {u'RelationType': u'MO', u'RelationId': {u'NationalIdentityNumber': u'195010106543'}},
                            {u'RelationType': u'B', u'RelationId': {u'NationalIdentityNumber': u'200202025678'}},
                            {u'RelationType': u'B', u'RelationId': {u'NationalIdentityNumber': u'200101014567'}},
                            {u'RelationType': u'M', u'RelationId': {u'NationalIdentityNumber': u'197512125432'}},
                        ]
                    },
                )
            ]
        )
        return result

    @TransactionAudit(MONGODB_URI)
    def _get_navet_data(self, identity_number: str) -> dict:
        """
        Fetch all data about a NIN from Navet.

        :param identity_number: Swedish national identity number
        :return: Loaded JSON
        """
        json_data = self.cache('navet_cache').get_cache_item(identity_number)
        if json_data is None:
            post_data = json.dumps({'identity_number': identity_number})
            response = self.navet_api.personpost.navetnotification.POST(data=post_data)
            if response.status_code != 200:
                raise NavetAPIException(repr(response))
            json_data = response.json()
            if not json_data.get('PopulationItems', False):
                raise NavetException('No PopulationItems returned')
            self.cache('navet_cache').add_cache_item(identity_number, json_data)
        return json_data

    def set_audit_log_postal_address(self, audit_reference: str) -> bool:
        from eduid_userdb import MongoDB

        conn = MongoDB(self.MONGODB_URI)
        db = conn.get_database(TRANSACTION_AUDIT_DB)
        log_entry = db[TRANSACTION_AUDIT_COLLECTION].find_one({'data.audit_reference': audit_reference})
        if log_entry and log_entry.get('data', {}).get('recipient', None):
            result = get_postal_address(log_entry['data']['recipient'])
            if result:
                address_dict = dict(result)
                log_entry['data']['navet_response'] = address_dict
                db[TRANSACTION_AUDIT_COLLECTION].update({'_id': log_entry['_id']}, log_entry)
                return True
        return False

    @TransactionAudit(MONGODB_URI)
    def sendmail(
        self, sender: str, recipients: list, message: str, reference: str, max_retry_seconds: Optional[int] = None
    ) -> dict:
        """
        Send mail

        :param sender: the From of the email
        :param recipients: the recipients of the email
        :param message: email.mime.multipart.MIMEMultipart message as a string
        :param reference: Audit reference to help cross reference audit log and events
        :param max_retry_seconds: DEPRECATED

        :return Dict of errors
        """

        # Just log the mail if in development mode
        conf = self._config
        if conf.devel_mode is True:
            logger.debug('sendmail task:')
            logger.debug(
                f"\nType: email\nReference: {reference}\nSender: {sender}\nRecipients: {recipients}\n"
                f"Message:\n{message}"
            )
            return {'devel_mode': True}

        return self.smtp.sendmail(sender, recipients, message)

    @TransactionAudit(MONGODB_URI)
    def sendsms(self, recipient: str, message: str, reference: str, max_retry_seconds: Optional[int] = None) -> str:
        """
        Send sms

        :param recipient: the recipient of the sms
        :param message: message as a string (160 chars per sms)
        :param reference: Audit reference to help cross reference audit log and events
        :param max_retry_seconds: DEPRECATED

        :return Transaction ID
        """

        # Just log the sms if in development mode
        conf = self._config
        if conf.devel_mode is True:
            logger.debug('sendsms task:')
            logger.debug(f"\nType: sms\nReference: {reference}\nRecipient: {recipient}\nMessage:\n{message}")
            return 'devel_mode'

        return self.sms.send(message, self._sms_sender, recipient, prio=2)

    def pong(self):
        # Leverage cache to test mongo db health
        if self.cache('pong', 0).conn.is_healthy():
            return 'pong'
        raise ConnectionError('Database not healthy')


@task(bind=True, base=MessageRelay)
def is_reachable(self, identity_number: str) -> bool:
    """
    Check if the user is registered with Swedish government mailbox service.

    :param self: base clas
    :param identity_number: Swedish national identity number
    :return: True if the user is reachable, otherwise False
    """
    try:
        return self.is_reachable(identity_number)
    except Exception as e:
        logger.error(f'is_reachable task error: {e}', exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@task(bind=True, base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT)
def send_message(
    self: MessageRelay,
    message_type: str,
    reference: str,
    message_dict: dict,
    recipient: str,
    template: str,
    language: str,
    subject: Optional[str] = None,
) -> str:
    """
    :param self: base class
    :param message_type: Message notification type (sms or mm)
    :param reference: Audit reference to help cross reference audit log and events
    :param message_dict: A dict of key value pairs used in the template of choice
    :param recipient: Recipient phone number or social security number (depends on the choice of message_type)
    :param template: Name of the message template to use
    :param language: Preferred language for the template
    :param subject: Optional message subject
    """
    try:
        return self.send_message(message_type, reference, message_dict, recipient, template, language, subject)
    except Exception as e:
        logger.error(f'send_message task error: {e}', exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@task(bind=True, base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT)
def sendmail(
    self: MessageRelay,
    sender: str,
    recipients: list,
    message: str,
    reference: str,
    max_retry_seconds: Optional[int] = None,
) -> dict:
    """
    :param self: base class
    :param sender: the From of the email
    :param recipients: the recipients of the email
    :param message: email.mime.multipart.MIMEMultipart message as a string
    :param reference: Audit reference to help cross reference audit log and events
    :param max_retry_seconds: DEPRECATED
    """
    try:
        return self.sendmail(sender, recipients, message, reference)
    except Exception as e:
        logger.error(f'sendmail task error: {e}', exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@task(bind=True, base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT)
def sendsms(
    self: MessageRelay, recipient: str, message: str, reference: str, max_retry_seconds: Optional[int] = None
) -> str:
    """
    :param self: base class
    :param recipient: the recipient of the sms
    :param message: message as a string (160 chars per sms)
    :param reference: Audit reference to help cross reference audit log and events
    :param max_retry_seconds: DEPRECATED
    """
    try:
        return self.sendsms(recipient, message, reference)
    except Exception as e:
        logger.error(f'sendsms task error: {e}', exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@task(bind=True, base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT)
def get_postal_address(self: MessageRelay, identity_number: str) -> Optional[OrderedDict]:
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
        logger.error(f'get_postal_address task error: {e}', exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@task(bind=True, base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT)
def get_relations_to(self: MessageRelay, identity_number: str, relative_nin: str) -> List[str]:
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
        #    {
        #        "RelationId" : {
        #                "NationalIdentityNumber" : "200001011234
        #        },
        #        "RelationType" : "B",
        #        "RelationStartDate" : "20000101"
        #    },
        #
        # (I wonder what other types of Relations than Relation that NAVET can come up with...)
        import pprint

        logger.debug(
            f"Looking for relations between {identity_number} and {relative_nin} in: " f"{pprint.pformat(relations)}"
        )
        for d in relations['Relations']['Relation']:
            if d.get('RelationId', {}).get("NationalIdentityNumber") == relative_nin:
                if 'RelationType' in d:
                    result.append(d['RelationType'])
        return result
    except Exception as e:
        logger.error(f'get_relations_to task error: {e}', exc_info=True)
        # self.retry raises Retry exception, assert False will not be reached
        self.retry(default_retry_delay=1, max_retries=3, exc=e)
    assert False  # make mypy happy


@task(bind=True, base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT)
def set_audit_log_postal_address(self, audit_reference: str) -> bool:
    """
    Looks in the transaction audit collection for the audit reference and make a postal address lookup and adds the
    result to the transaction audit document.
    """
    try:
        return self.set_audit_log_postal_address(audit_reference)
    except Exception as e:
        logger.error(f'set_audit_log_postal_address task error: {e}', exc_info=True)
        raise e


@periodic_task(run_every=timedelta(minutes=5))
def cache_expire():
    """
    Periodic function executed every 5 minutes to expire cached items.
    """
    global _CACHE
    for cache in _CACHE.keys():
        logger.debug(f"Invoking expire_cache at {datetime.fromtimestamp(time(), None)} for {cache}")
        _CACHE[cache].expire_cache_items()


@task(bind=True, base=MessageRelay)
def pong(self):
    return self.pong()
