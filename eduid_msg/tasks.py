from __future__ import absolute_import

from celery import Task
from celery.utils.log import get_task_logger
from celery.task import periodic_task
from smscom import SMSClient
from pymmclient.message import Message
from pymmclient.recipient import Recipient
from eduid_msg.celery import celery
from eduid_msg.cache import CacheMDB
from eduid_msg.db import DEFAULT_MONGODB_URI, DEFAULT_MONGODB_NAME
from time import time
from datetime import datetime, timedelta

logger = get_task_logger(__name__)


# Global cache object
def get_cache_db():
    logger.debug("Initiating cache object")
    return CacheMDB(celery.conf.get('MONGO_URI', DEFAULT_MONGODB_URI),
                    celery.conf.get('MONGO_DBNAME', DEFAULT_MONGODB_NAME),
                    'eduid_cache_mm', ttl=10, expiration_freq=5)


_cache = get_cache_db()


class MessageRelay(Task):
    """
    Singleton that stores reusable objects.
    """
    abstract = True
    _sms = None 
    _message = None
    _recipient = None

    @property
    def cache(self):
        global _cache
        if _cache is None:
            _cache = get_cache_db()
        return _cache

    @property
    def sms(self):
        if self._sms is None:
            self._sms = SMSClient(self.app.conf.get("SMS_ACC"), self.app.conf.get("SMS_PASSWORD"))
            self._sender = self.app.conf.get("SMS_SENDER")
        return self._sms

    @property
    def message(self):
        if self._message is None:
            c = self.app.conf
            self._message = Message(cert=c.get("MM_CERT_FILE"), key_file=c.get("MM_KEY_FILE"),
                                    sender_org_nr=c.get("MM_SENDER_ORG_NR"), sender_org_name=c.get("MM_SENDER_ORG_NAME"),
                                    support_text=c.get("MM_SUPPORT_TEXT"), verify=False, serializable=True)
        return self._message

    @property
    def recipient(self):
        if self._recipient is None:
            c = self.app.conf
            self._recipient = Recipient(cert=c.get("MM_CERT_FILE"), key_file=c.get("MM_KEY_FILE"), verify=False,
                                        serializable=True)
        return self._recipient

    def is_reachable(self, social_sec_nr):
        """
        Check if recipient has a reachable gov mailbox.

        @param social_sec_nr: Recipients social security number
        @return: Recipient status and service mailbox url
        """
        print self.app.conf
        result = self.cache.get_cache_item(social_sec_nr)
        if result is None:
            result = self.recipient.is_reachable(self.app.conf.get("MM_SENDER_ORG_NR"), social_sec_nr)[0]
            # Only cache accepted recipients
            if result['SenderAccepted']:
                self.cache.add_cache_item(social_sec_nr, result)

        return result['SenderAccepted']


@celery.task(ignore_results=True, base=MessageRelay)
def send_sms(msg, to):
    self = send_sms
    self.sms.send(msg, self._sender, to, prio=2)

@celery.task(base=MessageRelay)
def is_reachable(social_sec_nr):
    """
    Check if the user is registered with Swedish government mailbox service.

    @param social_sec_nr: User social security number
    @type social_sec_nr: int
    @return: Return True if the user is reachable, otherwise False
    """
    self = is_reachable
    return self.is_reachable(social_sec_nr)

@celery.task(base=MessageRelay)
def send_secure_message():
    raise NotImplementedError

@celery.task(base=MessageRelay)
def get_secure_message_object():
    raise NotImplementedError

@celery.task(base=MessageRelay)
def send_message(message_type, message_dict, recipient, template, language):
    """
    @param message_type: Message notification type (sms or mm)
    @type message_type: str (possible values 'sms' and 'mm')
    @param message_dict: A dict of key value pairs used in the template of choice
    @type message_dict: dict
    @param recipient: Recipient phone number or social security number (depends on the choice of message_type)
    @type recipient: str
    @param template: Name of the message template to use
    @type template: str
    @param language: List of preferred languages for the template. The list is processed in order and the first
    template matching a language will be used.
    @type language: List of languages in the form (sv_SE, en_US)
    """
    self = send_message

    if message_type == 'sms':
        pass
    elif message_type == 'mm':
        pass
    elif message_type == 'email':
        pass

@periodic_task(run_every=timedelta(seconds=5))
def cache_expire_mm():
    global _cache
    logger.debug("Invoking expire_cache at %s" % datetime.fromtimestamp(time(), None))
    if _cache is None:
        _cache = get_cache_db()
    _cache.expire_cache_items()
