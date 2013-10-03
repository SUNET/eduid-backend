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
from eduid_msg.utils import load_template
from time import time, sleep
from datetime import datetime, timedelta

LOG = get_task_logger(__name__)

usleep = lambda x: sleep(x/1000000.0)

# Cache collection name
CACHE_REACHABLE = 'recipient_cache'

_CACHE = None


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
        global _CACHE
        if _CACHE is None:
            _CACHE = init_cache()
        return _CACHE

    @property
    def sms(self):
        if self._sms is None:
            self._sms = SMSClient(self.app.conf.get("SMS_ACC"), self.app.conf.get("SMS_KEY"))
            self._sender = self.app.conf.get("SMS_SENDER")
        return self._sms

    @property
    def message(self):
        if self._message is None:
            conf = self.app.conf
            self._message = Message(cert=conf.get("MM_CERT_FILE"),
                                    key_file=conf.get("MM_KEY_FILE"),
                                    sender_org_nr=conf.get("MM_SENDER_ORG_NR"),
                                    sender_org_name=conf.get("MM_SENDER_ORG_NAME"),
                                    support_text=conf.get("MM_SUPPORT_TEXT"),
                                    verify=False, serializable=True)
        return self._message

    @property
    def recipient(self):
        if self._recipient is None:
            conf = self.app.conf
            self._recipient = Recipient(cert=conf.get("MM_CERT_FILE"),
                                        key_file=conf.get("MM_KEY_FILE"),
                                        verify=False,
                                        serializable=True)
        return self._recipient

    def is_reachable(self, social_sec_nr):
        """
        Check if the user is registered with Swedish government mailbox service.

        @param social_sec_nr: User social security number
        @type social_sec_nr: int
        @return: Return True if the user is reachable, otherwise False
        """
        result = self.cache.get_cache_item(social_sec_nr)
        if result is None:
            result = self.recipient.is_reachable(self.app.conf.get("MM_SENDER_ORG_NR"), social_sec_nr)[0]
            # Only cache accepted recipients
            if result['SenderAccepted']:
                self.cache.add_cache_item(social_sec_nr, result)

        return result['SenderAccepted']

    def send_message(self, message_type, message_dict, recipient, template, language, subject=None):
        """
        @param message_type: Message notification type (sms or mm)
        @type message_type: str (possible values 'sms' and 'mm')
        @param message_dict: A dict of key value pairs used in the template of choice
        @type message_dict: dict
        @param recipient: Recipient mobile phone number or social security number (depends on the choice of message_type)
        @type recipient: str
        @param template: Name of the message template to use
        @type template: str
        @param language: List of preferred languages for the template. The list is processed in order and the first
        template matching a language will be used.
        @type language: List of languages in the form (sv_SE, en_US)
        @param subject: (Optional) Subject used in my messages service or email deliveries
        @type subject: str
        """
        tmpl = load_template(self.app.conf.get("TEMPLATE_DIR", None), template, language)
        if not tmpl:
            raise RuntimeError("template not found")
        msg = tmpl.format(**message_dict)

        if message_type == 'sms':
            status = self.sms.send(msg, self._sender, recipient, prio=2)
        elif message_type == 'mm':
            if not self.is_reachable(recipient):
                LOG.debug("User not reachable")
                return False
            if subject is None:
                subject = self.app.conf.get("MM_DEFAULT_SUBJECT")

            secure_message = self.message.create_secure_message(subject, msg, 'text/plain', language.translate(None, '_'))
            result = self.message.send_secure_message([recipient], secure_message)

            #TODO: Fix proper queue handling for check_distribution_status()
            count = 0
            while count <= 10:
                if count > 0:
                    usleep(100)
                status = self.message.check_distribution_status(self.app.conf.get("MM_SENDER_ORG_NR"), result)
                if status[0]['DeliveryStatus'] == 'Delivered':
                    break
                count += 1
            status = status[0]

        return status


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
def send_message(message_type, message_dict, recipient, template, language, subject=None):
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
    return self.send_message(message_type, message_dict, recipient, template, language, subject)

@periodic_task(run_every=timedelta(minutes=5))
def cache_expire_mm():
    """
    Periodic function executed every 5 minutes to expire cached items.
    """
    global _CACHE
    LOG.debug("Invoking expire_cache at %s" % datetime.fromtimestamp(time(), None))
    if _CACHE is None:
        _CACHE = init_cache()
    _CACHE.expire_cache_items()


def init_cache(ttl=7200, expiration_freq=120):
    """
    Initialize MongoDB cache object.
    """
    LOG.debug("Initiating cache object")
    global _CACHE, CACHE_REACHABLE
    return CacheMDB(celery.conf.get('MONGO_URI', DEFAULT_MONGODB_URI),
                    celery.conf.get('MONGO_DBNAME', DEFAULT_MONGODB_NAME),
                    celery.conf.get('CACHE_REACHABLE', CACHE_REACHABLE),
                    ttl=ttl, expiration_freq=expiration_freq)
