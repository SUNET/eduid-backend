# -*- encoding: utf-8 -*-
from __future__ import absolute_import

from celery import Task
from celery.utils.log import get_task_logger
from celery.task import periodic_task, task
from smscom import SMSClient
from pymmclient.message import Message
from pymmclient.recipient import Recipient
from pymmclient.service import Service
from eduid_msg.celery import celery
from eduid_msg.cache import CacheMDB
from eduid_msg.db import DEFAULT_MONGODB_URI, DEFAULT_MONGODB_NAME
from eduid_msg.utils import load_template
from eduid_msg.decorators import TransactionAudit
from eduid_msg.config import read_configuration
from time import time
from datetime import datetime, timedelta
from pynavet.postaladdress import PostalAddress


LOG = get_task_logger(__name__)
_CACHE = {}
MESSAGE_RATE_LIMIT = celery.conf.get("MESSAGE_RATE_LIMIT", None)


class MessageRelay(Task):
    """
    Singleton that stores reusable objects.
    """
    abstract = True
    _sms = None
    _message = None
    _recipient = None
    _navet = None
    _config = read_configuration()

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
                                        sender_org_nr=conf.get("MM_SENDER_ORG_NR"),
                                        verify=False,
                                        serializable=True)
        return self._recipient

    @property
    def navet(self):
        if self._navet is None:
            conf = self.app.conf
            self._navet = PostalAddress(cert=conf.get("MM_CERT_FILE"),
                                        key_file=conf.get("MM_KEY_FILE"),
                                        order_id=conf.get("NAVET_ORDER_ID"),
                                        verify=False)
        return self._navet

    def cache(self, cache_name, ttl=7200):
        global _CACHE
        if not cache_name in _CACHE:
            _CACHE[cache_name] = CacheMDB(self.app.conf.get('MONGO_URI', DEFAULT_MONGODB_URI),
                                          self.app.conf.get('MONGO_DBNAME', DEFAULT_MONGODB_NAME),
                                          cache_name, ttl=ttl, expiration_freq=120)
        return _CACHE[cache_name]

    def is_reachable(self, identity_number):
        result = self.get_is_reachable(identity_number)
        # Ensure the recipient has a secure account and accept us as sender
        if result['AccountStatus']['Type'] == 'Secure' and result['SenderAccepted']:
            return True
        return False

    @TransactionAudit(DEFAULT_MONGODB_URI)
    def get_is_reachable(self, identity_number):
        """
        Check if the user is registered with Swedish government mailbox service.

        @param identity_number: User social security number
        @type identity_number: int
        @return: Return True if the user is reachable, otherwise False
        """
        result = self.cache('recipient_cache', 7200).get_cache_item(identity_number)
        if result is None:
            result = self.recipient.is_reachable(identity_number)[0]
            # Only cache secure recipients if we are an accepted sender
            if result['AccountStatus']['Type'] == 'Secure' and result['SenderAccepted']:
                self.cache('recipient_cache').add_cache_item(identity_number, result)
        return result

    @TransactionAudit(DEFAULT_MONGODB_URI)
    def send_message(self, message_type, message_dict, recipient, template, language, subject=None):
        """
        @param message_type: Message notification type (sms or mm)
        @type message_type: str (possible values 'sms' and 'mm')
        @param message_dict: A dict of key value pairs used in the template of choice
        @type message_dict: dict
        @param recipient: Recipient mobile phone number or social security number (depends on the choice of
        message_type)
        @type recipient: str
        @param template: Name of the message template to use
        @type template: str
        @param language: List of preferred languages for the template. The list is processed in order and the first
        template matching a language will be used.
        @type language: List of languages in the form (sv_SE, en_US)
        @param subject: (Optional) Subject used in my messages service or email deliveries
        @type subject: str
        @return: For type 'sms' a message id is returned if successful, if unsucessful an error message is returned.
        For type 'mm' a message id is returned if successful, the message id can be used to verify if that the message
        has been delivered to the users mailbox service by calling check_distribution_status(message_id),
        if unsuccessful an error message is returned.
        """
        conf = self.app.conf
        msg = load_template(conf.get("TEMPLATE_DIR", None), template, message_dict, language).encode('utf-8')
        if not msg:
            raise RuntimeError("template not found")

        # Only log the message if devel_mode is enabled
        if conf.get("DEVEL_MODE") == 'true':
            LOG.debug("\nType: %s\nRecipient: %s\nLang: %s\nSubject: %s\nMessage:\n %s" % (message_type, recipient,
                                                                                           language, subject, msg))
            return True

        if message_type == 'sms':
            LOG.debug("Sending SMS to '%s' using template '%s' and language '%s" % (recipient, template, language))
            status = self.sms.send(msg, self._sender, recipient, prio=2)
        elif message_type == 'mm':
            reachable = self.get_is_reachable(recipient)
            if reachable['AccountStatus']['Type'] is not 'Secure' and not reachable['SenderAccepted']:
                if reachable['AccountStatus']['Type'] == 'Not' or \
                   reachable['AccountStatus']['Type'] == 'Anonymous':
                    reason = reachable['AccountStatus']['Type']
                elif not reachable['SenderAccepted']:
                    reason = "SENDER_NOT"

                LOG.debug("User not reachable - reason: %s", reason)
                return reason

            if subject is None:
                subject = conf.get("MM_DEFAULT_SUBJECT")

            service_address = reachable['AccountStatus']['ServiceSupplier']['ServiceAdress']
            secure_message = self.message.create_secure_message(subject, msg, 'text/plain',
                                                                language.translate(None, '_'))
            signed_delivery = self.message.create_signed_delivery([recipient], secure_message)
            service = Service(cert=conf.get("MM_CERT_FILE"),
                              key_file=conf.get("MM_KEY_FILE"),
                              verify=False,
                              ws_endpoint=service_address,
                              serializable=True)
            status = service.deliver_secure_message(signed_delivery)

        return status

    @TransactionAudit(DEFAULT_MONGODB_URI)
    def get_postal_address(self, identity_number):
        """
        Fetch name and postal address from NAVET

        @param identity_number: Swedish national identity number
        @type identity_number: str
        @return: dict containing name and postal address
        """
        result = self.cache('navet_cache').get_cache_item(identity_number)
        if result is None:
            result = self.navet.get_name_and_official_address(identity_number)
            if result is not None:
                self.cache('navet_cache').add_cache_item(identity_number, result)

        return result


@task(ignore_results=True, base=MessageRelay)
def send_sms(msg, to):
    self = send_sms
    self.sms.send(msg, self._sender, to, prio=2)

@task(base=MessageRelay)
def is_reachable(identity_number):
    """
    Check if the user is registered with Swedish government mailbox service.

    @param identity_number: Swedish national identity number
    @type identity_number: str
    @return: True if the user is reachable, otherwise False
    """
    self = is_reachable
    return self.is_reachable(identity_number)

@task(base=MessageRelay)
def get_is_reachable(identity_number):
    """
    Get user reachable status from Swedish government mailbox service.

    @param identity_number: Swedish national identity number
    @type identity_number: str
    @return: Dict containing information about the user status
    """
    self = get_is_reachable
    return self.get_is_reachable(identity_number)

@task(base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT, max_retries=10)
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
    try:
        return self.send_message(message_type, message_dict, recipient, template, language, subject)
    except Exception, e:
        # Increase countdown every time it fails (to a maximum of 1 day)
        countdown = 600 * send_message.request.retries ** 2
        retry_countdown = countdown if countdown <= 86400 else 86400
        LOG.debug("send_message task retrying in %d seconds, error %s", retry_countdown, e.message)
        send_message.retry(exc=e, countdown=retry_countdown)

@task(base=MessageRelay)
def get_postal_address(identity_number):
    """
    Retrieve name and postal address from the Swedish population register using a Swedish national
    identity number.

    @param identity_number: Swedish national identity number
    @type identity_number: str
    @return: Ordered dict
    """
    self = get_postal_address
    return self.get_postal_address(identity_number)

@periodic_task(run_every=timedelta(minutes=5))
def cache_expire():
    """
    Periodic function executed every 5 minutes to expire cached items.
    """
    global _CACHE
    for cache in _CACHE.iterkeys():
        LOG.debug("Invoking expire_cache at %s for %s" % (datetime.fromtimestamp(time(), None), cache))
        _CACHE[cache].expire_cache_items()
