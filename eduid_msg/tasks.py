# -*- encoding: utf-8 -*-
from __future__ import absolute_import

from celery import Task
from celery.utils.log import get_task_logger
from celery.task import periodic_task, task
from eduid_msg.celery import celery
from eduid_msg.cache import CacheMDB
from eduid_msg.utils import load_template, navet_get_name_and_official_address, navet_get_relations
from eduid_msg.decorators import TransactionAudit
from eduid_msg.config import read_configuration
from time import time
from datetime import datetime, timedelta
from hammock import Hammock
import json


DEFAULT_MONGODB_HOST = 'localhost'
DEFAULT_MONGODB_PORT = 27017
DEFAULT_MONGODB_NAME = 'eduid_msg'
DEFAULT_MONGODB_URI = 'mongodb://%s:%d/%s' % (DEFAULT_MONGODB_HOST,
                                              DEFAULT_MONGODB_PORT,
                                              DEFAULT_MONGODB_NAME)

TRANSACTION_AUDIT_DB = 'eduid_msg'
TRANSACTION_AUDIT_COLLECTION = 'transaction_audit'

DEFAULT_MM_API_HOST = 'eduid-mm-service.docker'
DEFAULT_MM_API_PORT = 8080
DEFAULT_MM_API_URI = 'http://{0}:{1}'.format(DEFAULT_MM_API_HOST,
                                             DEFAULT_MM_API_PORT)

DEFAULT_NAVET_API_HOST = 'eduid-navet-service.docker'
DEFAULT_NAVET_API_PORT = 8080
DEFAULT_NAVET_API_URI = 'http://{0}:{1}'.format(DEFAULT_NAVET_API_HOST,
                                                DEFAULT_NAVET_API_PORT)


LOG = get_task_logger(__name__)
_CACHE = {}
MESSAGE_RATE_LIMIT = celery.conf.get("MESSAGE_RATE_LIMIT", None)


class MessageRelay(Task):
    """
    Singleton that stores reusable objects.
    """
    abstract = True
    _sms = None
    _mm_api = None
    _navet = None
    _config = read_configuration()
    MONGODB_URI = _config['MONGO_URI'] if 'MONGO_URI' in _config else DEFAULT_MONGODB_URI
    MM_API_URI = _config['MM_API_URI'] if 'MM_API_URI' in _config else DEFAULT_MM_API_URI
    NAVET_API_URI = _config['NAVET_API_URI'] if 'NAVET_API_URI' in _config else DEFAULT_NAVET_API_URI
    if 'AUDIT' in _config and _config['AUDIT'] == 'true':
        TransactionAudit.enable()

    @property
    def sms(self):
        if self._sms is None:
            from smscom import SMSClient

            self._sms = SMSClient(self.app.conf.get("SMS_ACC"), self.app.conf.get("SMS_KEY"))
            self._sender = self.app.conf.get("SMS_SENDER")
        return self._sms

    @property
    def mm_api(self):
        if self._mm_api is None:
            verify_ssl = True
            auth = None
            if self.app.conf.get("MM_API_VERIFY_SSL", None) == 'false':
                verify_ssl = False
            if self.app.conf.get("MM_API_USER", None) and self.app.conf.get("MM_API_PW"):
                auth = (self.app.conf.get("MM_API_USER"), self.app.conf.get("MM_API_PW"))
            self._mm_api = Hammock(self.MM_API_URI, auth=auth, verify=verify_ssl)
        return self._mm_api

    @property
    def navet(self):
        if self._navet_api is None:
            verify_ssl = True
            auth = None
            if self.app.conf.get("NAVET_API_VERIFY_SSL", None) == 'false':
                verify_ssl = False
            if self.app.conf.get("NAVET_API_USER", None) and self.app.conf.get("NAVET_API_PW"):
                auth = (self.app.conf.get("NAVET_API_USER"), self.app.conf.get("NAVET_API_PW"))
            self._navet = Hammock(self.NAVET_API_URI, auth=auth, verify=verify_ssl)
        return self._navet

    def cache(self, cache_name, ttl=7200):
        global _CACHE
        if not cache_name in _CACHE:
            _CACHE[cache_name] = CacheMDB(self.app.conf.get('MONGO_URI', DEFAULT_MONGODB_URI),
                                          self.app.conf.get('MONGO_DBNAME', DEFAULT_MONGODB_NAME),
                                          cache_name, ttl=ttl, expiration_freq=120)
        return _CACHE[cache_name]

    def is_reachable(self, identity_number, mailbox_url=False):
        """
        Check if the user is registered with Swedish government mailbox service.

        @param identity_number: User social security number
        @type identity_number: str
        @param mailbox_url: (optional) Return mailbox URL instead of true if the user exist and accept messages from
        the sender.
        @type mailbox_url: bool
        @return: True if the user is reachable, False if the user is not registered with the government mailbox service.
        'Anonymous' if the user is registered but has not confirmed their identity with the government mailbox service.
        'Sender_not' if the sender (you) is blocked by the recipient.
        """
        result = self.cache('recipient_cache', 7200).get_cache_item(identity_number)
        retval = False

        if result is None:
            result = self._get_is_reachable(identity_number)
            if result['AccountStatus']['Type'] == 'Secure' and result['SenderAccepted']:
                self.cache('recipient_cache').add_cache_item(identity_number, result)

        if retval is False:
            if result['AccountStatus']['Type'] == 'Secure':
                if result['SenderAccepted']:
                    retval = True
                else:
                    retval = 'Sender_not'
            elif result['AccountStatus']['Type'] == 'Not':
                pass
            elif result['AccountStatus']['Type'] == 'Anonymous':
                retval = 'Anonymous'

        if mailbox_url is True and retval is True:
            return result['AccountStatus']['ServiceSupplier']['ServiceAddress']

        return retval

    @TransactionAudit(MONGODB_URI)
    def _get_is_reachable(self, identity_number):
        # Users always reachable in devel mode
        conf = self.app.conf
        if conf.get("DEVEL_MODE") == 'true':
            LOG.debug("Faking that NIN %(identity_number) is reachable".format(identity_number=identity_number))
            return {'AccountStatus': {'Type': 'Secure', 'ServiceSupplier': 'devel_mode'}, 'SenderAccepted': 'devel_mode'}
        data = json.dumps({'identity_number': identity_number})
        response = self.mm_api.user.reachable.POST(data=data)
        if response.status_code == 200:
            return response.json()
        error = 'MM API is_reachable response: {0} {1}'.format(response.status_code,
                                                               response.json().get('message', 'No message'))
        LOG.error(error)
        raise RuntimeError(error)

    @TransactionAudit(MONGODB_URI)
    def send_message(self, message_type, reference, message_dict, recipient, template, language, subject=None):
        """
        @param message_type: Message notification type (sms or mm)
        @type message_type: str (possible values 'sms' and 'mm')
        @param reference: Unique reference id
        @type reference: str
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
        @return: For type 'sms' a message id is returned if successful, if unsuccessful an error message is returned.
        For type 'mm' a message id is returned if successful, the message id can be used to verify if that the message
        has been delivered to the users mailbox service by calling check_distribution_status(message_id),
        if unsuccessful an error message is returned.
        """
        conf = self.app.conf

        msg = load_template(conf.get("TEMPLATE_DIR", None), template, message_dict, language)
        if not msg:
            raise RuntimeError("template not found")
        msg = msg.encode('utf-8')

        # Only log the message if devel_mode is enabled
        if conf.get("DEVEL_MODE") == 'true':
            LOG.debug("\nType: %s\nReference: %s\nRecipient: %s\nLang: %s\nSubject: %s\nMessage:\n %s" % (message_type,
                                                                                                          reference,
                                                                                                          recipient,
                                                                                                          language,
                                                                                                          subject,
                                                                                                          msg))
            return 'devel_mode'

        if message_type == 'sms':
            LOG.debug("Sending SMS to '%s' using template '%s' and language '%s" % (recipient, template, language))
            status = self.sms.send(msg, self._sender, recipient, prio=2)
        elif message_type == 'mm':
            LOG.debug("Sending MM to '%s' using language '%s'" % (recipient, language))
            reachable = self.is_reachable(recipient)

            if reachable is not True:
                LOG.debug("User not reachable - reason: %s" % (reachable))
                return reachable

            if subject is None:
                subject = conf.get("MM_DEFAULT_SUBJECT")

            status = self._send_mm_message(recipient, subject, 'text/html', language.replace('_', ''), msg)

        return status

    def _send_mm_message(self, recipient, subject, content_type, language, message):
        data = json.dumps({
            'recipient': recipient,
            'subject': subject,
            'content_type': content_type,
            'language': language,
            'message': message
        })
        response = self.mm_api.message.send.POST(data=data)
        LOG.debug("_send_mm_message response for recipient '%s': '%r'" % (recipient, response))
        if response.status_code == 200:
            return response.json()['transaction_id']
        error = 'MM API send message response: {0} {1}'.format(response.status_code,
                                                               response.json().get('message', 'No message'))
        LOG.error(error)
        raise RuntimeError(error)

    def get_postal_address(self, identity_number):
        """
        Fetch name and postal address from NAVET

        @param identity_number: Swedish national identity number
        @type identity_number: str
        @return: dict containing name and postal address
        """
        # Only log the message if devel_mode is enabled
        conf = self.app.conf
        if conf.get("DEVEL_MODE") == 'true':
            return self.get_devel_postal_address()

        data = self._get_navet_data(identity_number)
        # Filter name and address from the Navet lookup results
        return navet_get_name_and_official_address(data)

    def get_devel_postal_address(self):
        """
        Return a OrderedDict just as we would get from navet.
        """
        from collections import OrderedDict
        result = OrderedDict([
            (u'Name', OrderedDict([
                (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                (u'SurName', u'Testsson')])),
            (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                              (u'PostalCode', u'12345'),
                                              (u'City', u'LANDET')]))
        ])
        return result

    def get_relations(self, identity_number):
        """
        Fetch information about someones relatives from NAVET

        @param identity_number: Swedish national identity number
        @type identity_number: str
        @return: dict containing name and postal address
        """
        # Only log the message if devel_mode is enabled
        conf = self.app.conf
        if conf.get("DEVEL_MODE") == 'true':
            return self.get_devel_relations()

        data = self._get_navet_data(identity_number)
        # Filter relations from the Navet lookup results
        return navet_get_relations(data)

    def get_devel_relations(self):
        """
        Return a OrderedDict just as we would get from navet.
        """
        from collections import OrderedDict
        result = \
            OrderedDict([(u'Relations', {u'Relation':
                         [{u'RelationType': u'VF', u'RelationId': {u'NationalIdentityNumber': u'200202025678'},
                           u'RelationStartDate': u'20020202'},
                          {u'RelationType': u'VF', u'RelationId': {u'NationalIdentityNumber': u'200101014567'},
                           u'RelationStartDate': u'20010101'},
                          {u'RelationType': u'FA', u'RelationId': {u'NationalIdentityNumber': u'194004048989'}},
                          {u'RelationType': u'MO', u'RelationId': {u'NationalIdentityNumber': u'195010106543'}},
                          {u'RelationType': u'B', u'RelationId': {u'NationalIdentityNumber': u'200202025678'}},
                          {u'RelationType': u'B', u'RelationId': {u'NationalIdentityNumber': u'200101014567'}},
                          {u'RelationType': u'M', u'RelationId': {u'NationalIdentityNumber': u'197512125432'}}]}
                          )])
        return result

    @TransactionAudit(MONGODB_URI)
    def _get_navet_data(self, identity_number):
        """
        Fetch all data about a NIN from Navet.

        @param identity_number: Swedish national identity number
        @type identity_number: str
        @return: Loaded JSON
        @rtype: dict
        """
        json_data = self.cache('navet_cache').get_cache_item(identity_number)
        if json_data is None:
            post_data = json.dumps({'identity_number': identity_number})
            response = self._navet.personpost.navetnotification.POST(data=post_data)
            if response.status_code == 200:
                json_data = response.json()
                if json_data.get('PopulationItems', None):
                    self.cache('navet_cache').add_cache_item(identity_number, json_data)
        return json_data

    def set_audit_log_postal_address(self, audit_reference):
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


@task(base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT, max_retries=10)
def send_message(message_type, reference, message_dict, recipient, template, language, subject=None):
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
        return self.send_message(message_type, reference, message_dict, recipient, template, language, subject)
    except Exception, e:
        # Increase countdown every time it fails (to a maximum of 1 day)
        countdown = 600 * send_message.request.retries ** 2
        retry_countdown = min(countdown, 86400)
        LOG.error('send_message task error', exc_info=True)
        LOG.debug("send_message task retrying in %d seconds, error %s", retry_countdown, e.message)
        send_message.retry(exc=e, countdown=retry_countdown)


@task(base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT, max_retries=10)
def get_postal_address(identity_number):
    """
    Retrieve name and postal address from the Swedish population register using a Swedish national
    identity number.

    @param identity_number: Swedish national identity number
    @type identity_number: str
    @return: Ordered dict
    """
    # Decorator task base=MessageRelay makes this an instance of MessageRelay().
    # This funny looking assignment of self to this function supposedly lets us
    # access other attributes etc. on the MessageRelay instance.
    # http://docs.celeryproject.org/en/latest/userguide/tasks.html#instantiation
    self = get_postal_address
    try:
        return self.get_postal_address(identity_number)
    except Exception, e:
        # Increase countdown every time it fails (to a maximum of 1 day)
        countdown = 600 * send_message.request.retries ** 2
        retry_countdown = min(countdown, 86400)
        LOG.error('get_postal_address task error', exc_info=True)
        LOG.debug("get_postal_address task retrying in %d seconds, error %s", retry_countdown, e.message)
        get_postal_address.retry(exc=e, countdown=retry_countdown)


@task(base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT, max_retries=3)
def get_relations_to(identity_number, relative_nin):
    """
    Get the relative status between identity_number and relative_nin.

    What is returned is a list of Navet codes. Known codes:
      M = spouse (make/maka)
      B = child (barn)
      FA = father
      MO = mother
      VF = some kind of legal guardian status. Childs typically have ['B', 'VF'] it seems.

    @param identity_number: Swedish national identity number
    @type identity_number: str
    @param relative_nin: Swedish national identity number
    @type relative_nin: str
    @return: [str | unicode]
    """
    # Decorator task base=MessageRelay makes this an instance of MessageRelay().
    # This funny looking assignment of self to this function supposedly lets us
    # access other attributes etc. on the MessageRelay instance.
    # http://docs.celeryproject.org/en/latest/userguide/tasks.html#instantiation
    self = get_relations_to
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
        LOG.debug("Looking for relations between {!r} and {!r} in:{!s}".format(identity_number,
                                                                               relative_nin,
                                                                               pprint.pformat(relations)))
        for d in relations['Relations']['Relation']:
            if d.get('RelationId', {}).get("NationalIdentityNumber") == relative_nin:
                if 'RelationType' in d:
                    result.append(d['RelationType'])
        return result
    except Exception, e:
        # Increase countdown every time it fails (to a maximum of 1 day)
        countdown = 600 * send_message.request.retries ** 2
        retry_countdown = min(countdown, 86400)
        LOG.error('get_relations_to task error', exc_info=True)
        LOG.debug("get_relations_to task retrying in %d seconds, error %s", retry_countdown, e.message)
        get_relations_to.retry(exc=e, countdown=retry_countdown)


@task(base=MessageRelay, rate_limit=MESSAGE_RATE_LIMIT, max_retries=10)
def set_audit_log_postal_address(audit_reference):
    """
    Looks in the transaction audit collection for the audit reference and make a postal address lookup and adds the
    result to the transaction audit document.
    """
    # Decorator task base=MessageRelay makes this an instance of MessageRelay().
    # This funny looking assignment of self to this function supposedly lets us
    # access other attributes etc. on the MessageRelay instance.
    # http://docs.celeryproject.org/en/latest/userguide/tasks.html#instantiation
    self = set_audit_log_postal_address
    try:
        return self.set_audit_log_postal_address(audit_reference)
    except Exception, e:
        # Increase countdown every time it fails (to a maximum of 1 day)
        countdown = 600 * send_message.request.retries ** 2
        retry_countdown = min(countdown, 86400)
        LOG.error('set_audit_log_postal_address task error', exc_info=True)
        LOG.debug("set_audit_log_postal_address task retrying in %d seconds, error %s", retry_countdown, e.message)
        set_audit_log_postal_address.retry(exc=e, countdown=retry_countdown)


@periodic_task(run_every=timedelta(minutes=5))
def cache_expire():
    """
    Periodic function executed every 5 minutes to expire cached items.
    """
    global _CACHE
    for cache in _CACHE.iterkeys():
        LOG.debug("Invoking expire_cache at %s for %s" % (datetime.fromtimestamp(time(), None), cache))
        _CACHE[cache].expire_cache_items()
