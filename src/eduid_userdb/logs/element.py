# -*- coding: utf-8 -*-
#
# Helper functions to log proofing events.
#

from eduid_userdb.element import Element
import logging

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class LogElement(Element):

    def __init__(self, created_by):
        """
        :param created_by: Application creating the log element

        :type created_by: str

        :return: LogElement object
        :rtype: LogElement
        """
        self._required_keys = ['created_by', 'created_ts']
        super(LogElement, self).__init__(data={'created_by': created_by, 'created_ts': True})

    def validate(self):
        # Check that all keys are accounted for and that none of them evaluates to false
        if not all(self._data.get(key) for key in self._required_keys):
            logger.error('Not enough data to log proofing event: {!r}. Required keys: {!r}'.format(
                self._data, list(set(self._required_keys)-set(self._data.keys()))))
            return False
        return True


class ProofingLogElement(LogElement):

    def __init__(self, user, created_by, proofing_method, proofing_method_version):
        """
        :param user: User object
        :param created_by: Application creating the log element

        :type user: eduid_userdb.user.User
        :type created_by: str

        :return: ProofingLogElement object
        :rtype: ProofingLogElement
        """
        super(ProofingLogElement, self).__init__(created_by)
        self._required_keys.extend(['eduPersonPrincipalName', 'proofing_method', 'proofing_method_version'])
        self._data['eduPersonPrincipalName'] = user.eppn
        self._data['proofing_method'] = proofing_method
        self._data['proofing_method_version'] = proofing_method_version


class MailAddressProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'e-mail',
        'proofing_method_version': '20130527',
        'mail_address': 'mail_address'
    }
    """
    def __init__(self, user, created_by, mail_address):
        """
        :param user: User object
        :param created_by: Application creating the log element
        :param mail_address: e-mail address

        :type user: eduid_userdb.user.User
        :type created_by: str
        :type mail_address: str | unicode

        :return: MailAddressProofing object
        :rtype: MailAddressProofing
        """
        super(MailAddressProofing, self).__init__(user, created_by, proofing_method='e-mail',
                                                  proofing_method_version='20130527')
        self._required_keys.extend(['mail_address'])
        self._data['mail_address'] = mail_address


class PhoneNumberProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'sms',
        'proofing_method_version': '20130527',
        'phone_number': 'phone_number'
    }
    """
    def __init__(self, user, created_by, phone_number):
        """
        :param user: User object
        :param created_by: Application creating the log element
        :param phone_number: phone number

        :type user: eduid_userdb.user.User
        :type created_by: str
        :type phone_number: str | unicode

        :return: PhoneNumberProofing object
        :rtype: PhoneNumberProofing
        """
        super(PhoneNumberProofing, self).__init__(user, created_by, proofing_method='sms',
                                                  proofing_method_version='20130527')
        self._required_keys.extend(['phone_number'])
        self._data['phone_number'] = phone_number


class TeleAdressProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'TeleAdress',
        'proofing_method_version': '20140411',
        'reason': 'matched',
        'nin': national_identity_number,
        'mobile_number': mobile_number,
        'teleadress_response': {teleadress_response},
        'user_postal_address': {postal_address_from_navet}
    }
    """

    def __init__(self, user, created_by, reason, nin, mobile_number, user_postal_address):
        """
        :param user: user object
        :param created_by: Application creating the log element
        :param reason: Reason for mobile phone number match to user
        :param nin: National identity number
        :param mobile_number: Mobile phone number
        :param user_postal_address: Navet response for users official address

        :type user: eduid_userdb.User
        :type created_by: str
        :type reason: str
        :type nin: str
        :type mobile_number: str
        :type user_postal_address: dict

        :return: TeleAdressProofing object
        :rtype: TeleAdressProofing
        """
        super(TeleAdressProofing, self).__init__(user, created_by, proofing_method='TeleAdress',
                                                 proofing_method_version='20140411')
        self._required_keys.extend(['reason', 'nin', 'mobile_number', 'user_postal_address'])
        self._data['reason'] = reason
        self._data['nin'] = nin
        self._data['mobile_number'] = mobile_number
        self._data['user_postal_address'] = user_postal_address


class TeleAdressProofingRelation(TeleAdressProofing):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'TeleAdress',
        'reason': 'match_by_navet',
        'nin': national_identity_number,
        'mobile_number': mobile_number,
        'teleadress_response': {teleadress_response},
        'user_postal_address': {postal_address_from_navet}
        'mobile_number_registered_to': 'registered_national_identity_number',
        'registered_relation': 'registered_relation_to_user'
        'registered_postal_address': {postal_address_from_navet}
    }
    """
    def __init__(self, user, created_by, reason, nin, mobile_number, user_postal_address, mobile_number_registered_to,
                 registered_relation, registered_postal_address):
        """
        :param user: user object
        :param created_by: Application creating the log element
        :param reason: Reason for mobile phone number match to user
        :param nin: National identity number
        :param mobile_number: Mobile phone number
        :param user_postal_address: Navet response for users official address
        :param mobile_number_registered_to: NIN of registered user of mobile phone subscription
        :param registered_relation: Relation of mobile phone subscriber to User
        :param registered_postal_address: Navet response for mobile phone subscriber

        :type user: User
        :type created_by: str
        :type reason: str
        :type nin: str
        :type mobile_number: str
        :type user_postal_address: dict
        :type mobile_number_registered_to: str
        :type registered_relation: str
        :type registered_postal_address:  dict

        :return: TeleAdressProofingRelation object
        :rtype: TeleAdressProofingRelation
        """
        super(TeleAdressProofingRelation, self).__init__(user, created_by, reason, nin, mobile_number,
                                                         user_postal_address)
        self._required_keys.extend(['mobile_number_registered_to', 'registered_relation', 'registered_postal_address'])
        self._data['mobile_number_registered_to'] = mobile_number_registered_to
        self._data['registered_relation'] = registered_relation
        self._data['registered_postal_address'] = registered_postal_address


class LetterProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'letter',
        'proofing_method_version': '20160108',
        'nin': 'national_identity_number',
        'letter_sent_to': {address_letter_was_sent_to},
        'transaction_id': 'transaction_id',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    def __init__(self, user, created_by, nin, letter_sent_to, transaction_id, user_postal_address):
        """
        :param user: user object
        :param created_by: Application creating the log element
        :param nin: National identity number
        :param letter_sent_to: Name and address the letter was sent to
        :param transaction_id: Letter service transaction id
        :param user_postal_address: Navet response for users official address

        :type user: User
        :type created_by: str
        :type nin: str
        :type letter_sent_to: dict
        :type transaction_id: str
        :type user_postal_address: dict

        :return: LetterProofing object
        :rtype: LetterProofing
        """
        super(LetterProofing, self).__init__(user, created_by, proofing_method='letter',
                                             proofing_method_version='20160108')
        self._required_keys.extend(['proofing_method', 'nin', 'letter_sent_to', 'transaction_id',
                                    'user_postal_address'])
        self._data['nin'] = nin
        self._data['letter_sent_to'] = letter_sent_to
        self._data['transaction_id'] = transaction_id
        self._data['user_postal_address'] = user_postal_address
