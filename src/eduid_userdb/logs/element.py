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
        """
        self._required_keys = ['created_by', 'created_ts']
        super(LogElement, self).__init__(data={'created_by': created_by, 'created_ts': True})

    def validate(self):
        # Check that all keys are accounted for and that none of them evaluates to false
        if not all(self._data.get(key) for key in self._required_keys):
            logger.error('Not enough data to log proofing event: {!r}. Required keys: {!r}'.format(
                self._data, list(set(self._required_keys)-set(d.keys()))))
            return False
        return True


class ProofingLogElement(LogElement):

    def __init__(self, user, created_by):
        """
        :param user: User object
        :type user: eduid_userdb.user.User
        :param created_by: Application creating the log element
        :type created_by: str
        """
        super(ProofingLogElement, self).__init__(created_by)
        self._required_keys.extend(['eduPersonPrincipalName'])
        self._data['eduPersonPrincipalName'] = user.eppn


class MailAddressProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'mail_address': 'mail_address'
    }
    """
    def __init__(self, user, created_by, mail_address):
        """
        :param user: User object
        :type user: eduid_userdb.user.User
        :param created_by: Application creating the log element
        :type created_by: str
        :param mail_address: e-mail address
        :type mail_address: str | unicode
        """
        super(MailAddressProofing, self).__init__(user, created_by)
        self._required_keys.extend(['mail_address'])
        self._data['mail_address'] = mail_address


class PhoneNumberProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'phone_number': 'phone_number'
    }
    """
    def __init__(self, user, created_by, phone_number):
        """
        :param user: User object
        :type user: eduid_userdb.user.User
        :param created_by: Application creating the log element
        :type created_by: str
        :param phone_number: phone number
        :type phone_number: str | unicode
        """
        super(PhoneNumberProofing, self).__init__(user, created_by)
        self._required_keys.extend(['phone_number'])
        self._data['phone_number'] = phone_number


class TeleAdressProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
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
        :type user: eduid_userdb.User
        :param created_by: Application creating the log element
        :type created_by: str
        :param reason: Reason for mobile phone number match to user
        :type reason: str
        :param nin: National identity number
        :type nin: str
        :param mobile_number: Mobile phone number
        :type mobile_number: str
        :param user_postal_address: Navet response for users official address
        :type user_postal_address: dict
        :return: TeleAdressProofing object
        :rtype: TeleAdressProofing
        """
        super(TeleAdressProofing, self).__init__(user, created_by)
        self._required_keys.extend(['proofing_method', 'reason', 'nin', 'mobile_number', 'user_postal_address'])
        self._data['proofing_method'] = 'TeleAdress'
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
        :type user: User
        :param created_by: Application creating the log element
        :type created_by: str
        :param reason: Reason for mobile phone number match to user
        :type reason: str
        :param nin: National identity number
        :type nin: str
        :param mobile_number: Mobile phone number
        :type mobile_number: str
        :param user_postal_address: Navet response for users official address
        :type user_postal_address: dict
        :param mobile_number_registered_to: NIN of registered user of mobile phone subscription
        :type mobile_number_registered_to: str
        :param registered_relation: Relation of mobile phone subscriber to User
        :type registered_relation: str
        :param registered_postal_address: Navet response for mobile phone subscriber
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
        'nin': 'national_identity_number',
        'letter_sent_to': {address_letter_was_sent_to},
        'transaction_id': 'transaction_id',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    def __init__(self, user, created_by, nin, letter_sent_to, transaction_id, user_postal_address):
        """
        :param user: user object
        :type user: User
        :param created_by: Application creating the log element
        :type created_by: str
        :param nin: National identity number
        :type nin: str
        :param letter_sent_to: Name and address the letter was sent to
        :type letter_sent_to: dict
        :param transaction_id: Letter service transaction id
        :type transaction_id: str
        :param user_postal_address: Navet response for users official address
        :type user_postal_address: dict
        :return: LetterProofing object
        :rtype: LetterProofing
        """
        super(LetterProofing, self).__init__(user, created_by)
        self._required_keys.extend(['proofing_method', 'nin', 'letter_sent_to', 'transaction_id',
                                    'user_postal_address'])
        self._data['proofing_method'] = 'eduid-idproofing-letter'
        self._data['nin'] = nin
        self._data['letter_sent_to'] = letter_sent_to
        self._data['transaction_id'] = transaction_id
        self._data['user_postal_address'] = user_postal_address
