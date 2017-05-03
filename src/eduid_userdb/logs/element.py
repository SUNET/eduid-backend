# -*- coding: utf-8 -*-
#
# Helper functions to log proofing events.
#

import logging
from eduid_userdb.element import Element


__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class LogElement(Element):

    def __init__(self, created_by):
        """
        :param created_by: Application creating the log element

        :type created_by: six.string_types

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

    def __init__(self, user, created_by, proofing_method, proofing_version):
        """
        :param user: User object
        :param created_by: Application creating the log element
        :param proofing_method: Proofing method name
        :param proofing_version: Proofing method version number

        :type user: eduid_userdb.user.User
        :type created_by: six.string_types
        :type proofing_method: six.string_types
        :type proofing_version: six.string_types

        :return: ProofingLogElement object
        :rtype: ProofingLogElement
        """
        super(ProofingLogElement, self).__init__(created_by)
        self._required_keys.extend(['eduPersonPrincipalName', 'proofing_method', 'proofing_version'])
        self._data['eduPersonPrincipalName'] = user.eppn
        self._data['proofing_method'] = proofing_method
        self._data['proofing_version'] = proofing_version


class MailAddressProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'e-mail',
        'proofing_version': '2013v1',
        'mail_address': 'mail_address'
    }
    """
    def __init__(self, user, created_by, mail_address, proofing_version):
        """
        :param user: User object
        :param created_by: Application creating the log element
        :param mail_address: e-mail address
        :param proofing_version: Proofing method version number

        :type user: eduid_userdb.user.User
        :type created_by: six.string_types
        :type mail_address: six.string_types
        :type proofing_version: six.string_types

        :return: MailAddressProofing object
        :rtype: MailAddressProofing
        """
        super(MailAddressProofing, self).__init__(user, created_by, proofing_method='e-mail',
                                                  proofing_version=proofing_version)
        self._required_keys.extend(['mail_address'])
        self._data['mail_address'] = mail_address


class PhoneNumberProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'sms',
        'proofing_version': '2013v1',
        'phone_number': 'phone_number'
    }
    """
    def __init__(self, user, created_by, phone_number, proofing_version):
        """
        :param user: User object
        :param created_by: Application creating the log element
        :param phone_number: phone number
        :param proofing_version: Proofing method version number

        :type user: eduid_userdb.user.User
        :type created_by: six.string_types
        :type phone_number: six.string_types
        :type proofing_version: six.string_types

        :return: PhoneNumberProofing object
        :rtype: PhoneNumberProofing
        """
        super(PhoneNumberProofing, self).__init__(user, created_by, proofing_method='sms',
                                                  proofing_version=proofing_version)
        self._required_keys.extend(['phone_number'])
        self._data['phone_number'] = phone_number


class TeleAdressProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'TeleAdress',
        'proofing_version': '2014v1',
        'reason': 'matched',
        'nin': national_identity_number,
        'mobile_number': mobile_number,
        'teleadress_response': {teleadress_response},
        'user_postal_address': {postal_address_from_navet}
    }
    """

    def __init__(self, user, created_by, reason, nin, mobile_number, user_postal_address, proofing_version):
        """
        :param user: user object
        :param created_by: Application creating the log element
        :param reason: Reason for mobile phone number match to user
        :param nin: National identity number
        :param mobile_number: Mobile phone number
        :param user_postal_address: Navet response for users official address
        :param proofing_version: Proofing method version number

        :type user: eduid_userdb.User
        :type created_by: six.string_types
        :type reason: six.string_types
        :type nin: six.string_types
        :type mobile_number: six.string_types
        :type user_postal_address: dict
        :type proofing_version: six.string_types

        :return: TeleAdressProofing object
        :rtype: TeleAdressProofing
        """
        super(TeleAdressProofing, self).__init__(user, created_by, proofing_method='TeleAdress',
                                                 proofing_version=proofing_version)
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
        'proofing_version': '2014v1',
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
                 registered_relation, registered_postal_address, proofing_version):
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
        :param proofing_version: Proofing method version number

        :type user: User
        :type created_by: six.string_types
        :type reason: six.string_types
        :type nin: six.string_types
        :type mobile_number: six.string_types
        :type user_postal_address: dict
        :type mobile_number_registered_to: six.string_types
        :type registered_relation: six.string_types
        :type registered_postal_address:  dict
        :type proofing_version: six.string_types

        :return: TeleAdressProofingRelation object
        :rtype: TeleAdressProofingRelation
        """
        super(TeleAdressProofingRelation, self).__init__(user, created_by, reason, nin, mobile_number,
                                                         user_postal_address, proofing_version=proofing_version)
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
        'proofing_version': '2016v1',
        'nin': 'national_identity_number',
        'letter_sent_to': {address_letter_was_sent_to},
        'transaction_id': 'transaction_id',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    def __init__(self, user, created_by, nin, letter_sent_to, transaction_id, user_postal_address, proofing_version):
        """
        :param user: user object
        :param created_by: Application creating the log element
        :param nin: National identity number
        :param letter_sent_to: Name and address the letter was sent to
        :param transaction_id: Letter service transaction id
        :param user_postal_address: Navet response for users official address
        :param proofing_version: Proofing method version number

        :type user: User
        :type created_by: six.string_types
        :type nin: six.string_types
        :type letter_sent_to: dict
        :type transaction_id: six.string_types
        :type user_postal_address: dict
        :type proofing_version: six.string_types

        :return: LetterProofing object
        :rtype: LetterProofing
        """
        super(LetterProofing, self).__init__(user, created_by, proofing_method='letter',
                                             proofing_version=proofing_version)
        self._required_keys.extend(['proofing_method', 'nin', 'letter_sent_to', 'transaction_id',
                                    'user_postal_address'])
        self._data['nin'] = nin
        self._data['letter_sent_to'] = letter_sent_to
        self._data['transaction_id'] = transaction_id
        self._data['user_postal_address'] = user_postal_address


class OidcProofing(ProofingLogElement):
    """
    {
        'eduPersonPrincipalName': eppn,
        'created_ts': datetime.utcnow()
        'created_by': 'application',
        'proofing_method': 'oidc',
        'proofing_version': '2017v1',
        'nin': 'national_identity_number',
        'vetting_by': 'provider who performed the vetting,
        'transaction_id': 'transaction_id',
        'user_postal_address': {postal_address_from_navet}
    }
    """

    def __init__(self, user, created_by, nin, vetting_by, transaction_id, user_postal_address, proofing_version):
        """
        :param user: user object
        :param created_by: Application creating the log element
        :param nin: National identity number
        :param vetting_by: Name of the provider who performed the vetting
        :param transaction_id: Letter service transaction id
        :param user_postal_address: Navet response for users official address
        :param proofing_version: Proofing method version number

        :type user: User
        :type created_by: six.string_types
        :type nin: six.string_types
        :type vetting_by: six.string_types
        :type transaction_id: six.string_types
        :type user_postal_address: dict
        :type proofing_version: six.string_types

        :return: LetterProofing object
        :rtype: LetterProofing
        """
        super(OidcProofing, self).__init__(user, created_by, proofing_method='letter',
                                           proofing_version=proofing_version)
        self._required_keys.extend(['proofing_method', 'nin', 'letter_sent_to', 'transaction_id',
                                    'user_postal_address'])
        self._data['nin'] = nin
        self._data['vetting_by'] = vetting_by
        self._data['transaction_id'] = transaction_id
        self._data['user_postal_address'] = user_postal_address
