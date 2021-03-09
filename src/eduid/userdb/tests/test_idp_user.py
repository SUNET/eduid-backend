# -*- coding: utf-8 -*-
from unittest import TestCase

from eduid.userdb.fixtures.users import mocked_user_standard
from eduid.userdb.idp.user import _SAML_ATTRIBUTES, IdPUser, SAMLAttributeSettings
from eduid.userdb.testing import normalised_data

__author__ = 'lundberg'


class TestIdpUser(TestCase):
    def setUp(self):
        super().setUp()
        self.idp_config = {
            'default_eppn_scope': 'example.com',
            'default_country_code': 'se',
            'default_country': 'Sweden',
        }
        self.saml_attribute_settings = SAMLAttributeSettings(**self.idp_config)

    def test_idp_user_to_attributes_all(self):
        idp_user = IdPUser.from_dict(mocked_user_standard.to_dict())
        attributes = idp_user.to_saml_attributes(settings=self.saml_attribute_settings)

        for key in _SAML_ATTRIBUTES:
            if key == 'eduPersonTargetedID':
                # eduPersonTargetedID is generated by the IdP
                continue
            self.assertIsNotNone(attributes.get(key), f'{key} is unexpectedly None')

        expected = {
            'displayName': 'John Smith',
            'eduPersonEntitlement': ['urn:mace:eduid.se:role:admin', 'urn:mace:eduid.se:role:student'],
            'eduPersonPrincipalName': 'hubba-bubba@example.com',
            'givenName': 'John',
            'preferredLanguage': 'en',
            'c': 'se',
            'co': 'Sweden',
            'eduPersonUniqueID': 'hubbabubba@example.com',
            'eduPersonAssurance': ['http://www.swamid.se/policy/assurance/al2'],
            'cn': 'John Smith',
            'sn': 'Smith',
            'norEduPersonNIN': '197801011234',
            'personalIdentityNumber': '197801011234',
            'schacDateOfBirth': '19780101',
            'mail': 'johnsmith@example.com',
            'eduPersonOrcid': 'https://op.example.org/user_orcid',
        }
        assert normalised_data(expected) == normalised_data(attributes)
