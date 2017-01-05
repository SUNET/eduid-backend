'''
Some data samples, old and new. 
'''

from datetime import datetime
from copy import deepcopy
from bson import ObjectId


OLD_USER_EXAMPLE = {
    '_id': ObjectId('012345678901234567890123'),
    'preferredLanguage': 'en',
    'modified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"),
    'givenName': 'John',
    'displayName': 'John Smith',
    'sn': 'Smith',
    'mail': 'johnsmith@example.com',
    'mailAliases': [{
        'email': 'johnsmith@example.com',
        'verified': True,
    }, {
        'email': 'johnsmith2@example.com',
        'verified': True,
    }, {
        'email': 'johnsmith3@example.com',
        'verified': False,
    }],
    'norEduPersonNIN': ['197801011234',],
    'postalAddress': [{
        'type': 'home',
        'country': 'SE',
        'address': "Long street, 48",
        'postalCode': "123456",
        'locality': "Stockholm",
        'verified': True,
    }, {
        'type': 'work',
        'country': 'ES',
        'address': "Calle Ancha, 49",
        'postalCode': "123456",
        'locality': "Punta Umbria",
        'verified': False,
    }],
    'mobile': [{
        'mobile': '+34609609609',
        'primary': True,
        'verified': True
    }, {
        'mobile': '+34 6096096096',
        'verified': False
    }],
    'passwords': [{
        'id': ObjectId('112345678901234567890123'),
        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
        'source': 'signup',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
    }],
    'eduPersonEntitlement': [
        'urn:mace:eduid.se:role:admin',
        'urn:mace:eduid.se:role:student',
    ],
    'eduPersonPrincipalName': 'hubba-bubba',
    'terminated': None,
}


OLD_VERIFICATIONS_EXAMPLE = [{
    '_id': ObjectId('234567890123456789012301'),
    'code': '9d392c',
    'model_name': 'mobile',
    'obj_id': '+34 6096096096',
    'user_oid': ObjectId("012345678901234567890123"),
    'timestamp': datetime.utcnow(),
    'verified': False,
}, {
    '_id': ObjectId(),
    'code': '123124',
    'model_name': 'norEduPersonNIN',
    'obj_id': '197801011234',
    'user_oid': ObjectId("012345678901234567890123"),
    'timestamp': datetime.utcnow(),
    'verified': True,
}]


NEW_USER_EXAMPLE = {
    '_id': ObjectId('012345678901234567890123'),
    'eduPersonPrincipalName': 'hubba-bubba',
    'givenName': 'John',
    'displayName': 'John Smith',
    'surname': 'Smith',
    'subject': 'physical person',
    'preferredLanguage': 'en',
    'modified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"),
    'mail': 'johnsmith@example.com',
    'terminated': False,
    'mailAliases': [{
        'email': 'johnsmith@example.com',
        'created_by': 'signup',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verified': True,
        # XXX is verified_by an application, or a user_id?
        'verified_by': 'signup',
        'verified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verification_code': '1234',
        'primary': True,
    }, {
        'email': 'johnsmith2@example.com',
        'created_by': 'dashboard',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verified': False,
        'verified_by': 'dashboard',
        'verified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verification_code': '1234',
        'primary': False,
    }],
    'nins': [{
        'number': '197801011234',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'created_by': 'dashboard',
        'verified': True,
        'verified_by': 'dashboard',
        'verified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verification_code': '1234',
        'primary': True,
    }, {
        'number': '197801011235',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'created_by': 'dashboard',
        'verified': True,
        'verified_by': 'dashboard',
        'verified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verification_code': '1234',
        'primary': False,
    }],
    'phone': [{
        'number': '+34609609609',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'created_by': 'dashboard',
        'verified': True,
        'verified_by': 'dashboard',
        'verified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verification_code': '1234',
        'primary': True,
    }, {
        'number': '+34 6096096096',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'created_by': 'dashboard',
        'verified': True,
        'verified_by': 'dashboard',
        'verified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verification_code': '1234',
        'primary': False,
    }],
    'passwords': [{
        'id': ObjectId('112345678901234567890123'),
        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
        'created_by': 'signup',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
    }],
    'entitlements': [
        'urn:mace:eduid.se:role:admin',
        'urn:mace:eduid.se:role:student',
    ],
}


NEW_SIGNUP_USER_EXAMPLE = deepcopy(NEW_USER_EXAMPLE)
NEW_SIGNUP_USER_EXAMPLE.update({
    'social_network': 'facebook',
    'social_network_id': 'hubba-1234',
    'pending_mail_address': {
        'email': 'johnsmith2@example.com',
        'created_by': 'dashboard',
        'created_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"), 
        'verified': False,
        'verified_by': None,
        'verified_ts': None, 
        'verification_code': '1234',
        'primary': False,
    }
})

NEW_COMPLETED_SIGNUP_USER_EXAMPLE = deepcopy(NEW_USER_EXAMPLE)
NEW_COMPLETED_SIGNUP_USER_EXAMPLE.update({
    '_id': ObjectId('012345678901234567890123'),
    'nins': [],
    'mailAliases': [
        {
            'created_ts': datetime.strptime("2017-01-04T15:47:27", "%Y-%m-%dT%H:%M:%S"),
            'verified': True,
            'verified_by': 'signup',
            'verification_code': '1234',
            'created_by': 'signup',
            'primary': True,
            'verified_ts': datetime.strptime("2017-01-04T16:47:27", "%Y-%m-%dT%H:%M:%S"),
            'email': 'johnsmith3@example.com'
        }
    ],
    'tou': [
        {
            'created_ts': datetime.strptime("2017-01-04T16:47:30", "%Y-%m-%dT%H:%M:%S"),
            'version': '2016-v1',
            'created_by': 'signup',
            'id': ObjectId('912345678901234567890123')
        }
    ],
    'eduPersonEntitlement': [],
    'passwords': [
        {
            'created_ts': datetime.strptime("2017-01-04T16:47:30", "%Y-%m-%dT%H:%M:%S"),
            'salt': '$NDNv1H1$2d465dcc9c68075aa095b646a98e2e3edb1c612c175ebdeaca6c9a55a0457833$32$32$',
            'id': ObjectId('a12345678901234567890123'),
            'created_by': 'signup'
        }
    ],
    'eduPersonPrincipalName': 'hubba-fooo',
    'modified_ts': datetime.strptime("2017-01-04T16:47:30", "%Y-%m-%dT%H:%M:%S"),
    'subject': 'physical person'
})

NEW_DASHBOARD_USER_EXAMPLE = deepcopy(NEW_USER_EXAMPLE)
