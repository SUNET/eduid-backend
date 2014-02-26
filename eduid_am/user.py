#
# Copyright (c) 2014 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#



class User(object):
    """

    :param user_id: User id, typically MongoDB _id
    :param authn_ref: AuthnBroker opaque reference
    :param authn_class_ref: Authn class reference
    :param authn_request_id: SAML request id of request that caused authentication
    :param ts: Authentication timestamp, in UTC

    :type user_id: bson.ObjectId | object
    :type authn_ref: object
    :type authn_class_ref: string
    :type authn_request_id: string
    :type ts: int
    """

    def __init__(self, mongo_doc):
        if type(mongo_doc) is User:
            self._mongo_doc = mongo_doc._mongo_doc
        else:
            self._mongo_doc = mongo_doc

    def __repr__(self):
        return '<User: {0}>'.format(self['displayName'])

    def __getitem__(self, key):
        return self._mongo_doc[key]

    def items(self):
        return self._mongo_doc.items()

    def keys(self):
        return self._mongo_doc.keys()

    def get_doc(self):
        return self._mongo_doc

    def get_id(self):
        return self._mongo_doc['_id']

    def get_given_name(self):
        return self._mongo_doc.get('givenName', '')

    def set_given_name(self, name):
        self._mongo_doc['givenName'] = name

    def get_display_name(self):
        return self._mongo_doc.get('displayName', '')

    def set_display_name(self, name):
        self._mongo_doc['displayName'] = name

    def get_sn(self):
        return self._mongo_doc.get('sn', '')

    def set_sn(self, sn):
        self._mongo_doc['sn'] = sn

    def get_mail(self):
        return self._mongo_doc.get('mail', '')

    def set_mail(self, mail):
        self._mongo_doc['mail'] = mail

    def get_mail_aliases(self):
        return self._mongo_doc.get('mailAliases', [])

    def set_mail_aliases(self, emails):
        self._mongo_doc['mailAliases'] = emails

    def add_verified_email(self, verified_email):
        emails = self._mongo_doc['mailAliases']
        for email in emails:
            if email['email'] == verified_email:
                email['verified'] = True

    def save(self, request):
        request.db.profiles.save(self._mongo_doc, safe=True)
        request.context.propagate_user_changes(self._mongo_doc)

    def has_nin(self):
        if self._mongo_doc.get('norEduPersonNIN', None) is None:
            return False
        return True

    def add_verified_nin(self, verified_nin):
        if self.has_nin():
            self._mongo_doc['norEduPersonNIN'].append(verified_nin)
        else:
            self._mongo_doc['norEduPersonNIN'] = [verified_nin]

    def get_nins(self):
        return self._mongo_doc.get('norEduPersonNIN', [])

    def set_nins(self, nins):
        self._mongo_doc['norEduPersonNIN'] = nins

    def get_addresses(self):
        return self._mongo_doc.get('postalAddress', [])

    def set_addresses(self, addresses):
        self._mongo_doc['postalAddress'] = addresses

    def retrieve_address(self, request, verified_nin):
        """ 
            Function to get the official postal address from
            the government service
        """

        if not request.registry.settings.get('enable_postal_address_retrieve', True):
            return

        address = request.msgrelay.get_postal_address(verified_nin)

        address['type'] = 'official'
        address['verified'] = True

        user_addresses = self.get_addresses()

        for old_address in user_addresses:
            if old_address.get('type') == 'official':
                user_addresses.remove(user_address)
                user_addresses.append(address)
                break
        else:
            user_addresses.append(address)

    def add_verified_mobile(self, verified_mobile):
        mobiles = self._mongo_doc['mobile']

        for mobile in mobiles:
            if mobile['mobile'] == verified_mobile:
                mobile['verified'] = True
                if len(mobiles) == 1:
                    mobile['primary'] = True

    def get_mobiles(self):
        return self._mongo_doc.get('mobile', [])

    def set_mobiles(self, mobiles):
        self._mongo_doc['mobile'] = mobiles

    def add_mobile(self, mobile):
        mobiles = self.get_mobiles()
        mobiles.append(mobile)
        self.set_mobiles(mobiles)

    def get_passwords(self):
        return self._mongo_doc.get('passwords', [])

    def set_passwords(self, passwords):
        self._mongo_doc['passwords'] = passwords

    def get_entitlements(self):
        return self._mongo_doc.get('eduPersonEntitlement', [])

    def set_entitlements(self, entitlements):
        self._mongo_doc['eduPersonEntitlement'] = entitlements

    def get_preferred_language(self):
        return self._mongo_doc.get('preferredLanguage', None)

