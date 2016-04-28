#
# Copyright (c) 2015 NORDUnet A/S
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

from eduid_userdb.testing import MongoTestCase


class TestUserDB(MongoTestCase):

    def setUp(self):
        super(TestUserDB, self).setUp(None, None)

    def test_get_user_by_nin(self):
        """ Test get_user_by_nin """
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        test_user.given_name = 'Kalle Anka'
        self.amdb.save(test_user, old_format = False)
        res = self.amdb.get_user_by_nin(test_user.nins.primary.number)
        self.assertEqual(test_user.given_name, res.given_name)


    def test_get_user_by_nin_old_format(self):
        """ Test get_user_by_nin """
        test_user = self.amdb.get_user_by_id(self.user.user_id)
        test_user.given_name = 'Kalle Anka 2'
        self.amdb.save(test_user, old_format = True)
        res = self.amdb.get_user_by_nin(test_user.nins.primary.number)
        self.assertEqual(test_user.given_name, res.given_name)
        self.fail('test')
