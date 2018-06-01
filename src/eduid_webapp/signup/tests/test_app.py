# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
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

import json
from mock import patch
from flask import Flask

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.signup.app import signup_init_app


class SignupTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropiate flask
        app for this test case.
        """
        return signup_init_app('signup', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English','sv': 'Svenska'},
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'DASHBOARD_URL': '/profile/',
            'SIGNUP_URL': 'https://signup.eduid.local.emergya.info/',
            'DEVELOPMENT': 'DEBUG',
            'APPLICATION_ROOT': '/',
            'SERVER_NAME': 'signup.eduid.local.emergya.info',
            'SECRET_KEY': 'supersecretkey',
            'MONGO_URI': 'mongodb://eduid_signup:eduid_signup_pw@mongodb.eduid_dev',
            'LOG_LEVEL': 'DEBUG',
            'LOGGER_NAME': 'signup',
            'AM_BROKER_URL': 'amqp://eduid:eduid_pw@rabbitmq/am',
            'MSG_BROKER_URL': 'amqp://eduid:eduid_pw@rabbitmq/msg',
            'PASSWORD_LENGTH': '10',
            'VCCS_URL': 'http://turq:13085/',
            'TOU_VERSION': '2018-v1',
            'AUTH_SHARED_SECRET': 'shared_secret_Eifool0ua0eiph7ooch0',
            'DEFAULT_FINISH_URL': 'https://www.eduid.se/',
            'RECAPTCHA_PUBLIC_KEY': 'XXXX',
            'RECAPTCHA_PRIVATE_KEY': 'XXXX',
            'STUDENTS_LINK': 'https://www.eduid.se/index.html',
            'TECHNICIANS_LINK': 'https://www.eduid.se/tekniker.html',
            'STAFF_LINK': 'https://www.eduid.se/personal.html',
            'FAQ_LINK': 'https://www.eduid.se/faq.html',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json',
                'MONGO_URI': config['MONGO_URI'],
            },
        })
        return config

    def init_data(self):
        test_user_dict = self.app.private_userdb.UserClass(data=self.test_user.to_dict())
        self.app.private_userdb.save(test_user_dict, check_sync=False)

    def tearDown(self):
        super(PhoneTests, self).tearDown()
        with self.app.app_context():
            self.app.private_userdb._drop_whole_collection()
            self.app.central_userdb._drop_whole_collection()

    def test_get_all_phone(self):
        response = self.browser.get('/config')
        self.assertEqual(response.status_code, 200)

        config_data = json.loads(response.data)

        self.assertEqual('XXXX', config_data['recaptcha_public_key'])
