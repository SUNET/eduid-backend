#  -*- encoding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
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
#     3. Neither the name of the SUNET nor the names of its
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

from enum import unique
from unittest import TestCase

from werkzeug.wrappers import Response

from eduid_common.api.messages import (
    CommonMsg,
    TranslatableMsg,
    error_message,
    make_query_string,
    redirect_with_msg,
    success_message,
)


@unique
class TestsMsg(TranslatableMsg):
    fst_test_msg = 'test.first_msg'
    snd_test_msg = 'test.second_msg'


class MessageTests(TestCase):
    def test_success_message(self):
        message = success_message(TestsMsg.fst_test_msg)
        self.assertEqual(message['_status'], 'ok')
        self.assertTrue(message['success'])
        self.assertEqual(message['message'], 'test.first_msg')

    def test_success_message_with_data(self):
        data = {'email': 'test@example.com'}
        message = success_message(TestsMsg.fst_test_msg, data=data)
        self.assertEqual(message['_status'], 'ok')
        self.assertEqual(message['message'], 'test.first_msg')
        self.assertEqual(message['email'], 'test@example.com')

    def test_success_message_from_str(self):
        message = success_message('test.str_msg')
        self.assertEqual(message['_status'], 'ok')
        self.assertEqual(message['message'], 'test.str_msg')

    def test_success_message_from_str_with_data(self):
        data = {'email': 'test@example.com'}
        message = success_message('test.str_msg', data=data)
        self.assertEqual(message['_status'], 'ok')
        self.assertEqual(message['message'], 'test.str_msg')
        self.assertEqual(message['email'], 'test@example.com')

    def test_success_message_unknown(self):
        with self.assertRaises(AttributeError):
            success_message(TestsMsg.unknown_msg)

    def test_success_message_unknown_with_data(self):
        data = {'email': 'test@example.com'}
        with self.assertRaises(AttributeError):
            success_message(TestsMsg.unknown_msg, data=data)

    def test_error_message(self):
        message = error_message(TestsMsg.fst_test_msg)
        self.assertEqual(message['_status'], 'error')
        self.assertFalse(message['success'])
        self.assertEqual(message['message'], 'test.first_msg')

    def test_error_message_with_errors(self):
        data = {'errors': {'email': 'required'}}
        message = error_message(TestsMsg.fst_test_msg, data=data)
        self.assertEqual(message['_status'], 'error')
        self.assertEqual(message['message'], 'test.first_msg')
        self.assertEqual(message['errors'], data['errors'])

    def test_error_message_with_status(self):
        data = {'status': 'stale'}
        message = error_message(TestsMsg.fst_test_msg, data=data)
        self.assertEqual(message['_status'], 'error')
        self.assertEqual(message['message'], 'test.first_msg')
        self.assertEqual(message['status'], data['status'])

    def test_error_message_with_next(self):
        data = {'next': '/next'}
        message = error_message(TestsMsg.fst_test_msg, data=data)
        self.assertEqual(message['_status'], 'error')
        self.assertEqual(message['message'], 'test.first_msg')
        self.assertEqual(message['next'], data['next'])

    def test_error_message_from_str(self):
        message = error_message('test.str_msg')
        self.assertEqual(message['_status'], 'error')
        self.assertEqual(message['message'], 'test.str_msg')

    def test_error_message_from_str_with_errors(self):
        data = {'errors': {'email': 'required'}}
        message = error_message('str_msg', data=data)
        self.assertEqual(message['_status'], 'error')
        self.assertEqual(message['message'], 'str_msg')
        self.assertEqual(message['errors'], data['errors'])

    def test_error_message_from_str_with_status(self):
        data = {'status': 'stale'}
        message = error_message('str_msg', data=data)
        self.assertEqual(message['_status'], 'error')
        self.assertEqual(message['message'], 'str_msg')
        self.assertEqual(message['status'], data['status'])

    def test_error_message_from_str_with_next(self):
        data = {'next': '/next'}
        message = error_message('str_msg', data=data)
        self.assertEqual(message['_status'], 'error')
        self.assertEqual(message['message'], 'str_msg')
        self.assertEqual(message['next'], data['next'])

    def test_error_message_unknown(self):
        with self.assertRaises(AttributeError):
            error_message(TestsMsg.unknown_msg)

    def test_make_query_string_error(self):
        qs = make_query_string(TestsMsg.fst_test_msg)
        self.assertEqual(qs, 'msg=%3AERROR%3Atest.first_msg')

    def test_make_query_string_success(self):
        qs = make_query_string(TestsMsg.fst_test_msg, error=False)
        self.assertEqual(qs, 'msg=test.first_msg')

    def test_make_query_string_error_unknown(self):
        with self.assertRaises(AttributeError):
            make_query_string(TestsMsg.unknown_msg)

    def test_make_query_string_success_unknown(self):
        with self.assertRaises(AttributeError):
            make_query_string(TestsMsg.unknown_msg, error=False)

    def test_make_redirect_error(self):
        url = 'https://example.com'
        response = redirect_with_msg(url, TestsMsg.fst_test_msg)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'https://example.com?msg=%3AERROR%3Atest.first_msg')

    def test_make_redirect_error_with_str(self):
        url = 'https://example.com'
        response = redirect_with_msg(url, 'test.str_msg')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'https://example.com?msg=%3AERROR%3Atest.str_msg')

    def test_make_redirect_success(self):
        url = 'https://example.com'
        response = redirect_with_msg(url, TestsMsg.fst_test_msg, error=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'https://example.com?msg=test.first_msg')

    def test_make_redirect_success_with_str(self):
        url = 'https://example.com'
        response = redirect_with_msg(url, 'test.str_msg', error=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'https://example.com?msg=test.str_msg')


class MessagesTests(TestCase):
    def test_messages(self):
        """"""
        self.assertEqual(CommonMsg.temp_problem.value, 'Temporary technical problems')
        self.assertEqual(CommonMsg.form_errors.value, 'form-errors')
        self.assertEqual(CommonMsg.out_of_sync.value, 'user-out-of-sync')
        self.assertEqual(CommonMsg.navet_error.value, 'error_navet_task')
        self.assertEqual(CommonMsg.nin_invalid.value, 'nin needs to be formatted as 18|19|20yymmddxxxx')
        self.assertEqual(CommonMsg.email_invalid.value, 'email needs to be formatted according to RFC2822')
        self.assertEqual(CommonMsg.csrf_try_again.value, 'csrf.try_again')
        self.assertEqual(CommonMsg.csrf_missing.value, 'csrf.missing')
