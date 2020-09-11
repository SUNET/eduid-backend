# -*- coding: utf-8 -*-
from dataclasses import asdict
from datetime import datetime, timedelta
from unittest import TestCase, skip

from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_userdb.message import EduidInviteEmail, Message, MessageDB, MessageType, SenderInfo, TestPayload
from eduid_userdb.testing import MongoTestCase, normalised_data

__author__ = 'lundberg'


class TestMessage(TestCase):
    def test_message(self):
        expires_at = datetime.utcnow() + timedelta(days=180)
        discard_at = expires_at + timedelta(days=7)
        sender_info = SenderInfo(hostname='testhost', node_id='userdb@testhost')
        payload = TestPayload(message='this is a test payload')
        message = Message(
            type=MessageType.TEST_PAYLOAD,
            version='1',
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload=payload.to_dict(),
        )
        loaded_message_dict = asdict(Message.from_dict(message.to_dict()))
        assert normalised_data(asdict(message)) == normalised_data(loaded_message_dict)

        loaded_payload_dict = asdict(message.get_payload())
        assert normalised_data(payload.to_dict()) == normalised_data(loaded_payload_dict)

    def test_eduid_invite_mail(self):
        expires_at = datetime.utcnow() + timedelta(days=180)
        discard_at = expires_at + timedelta(days=7)
        sender_info = SenderInfo(hostname='testhost', node_id='userdb@testhost')
        payload = EduidInviteEmail(
            email='mail@example.com',
            reference='ref_id',
            invite_link='https://signup.example.com/abc123',
            invite_code='abc123',
            inviter_name='Test Application',
        )
        message = Message(
            type=MessageType.EDUID_INVITE_EMAIL,
            version='1',
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload=payload.to_dict(),
        )

        loaded_message_dict = asdict(Message.from_dict(message.to_dict()))
        assert normalised_data(asdict(message)) == normalised_data(loaded_message_dict)

        loaded_payload_dict = asdict(message.get_payload())
        assert normalised_data(payload.to_dict()) == normalised_data(loaded_payload_dict)


class TestMessageDB(MongoTestCase):
    def setUp(self, init_am=False, am_settings=None):
        super().setUp(init_am=init_am, am_settings=am_settings)
        self.messagedb = MessageDB(self.tmp_db.uri)

        expires_at = datetime.utcnow() + timedelta(days=180)
        discard_at = expires_at + timedelta(days=7)
        sender_info = SenderInfo(hostname='testhost', node_id='userdb@testhost')
        self.payload = TestPayload(message='this is a test payload')
        self.message = Message(
            type=MessageType.TEST_PAYLOAD,
            version='1',
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload=self.payload.to_dict(),
        )

    def test_save_load(self):
        self.messagedb.save(self.message)

        assert 1 == self.messagedb.db_count()
        message = self.messagedb.get_message_by_id(self.message.message_id)
        assert normalised_data(asdict(self.message)) == normalised_data(asdict(message))

        loaded_payload_dict = asdict(message.get_payload())
        assert normalised_data(asdict(self.payload)) == normalised_data(loaded_payload_dict)

    def test_save_load_eduid_email_invite(self):
        payload = EduidInviteEmail(
            email='mail@example.com',
            reference='ref_id',
            invite_link='https://signup.example.com/abc123',
            invite_code='abc123',
            inviter_name='Test Application',
        )
        self.message.type = MessageType.EDUID_INVITE_EMAIL
        self.message.payload = payload.to_dict()
        self.messagedb.save(self.message)

        assert 1 == self.messagedb.db_count()
        message = self.messagedb.get_message_by_id(self.message.message_id)
        assert normalised_data(asdict(self.message)) == normalised_data(asdict(message))

        loaded_payload_dict = asdict(message.get_payload())
        assert normalised_data(asdict(payload)) == normalised_data(loaded_payload_dict)

    @skip('It takes mongo a couple of seconds to actually remove the document, skip for now.')
    # TODO: Investigate if it is possible to force a expire check in mongodb
    def test_auto_discard(self):
        message = Message.from_dict(self.message.to_dict())
        message.discard_at = datetime.utcnow() - timedelta(seconds=-10)
        self.messagedb.save(message)
        assert 0 == self.messagedb.db_count()
        with self.assertRaises(DocumentDoesNotExist):
            self.messagedb.get_message_by_id(self.message.message_id)
