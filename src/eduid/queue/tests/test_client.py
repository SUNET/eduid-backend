from datetime import timedelta
from unittest import TestCase, skip

from eduid.common.misc.timeutil import utc_now
from eduid.common.testing_base import normalised_data
from eduid.queue.db import Payload, RawPayload, TestPayload
from eduid.queue.db.message import EduidInviteEmail, EduidSignupEmail, MessageDB
from eduid.queue.db.queue_item import QueueItem, SenderInfo
from eduid.queue.testing import EduidQueueTestCase

__author__ = "lundberg"


class TestClient(TestCase):
    def test_queue_item(self) -> None:
        expires_at = utc_now() + timedelta(days=180)
        discard_at = expires_at + timedelta(days=7)
        sender_info = SenderInfo(hostname="testhost", node_id="userdb@testhost")
        payload = TestPayload(message="this is a test payload")
        item = QueueItem(
            version=1,
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload_type=payload.get_type(),
            payload=payload,
        )
        loaded_message_dict = QueueItem.from_dict(item.to_dict()).to_dict()
        assert normalised_data(item.to_dict()) == normalised_data(loaded_message_dict)
        assert normalised_data(payload.to_dict()) == normalised_data(item.payload.to_dict())


class TestMessage(TestCase):
    def setUp(self) -> None:
        self.expires_at = utc_now() + timedelta(days=180)
        self.discard_at = self.expires_at + timedelta(days=7)
        self.sender_info = SenderInfo(hostname="testhost", node_id="userdb@testhost")

    def _create_queue_item(self, payload: Payload) -> QueueItem:
        return QueueItem(
            version=1,
            expires_at=self.expires_at,
            discard_at=self.discard_at,
            sender_info=self.sender_info,
            payload_type=payload.get_type(),
            payload=payload,
        )

    def test_eduid_invite_mail(self) -> None:
        payload = EduidInviteEmail(
            email="mail@example.com",
            reference="ref_id",
            invite_link="https://signup.example.com/abc123",
            invite_code="abc123",
            inviter_name="Test Application",
            language="sv",
        )
        item = self._create_queue_item(payload=payload)
        loaded_message_dict = QueueItem.from_dict(item.to_dict()).to_dict()
        assert normalised_data(item.to_dict()) == normalised_data(loaded_message_dict)
        assert normalised_data(payload.to_dict()) == normalised_data(item.payload.to_dict())

    def test_eduid_signup_mail(self) -> None:
        payload = EduidSignupEmail(
            email="mail@example.com",
            reference="ref_id",
            verification_code="abc123",
            site_name="Test Site",
            language="sv",
        )
        item = self._create_queue_item(payload=payload)
        loaded_message_dict = QueueItem.from_dict(item.to_dict()).to_dict()
        assert normalised_data(item.to_dict()) == normalised_data(loaded_message_dict)
        assert normalised_data(payload.to_dict()) == normalised_data(item.payload.to_dict())


class TestMessageDB(EduidQueueTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.messagedb = MessageDB(self.mongo_uri)
        self.messagedb.register_handler(TestPayload)
        self.messagedb.register_handler(EduidInviteEmail)
        self.messagedb.register_handler(EduidSignupEmail)

        self.expires_at = utc_now() + timedelta(hours=2)
        self.discard_at = self.expires_at + timedelta(days=7)
        self.sender_info = SenderInfo(hostname="testhost", node_id="userdb@testhost")

    def tearDown(self) -> None:
        super().tearDown()
        self.messagedb._drop_whole_collection()

    def _create_queue_item(self, payload: Payload) -> QueueItem:
        return QueueItem(
            version=1,
            expires_at=self.expires_at,
            discard_at=self.discard_at,
            sender_info=self.sender_info,
            payload_type=payload.get_type(),
            payload=payload,
        )

    def test_save_load(self) -> None:
        payload = TestPayload(message="this is a test payload")
        item = self._create_queue_item(payload)
        self.messagedb.save(item)
        assert 1 == self.messagedb.db_count()

        loaded_item = self.messagedb.get_item_by_id(item.item_id)
        assert loaded_item
        assert loaded_item.payload_type == payload.get_type()
        assert isinstance(loaded_item.payload, TestPayload) is True
        assert normalised_data(item.to_dict()) == normalised_data(loaded_item.to_dict())

    def test_save_load_raw_payload(self) -> None:
        payload = TestPayload(message="this is a test payload")
        item = self._create_queue_item(payload)
        self.messagedb.save(item)
        assert 1 == self.messagedb.db_count()

        loaded_item = self.messagedb.get_item_by_id(item.item_id)
        assert loaded_item
        assert loaded_item.payload_type == payload.get_type()
        assert isinstance(loaded_item.payload, TestPayload) is True

        raw_loaded_item = self.messagedb.get_item_by_id(item.item_id, parse_payload=False)
        assert raw_loaded_item
        assert raw_loaded_item.payload_type == payload.get_type()
        assert isinstance(raw_loaded_item.payload, RawPayload) is True
        assert normalised_data(item.payload.to_dict()) == normalised_data(raw_loaded_item.payload.to_dict())

    def test_save_load_eduid_email_invite(self) -> None:
        payload = EduidInviteEmail(
            email="mail@example.com",
            reference="ref_id",
            invite_link="https://signup.example.com/abc123",
            invite_code="abc123",
            inviter_name="Test Application",
            language="sv",
        )
        item = self._create_queue_item(payload)
        self.messagedb.save(item)
        assert 1 == self.messagedb.db_count()

        loaded_item = self.messagedb.get_item_by_id(item.item_id)
        assert loaded_item
        assert normalised_data(item.to_dict()) == normalised_data(loaded_item.to_dict())
        assert normalised_data(item.payload.to_dict()), normalised_data(loaded_item.payload.to_dict())

    def test_save_load_eduid_email_signup(self) -> None:
        payload = EduidSignupEmail(
            email="mail@example.com",
            reference="ref_id",
            verification_code="abc123",
            site_name="Test Site",
            language="sv",
        )
        item = self._create_queue_item(payload)
        self.messagedb.save(item)
        assert 1 == self.messagedb.db_count()

        loaded_item = self.messagedb.get_item_by_id(item.item_id)
        assert loaded_item
        assert normalised_data(item.to_dict()) == normalised_data(loaded_item.to_dict())
        assert normalised_data(item.payload.to_dict()) == normalised_data(loaded_item.payload.to_dict())

    @skip("It takes mongo a couple of seconds to actually remove the document, skip for now.")
    # TODO: Investigate if it is possible to force a expire check in mongodb
    def test_auto_discard(self) -> None:
        self.discard_at = utc_now() - timedelta(seconds=-10)
        payload = TestPayload(message="this is a test payload")
        item = self._create_queue_item(payload)
        self.messagedb.save(item)
        assert 0 == self.messagedb.db_count()
        assert not self.messagedb.get_item_by_id(item.item_id)
