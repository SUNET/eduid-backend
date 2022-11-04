import asyncio
import logging
import os
from datetime import timedelta
from os import environ
from typing import Optional
from unittest.mock import patch

from aiosmtplib import SMTP, SMTPResponse

from eduid.common.config.parsers import load_config
from eduid.queue.config import QueueWorkerConfig
from eduid.queue.db import QueueItem, TestPayload
from eduid.queue.db.message import EduidSignupEmail
from eduid.queue.testing import QueueAsyncioTest
from eduid.queue.workers.mail import MailQueueWorker
from eduid.userdb.util import utc_now

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class TestMailWorker(QueueAsyncioTest):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        environ["WORKER_NAME"] = "Test Mail Worker 1"

    def setUp(self) -> None:
        super().setUp()
        self.test_config = {
            "testing": True,
            "mongo_uri": self.mongo_uri,
            "mongo_collection": self.mongo_collection,
            "periodic_min_retry_wait_in_seconds": 1,
        }

        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        self.config = load_config(typ=QueueWorkerConfig, app_name="test", ns="queue", test_config=self.test_config)

        self.db.register_handler(EduidSignupEmail)

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        await asyncio.sleep(0.5)  # wait for db
        self.worker = MailQueueWorker(config=self.config)
        self.tasks = [asyncio.create_task(self.worker.run())]
        await asyncio.sleep(0.5)  # wait for worker to initialize

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()

    @patch("aiosmtplib.SMTP.connect")
    @patch("aiosmtplib.SMTP.sendmail")
    async def test_eduid_signup_mail_from_stream(self, mock_sendmail, mock_connect):
        """
        Test that saved queue items are handled by the handle_new_item method
        """
        recipient = "test@example.com"
        mock_sendmail.return_value = ({}, "OK")
        mock_connect.return_value = SMTPResponse(250, "OK")
        expires_at = utc_now() + timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=5)
        payload = EduidSignupEmail(
            email=recipient, reference="test", language="en", verification_code="123456", site_name="Test"
        )
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        # Client saves new queue item
        self.db.save(queue_item)
        await self._assert_item_gets_processed(queue_item)

    @patch("aiosmtplib.SMTP.connect")
    @patch("aiosmtplib.SMTP.sendmail")
    async def test_eduid_signup_mail_from_stream_unrecoverable_error(self, mock_sendmail, mock_connect):
        """
        Test that saved queue items are handled by the handle_new_item method
        """
        recipient = "test@example.com"
        mock_sendmail.return_value = ({recipient: SMTPResponse(550, "User unknown")}, "Some other message")
        mock_connect.return_value = SMTPResponse(250, "OK")
        expires_at = utc_now() + timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=5)
        payload = EduidSignupEmail(
            email=recipient, reference="test", language="en", verification_code="123456", site_name="Test"
        )
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        # Client saves new queue item
        self.db.save(queue_item)
        await self._assert_item_gets_processed(queue_item)

    @patch("aiosmtplib.SMTP.connect")
    @patch("aiosmtplib.SMTP.sendmail")
    async def test_eduid_signup_mail_from_stream_error_retry(self, mock_sendmail, mock_connect):
        """
        Test that saved queue items are handled by the handle_new_item method
        """
        recipient = "test@example.com"
        mock_sendmail.return_value = (
            {recipient: SMTPResponse(450, "Requested mail action not taken: mailbox unavailable")},
            "Some other message",
        )
        mock_connect.return_value = SMTPResponse(250, "OK")
        expires_at = utc_now() + timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=5)
        payload = EduidSignupEmail(
            email=recipient, reference="test", language="en", verification_code="123456", site_name="Test"
        )
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        # Client saves new queue item
        self.db.save(queue_item)
        await self._assert_item_gets_processed(queue_item, retry=True)
