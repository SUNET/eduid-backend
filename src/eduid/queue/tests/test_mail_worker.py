import asyncio
import logging
import os
from collections.abc import AsyncIterator
from datetime import timedelta
from os import environ
from typing import ClassVar

import pytest_asyncio
from aiosmtplib import SMTPResponse
from pytest_mock import MockerFixture

from eduid.common.config.parsers import load_config
from eduid.common.misc.timeutil import utc_now
from eduid.queue.config import QueueWorkerConfig
from eduid.queue.db.message import EduidSignupEmail
from eduid.queue.db.message.payload import (
    EduidIdentityExpiryWarningEmail,
    EduidIdentityUnverifiedEmail,
    EduidResetPasswordEmail,
    EduidTerminationEmail,
    EduidVerificationEmail,
)
from eduid.queue.testing import IsolatedWorkerDBMixin, QueueAsyncioTest, SMPTDFixTemporaryInstance
from eduid.queue.workers.mail import MailQueueWorker

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class TestMailQueueWorker(IsolatedWorkerDBMixin, MailQueueWorker):
    __test__: ClassVar[bool] = False


class TestMailWorker(QueueAsyncioTest):
    @pytest_asyncio.fixture(autouse=True)
    async def setup_mail_worker(
        self, setup_asyncio_queue: None, smtpdfix_instance: SMPTDFixTemporaryInstance
    ) -> AsyncIterator[None]:
        smtpdfix = smtpdfix_instance
        environ["WORKER_NAME"] = "Test Mail Worker 1"

        test_config = {
            "testing": True,
            "mongo_uri": self.mongo_uri,
            "mongo_collection": self.mongo_collection,
            "periodic_min_retry_wait_in_seconds": 1,
            # NOTE: the mail settings need to match the env variables in the smtpdfix container
            "mail_host": "localhost",
            "mail_port": smtpdfix.port,
            "mail_starttls": True,
            "mail_verify_tls": False,
            "mail_username": "eduid_mail",
            "mail_password": "secret",
        }

        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        self.config = load_config(typ=QueueWorkerConfig, app_name="test", ns="queue", test_config=test_config)
        self.client_db.register_handler(EduidSignupEmail)
        self.worker_db.register_handler(EduidSignupEmail)
        await asyncio.sleep(0.5)  # wait for db
        self.worker = TestMailQueueWorker(config=self.config)
        self.tasks = [asyncio.create_task(self.worker.run())]
        await asyncio.sleep(0.5)  # wait for worker to initialize
        yield

    async def test_eduid_signup_mail_from_stream(self) -> None:
        """
        Test that saved queue items are handled by the handle_new_item method
        """
        recipient = "test@example.com"
        expires_at = utc_now() + timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=5)
        payload = EduidSignupEmail(
            email=recipient, reference="test", language="en", verification_code="123456", site_name="Test"
        )
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        # Client saves new queue item
        self.client_db.save(queue_item)
        await self._assert_item_gets_processed(queue_item)

    async def test_eduid_signup_mail_from_stream_unrecoverable_error(self, mocker: MockerFixture) -> None:
        mock_sendmail = mocker.patch("aiosmtplib.SMTP.sendmail")
        """
        Test that saved queue items are handled by the handle_new_item method
        """
        recipient = "test@example.com"
        mock_sendmail.return_value = ({recipient: SMTPResponse(550, "User unknown")}, "Some other message")
        expires_at = utc_now() + timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=5)
        payload = EduidSignupEmail(
            email=recipient, reference="test", language="en", verification_code="123456", site_name="Test"
        )
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        # Client saves new queue item
        self.client_db.save(queue_item)
        await self._assert_item_gets_processed(queue_item)

    async def test_eduid_signup_mail_from_stream_error_retry(self, mocker: MockerFixture) -> None:
        mock_sendmail = mocker.patch("aiosmtplib.SMTP.sendmail")
        """
        Test that saved queue items are handled by the handle_new_item method
        """
        recipient = "test@example.com"
        mock_sendmail.return_value = (
            {recipient: SMTPResponse(450, "Requested mail action not taken: mailbox unavailable")},
            "Some other message",
        )
        expires_at = utc_now() + timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=5)
        payload = EduidSignupEmail(
            email=recipient, reference="test", language="en", verification_code="123456", site_name="Test"
        )
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        # Client saves new queue item
        self.client_db.save(queue_item)
        await self._assert_item_gets_processed(queue_item, retry=True)

    def test_register_mail_translations(self) -> None:
        for lang in ["en", "sv"]:
            payload = EduidSignupEmail(
                email="noone@example.com",
                reference="test",
                language=lang,
                verification_code="secret",
                site_name="Test App",
            )
            with self.worker._jinja2.select_language(lang) as env:
                msg = self.worker._build_mail(
                    translation_env=env.jinja2_env,
                    subject=env.gettext("eduID registration"),
                    txt_template="eduid_signup_email.txt.jinja2",
                    html_template="eduid_signup_email.html.jinja2",
                    data=payload,
                )
            msg_string = str(msg)
            if lang == "en":
                assert "Subject: eduID registration" in msg_string
                assert "You recently used noone@example.com to sign up for" in msg_string
            if lang == "sv":
                assert "Subject: eduID-registrering" in msg_string
                assert "Du har registrerat noone@example.com som e-postadress" in msg_string

    def test_identity_expiry_warning_mail_translations(self) -> None:
        for lang in ["en", "sv"]:
            payload = EduidIdentityExpiryWarningEmail(
                email="noone@example.com",
                reference="test",
                language=lang,
                site_name="Test App",
                expires_at="2030-01-31",
            )
            with self.worker._jinja2.select_language(lang) as env:
                subject = env.gettext("%(site_name)s identity verification is about to expire") % {
                    "site_name": payload.site_name
                }
                msg = self.worker._build_mail(
                    translation_env=env.jinja2_env,
                    subject=subject,
                    txt_template="identity_expiry_warning_email.txt.jinja2",
                    html_template="identity_expiry_warning_email.html.jinja2",
                    data=payload,
                )
            msg_string = str(msg)
            body = msg.get_body(preferencelist=("plain",)).get_content()  # type: ignore[union-attr]
            assert "2030-01-31" in msg_string
            assert "http" not in msg_string
            assert "identity_type" not in msg_string
            if lang == "en":
                assert "Subject: Test App identity verification is about to expire" in msg_string
                assert "Your identity verification at Test App expires on 2030-01-31." in body
            if lang == "sv":
                assert "Subject: Din identitetsverifiering hos Test App" in msg_string
                assert "Din identitet är verifierad hos Test App till och med 2030-01-31." in body

    def test_identity_unverified_mail_translations(self) -> None:
        for lang in ["en", "sv"]:
            payload = EduidIdentityUnverifiedEmail(
                email="noone@example.com",
                reference="test",
                language=lang,
                site_name="Test App",
            )
            with self.worker._jinja2.select_language(lang) as env:
                subject = env.gettext("%(site_name)s identity verification has expired") % {
                    "site_name": payload.site_name
                }
                msg = self.worker._build_mail(
                    translation_env=env.jinja2_env,
                    subject=subject,
                    txt_template="identity_unverified_email.txt.jinja2",
                    html_template="identity_unverified_email.html.jinja2",
                    data=payload,
                )
            msg_string = str(msg)
            assert "http" not in msg_string
            assert "identity_type" not in msg_string
            body = msg.get_body(preferencelist=("plain",)).get_content()  # type: ignore[union-attr]
            if lang == "en":
                assert "Subject: Test App identity verification has expired" in msg_string
                assert "Your identity verification at Test App has expired" in body
                assert "your identity is no longer verified" in body
            if lang == "sv":
                assert "Subject: Din identitetsverifiering hos Test App har gått ut" in msg_string
                assert "Din identitetsverifiering hos Test App har gått ut" in body
                assert "din identitet är inte längre verifierad" in body

    def test_reset_password_mail_translations(self) -> None:
        for lang in ["en", "sv"]:
            payload = EduidResetPasswordEmail(
                email="noone@example.com",
                reference="test",
                language=lang,
                verification_code="secret",
                password_reset_timeout=2,
                site_name="Test App",
            )
            with self.worker._jinja2.select_language(lang) as env:
                msg = self.worker._build_mail(
                    translation_env=env.jinja2_env,
                    subject=env.gettext("Reset password"),
                    txt_template="reset_password_email.txt.jinja2",
                    html_template="reset_password_email.html.jinja2",
                    data=payload,
                )
            msg_string = str(msg)
            if lang == "en":
                assert "Subject: Reset password" in msg_string
                assert "You recently asked to reset your password for" in msg_string
                assert "The code is valid for 2 hours." in msg_string
            if lang == "sv":
                assert "Subject: eduID lösenordsåterställning" in msg_string
                assert "Du har bett om att byta" in msg_string
                assert "giltig i 2 timmar." in msg_string

    def test_verification_mail_translations(self) -> None:
        for lang in ["en", "sv"]:
            payload = EduidVerificationEmail(
                email="noone@example.com",
                reference="test",
                language=lang,
                verification_code="secret",
                site_name="Test App",
            )
            with self.worker._jinja2.select_language(lang) as env:
                msg = self.worker._build_mail(
                    translation_env=env.jinja2_env,
                    subject=env.gettext("eduID verification email"),
                    txt_template="verification_email.txt.jinja2",
                    html_template="verification_email.html.jinja2",
                    data=payload,
                )
            msg_string = str(msg)
            if lang == "en":
                assert "Subject: eduID verification email" in msg_string
                assert "You have recently added this mail address to your Test App account." in msg_string
            if lang == "sv":
                assert "Subject: eduID e-postverifiering" in msg_string
                assert "Du har nyligen lagt till den" in msg_string
                assert "Skriv in koden nedan" in msg_string

    def test_termination_mail_translations(self) -> None:
        for lang in ["en", "sv"]:
            payload = EduidTerminationEmail(
                email="noone@example.com",
                reference="test",
                language=lang,
                site_name="Test App",
            )
            with self.worker._jinja2.select_language(lang) as env:
                msg = self.worker._build_mail(
                    translation_env=env.jinja2_env,
                    subject=env.gettext("eduID account termination"),
                    txt_template="termination_email.txt.jinja2",
                    html_template="termination_email.html.jinja2",
                    data=payload,
                )
            msg_string = str(msg)
            if lang == "en":
                assert "Subject: eduID account termination" in msg_string
                assert "You have chosen to terminate your account at Test App." in msg_string
            if lang == "sv":
                assert "Subject: eduID avsluta konto" in msg_string
                assert "tas ditt konto bort om en vecka." in msg_string
