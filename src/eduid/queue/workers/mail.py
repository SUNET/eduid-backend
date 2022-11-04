# -*- coding: utf-8 -*-
import asyncio
import logging
from dataclasses import asdict
from email.message import EmailMessage
from gettext import gettext as _
from ssl import create_default_context
from typing import Any, Mapping, Optional, Sequence, Type, cast

from aiosmtplib import SMTP, SMTPException, SMTPResponse, send

from eduid.common.config.base import EduidEnvironment
from eduid.common.config.parsers import load_config
from eduid.queue.config import QueueWorkerConfig
from eduid.queue.db import QueueItem
from eduid.queue.db.message import EduidInviteEmail, EduidSignupEmail
from eduid.queue.db.message.payload import OldEduidSignupEmail
from eduid.queue.db.payload import Payload
from eduid.queue.db.queue_item import Status
from eduid.queue.helpers import Jinja2Env
from eduid.queue.workers.base import QueueWorker

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class MailQueueWorker(QueueWorker):
    def __init__(self, config: QueueWorkerConfig):
        # Register which queue items this worker should try to grab
        payloads: Sequence[Type[Payload]] = [EduidInviteEmail, EduidSignupEmail, OldEduidSignupEmail]
        super().__init__(config=config, handle_payloads=payloads)

        self._smtp: Optional[SMTP] = None
        self._jinja2 = Jinja2Env()

    @property
    async def smtp(self):
        if self._smtp is None:
            logger.debug(f"Creating SMTP client for {self.config.mail_host}:{self.config.mail_port}")
            self._smtp = SMTP(hostname=self.config.mail_host, port=self.config.mail_port)
            await self._smtp.connect()
            # starttls
            ssl_context = None
            if self.config.mail_verify_tls is False:
                logger.warning("Disabling TLS certificate hostname verification")
                ssl_context = create_default_context()
                ssl_context.check_hostname = False
            if self.config.mail_starttls:
                keyfile = self.config.mail_keyfile
                certfile = self.config.mail_certfile
                if keyfile and certfile:
                    logger.debug(f"Starting TLS with keyfile: {keyfile} and certfile: {certfile}")
                    await self._smtp.starttls(client_key=keyfile, client_cert=certfile, tls_context=ssl_context)
                else:
                    logger.debug("Starting TLS")
                    await self._smtp.starttls(tls_context=ssl_context)
            # login
            username = self.config.mail_username
            password = self.config.mail_password
            if username and password:
                logger.debug(f"Logging in with username: {username}")
                await self._smtp.login(username=username, password=password)
        # ensure that the connection is still alive
        if not self._smtp.is_connected:
            logger.debug("Reconnecting SMTP client")
            await self._smtp.connect()
        return self._smtp

    async def sendmail(self, sender: str, recipient: str, message: str, reference: str) -> Status:
        """
        Send mail

        :param sender: the From of the email
        :param recipient: the recipient of the email
        :param message: email.mime.multipart.MIMEMultipart message as a string
        :param reference: Audit reference to help cross-reference audit log and events
        """

        # Just log the mail if in development mode
        if self.config.environment == EduidEnvironment.dev:
            logger.info("sendmail task:")
            logger.info(
                f"\nType: email\nReference: {reference}\nSender: {sender}\nRecipient: {recipient}\n"
                f"Message:\n{message}"
            )
            return Status(success=True, message="Devel message printed")

        smtp_client = await self.smtp
        try:
            errors, response_message = await smtp_client.sendmail(sender, recipient, message)
        except SMTPException as e:
            logger.error(f"SMTPException: {e}")
            return Status(success=False, message=str(e), retry=True)

        if not errors:
            # mail sent successfully
            logger.debug(f"Mail to {recipient} sent successfully: {response_message}")
            return Status(success=True, message=response_message)

        # handle errors
        smtp_response = errors.get(recipient, SMTPResponse(0, "Unknown error"))
        logger.error(f"Error sending mail to {recipient}: {smtp_response.code} {smtp_response.message}")

        return_code = smtp_response.code // 100
        if return_code == 5:
            # 500, permanent error condition
            return Status(success=False, retry=False, message=smtp_response.message)
        elif return_code == 4:
            # 400, error condition is temporary, and the action may be requested again
            return Status(success=False, retry=True, message=smtp_response.message)
        else:
            # unknown error
            return Status(success=False, retry=False, message=smtp_response.message)

    async def handle_new_item(self, queue_item: QueueItem) -> None:
        status = None
        if queue_item.payload_type == EduidInviteEmail.get_type():
            status = await self.send_eduid_invite_mail(
                cast(
                    EduidInviteEmail,
                    queue_item.payload,
                )
            )
            logger.debug(f"send_eduid_invite_mail returned status: {status}")
        elif queue_item.payload_type == EduidSignupEmail.get_type():
            status = await self.send_eduid_signup_mail(
                cast(
                    EduidSignupEmail,
                    queue_item.payload,
                )
            )
            logger.debug(f"send_eduid_invite_mail returned status: {status}")
        elif queue_item.payload_type == OldEduidSignupEmail.get_type():
            status = await self.send_old_eduid_signup_mail(
                cast(
                    OldEduidSignupEmail,
                    queue_item.payload,
                )
            )
            logger.debug(f"send_eduid_invite_mail returned status: {status}")

        if status and status.retry:
            logger.info(f"Retrying queue item: {queue_item.item_id}")
            logger.debug(queue_item)
            await self.retry_item(queue_item)
            return

        await self.item_successfully_handled(queue_item)

    async def handle_expired_item(self, queue_item: QueueItem) -> None:
        logger.warning(f"Found expired item: {queue_item}")

    async def send_eduid_invite_mail(self, data: EduidInviteEmail) -> Status:
        msg = EmailMessage()
        with self._jinja2.select_language(data.language) as env:
            msg["Subject"] = _("eduID invitation")
            txt = env.get_template("eduid_invite_mail_txt.jinja2").render(**asdict(data))
            logger.debug(f"TXT: {txt}")
            html = env.get_template("eduid_invite_mail_html.jinja2").render(**asdict(data))
            logger.debug(f"HTML: {html}")
        msg.set_content(txt, "plain", "utf-8")
        msg.add_alternative(html, "html", "utf-8")

        return await self.sendmail(
            sender=self.config.mail_default_from,
            recipient=data.email,
            message=msg.as_string(),
            reference=data.reference,
        )

    async def send_eduid_signup_mail(self, data: EduidSignupEmail) -> Status:
        msg = EmailMessage()
        with self._jinja2.select_language(data.language) as env:
            msg["Subject"] = _("eduID registration")
            txt = env.get_template("eduid_signup_email.txt.jinja2").render(**asdict(data))
            logger.debug(f"TXT: {txt}")
            html = env.get_template("eduid_signup_email.html.jinja2").render(**asdict(data))
            logger.debug(f"HTML: {html}")
        msg.set_content(txt, "plain", "utf-8")
        msg.add_alternative(html, "html", "utf-8")

        return await self.sendmail(
            sender=self.config.mail_default_from,
            recipient=data.email,
            message=msg.as_string(),
            reference=data.reference,
        )

    # TODO: Remove this when we no longer need to send old signup emails
    async def send_old_eduid_signup_mail(self, data: OldEduidSignupEmail) -> Status:
        msg = EmailMessage()
        with self._jinja2.select_language(data.language) as env:
            msg["Subject"] = _("eduID registration")
            txt = env.get_template("old_eduid_signup_email.txt.jinja2").render(**asdict(data))
            logger.debug(f"TXT: {txt}")
            html = env.get_template("old_eduid_signup_email.html.jinja2").render(**asdict(data))
            logger.debug(f"HTML: {html}")
        msg.set_content(txt, "plain", "utf-8")
        msg.add_alternative(html, "html", "utf-8")

        return await self.sendmail(
            sender=self.config.mail_default_from,
            recipient=data.email,
            message=msg.as_string(),
            reference=data.reference,
        )


def init_mail_worker(name: str = "mail_worker", test_config: Optional[Mapping[str, Any]] = None) -> MailQueueWorker:
    config = load_config(typ=QueueWorkerConfig, app_name=name, ns="queue", test_config=test_config)
    return MailQueueWorker(config=config)


def start_worker():
    worker = init_mail_worker()
    exit(asyncio.run(worker.run()))


if __name__ == "__main__":
    start_worker()
