import asyncio
import logging
from dataclasses import asdict
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from gettext import gettext as _
from typing import Any, Optional, Type, cast
from collections.abc import Mapping, Sequence

from aiosmtplib import SMTP, SMTPException, SMTPResponse

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
        payloads: Sequence[type[Payload]] = [EduidInviteEmail, EduidSignupEmail, OldEduidSignupEmail]
        super().__init__(config=config, handle_payloads=payloads)

        self._smtp: Optional[SMTP] = None
        self._jinja2 = Jinja2Env()

    @property
    async def smtp(self):
        if self._smtp is None:
            logger.debug(f"Creating SMTP client for {self.config.mail_host}:{self.config.mail_port}")
            validate_certs = self.config.mail_verify_tls
            if not validate_certs:
                logger.warning("Disabling TLS certificate hostname verification")

            self._smtp = SMTP(
                hostname=self.config.mail_host,
                port=self.config.mail_port,
                start_tls=False,
                validate_certs=validate_certs,
            )
            await self._smtp.connect()

            # starttls
            if self.config.mail_starttls:
                keyfile = self.config.mail_keyfile
                certfile = self.config.mail_certfile
                if keyfile and certfile:
                    logger.debug(f"Starting TLS with keyfile: {keyfile} and certfile: {certfile}")
                    await self._smtp.starttls(client_key=keyfile, client_cert=certfile, validate_certs=validate_certs)
                else:
                    logger.debug("Starting TLS")
                    await self._smtp.starttls(validate_certs=validate_certs)

            # login
            username = self.config.mail_username
            password = self.config.mail_password
            if username and password:
                logger.debug(f"Logging in with username: {username}")
                await self._smtp.login(username=username, password=password)
        # ensure that the connection is still alive
        if not self._smtp.is_connected:
            logger.debug("Reconnecting SMTP client")
            self._smtp = None
            return await self.smtp
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

    async def _create_base_message(self) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = self.config.mail_default_from
        msg["Date"] = formatdate()
        msg["Message-ID"] = make_msgid(domain=self.config.mail_default_domain)
        return msg

    async def send_eduid_invite_mail(self, data: EduidInviteEmail) -> Status:
        msg = await self._create_base_message()
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
        msg = await self._create_base_message()
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
        msg = await self._create_base_message()
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
    if worker.smtp is None:
        # fail fast if we can't connect to the SMTP server
        raise RuntimeError("SMTP client not configured correctly")
    exit(asyncio.run(worker.run()))


if __name__ == "__main__":
    start_worker()
