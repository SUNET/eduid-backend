# -*- coding: utf-8 -*-
import asyncio
import logging
from dataclasses import asdict
from email.message import EmailMessage
from gettext import gettext as _
from typing import Any, Mapping, Optional, cast

from aiosmtplib import SMTP, SMTPResponse

from eduid.common.config.parsers import load_config

from eduid.queue.config import QueueWorkerConfig
from eduid.queue.db import QueueItem
from eduid.queue.db.message import EduidInviteEmail
from eduid.queue.db.queue_item import Status
from eduid.queue.helpers import Jinja2Env
from eduid.queue.workers.base import QueueWorker

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class MailQueueWorker(QueueWorker):
    def __init__(self, config: QueueWorkerConfig):
        # Register which queue items this worker should try to grab
        payloads = [EduidInviteEmail]
        super().__init__(config=config, handle_payloads=payloads)

        self._smtp: Optional[SMTP] = None
        self._jinja2 = Jinja2Env()

    @property
    async def smtp(self):
        if self._smtp is None:
            self._smtp = SMTP(hostname=self.config.mail_host, port=self.config.mail_port)
            if self.config.mail_starttls:
                keyfile = self.config.mail_keyfile
                certfile = self.config.mail_certfile
                if keyfile and certfile:
                    await self._smtp.starttls(client_key=keyfile, client_cert=certfile)
                else:
                    await self._smtp.starttls()
            username = self.config.mail_username
            password = self.config.mail_password
            if username and password:
                await self._smtp.login(username=username, password=password)
        return self._smtp

    async def sendmail(self, sender: str, recipients: list, message: str, reference: str) -> SMTPResponse:
        """
        Send mail

        :param sender: the From of the email
        :param recipients: the recipients of the email
        :param message: email.mime.multipart.MIMEMultipart message as a string
        :param reference: Audit reference to help cross reference audit log and events

        :return SMTPResponse
        """

        # Just log the mail if in development mode
        devel_mode = self.config.devel_mode
        if devel_mode is True:
            logger.debug('sendmail task:')
            logger.debug(
                f"\nType: email\nReference: {reference}\nSender: {sender}\nRecipients: {recipients}\n"
                f"Message:\n{message}"
            )
            return SMTPResponse(code=221, message='Devel message printed')

        async with self.smtp as smtp_client:
            ret = await smtp_client.sendmail(sender, recipients, message)
        return ret

    async def handle_new_item(self, queue_item: QueueItem) -> None:
        status = None
        if queue_item.payload_type == EduidInviteEmail.get_type():
            status = await self.send_eduid_invite_mail(cast(EduidInviteEmail, queue_item.payload,))
            logger.debug(f'send_eduid_invite_mail returned status: {status}')

        if status and status.retry:
            logger.info(f'Retrying queue item: {queue_item.item_id}')
            logger.debug(queue_item)
            await self.retry_item(queue_item)
            return

        await self.item_successfully_handled(queue_item)

    async def handle_expired_item(self, queue_item: QueueItem) -> None:
        logger.warning(f'Found expired item: {queue_item}')

    async def send_eduid_invite_mail(self, data: EduidInviteEmail) -> Status:
        msg = EmailMessage()
        with self._jinja2.select_language(data.language) as env:
            msg['Subject'] = _('eduID invitation')
            txt = env.get_template('eduid_invite_mail_txt.jinja2').render(**asdict(data))
            logger.debug(f'TXT: {txt}')
            html = env.get_template('eduid_invite_mail_html.jinja2').render(**asdict(data))
            logger.debug(f'HTML: {html}')
        msg.set_content(txt, 'plain', 'utf-8')
        msg.add_alternative(html, 'html', 'utf-8')

        ret = await self.sendmail(
            sender=self.config.mail_default_from,
            recipients=[data.email],
            message=msg.as_string(),
            reference=data.reference,
        )

        return_code = ret.code // 100
        if return_code == 5:
            # 500, permanent error condition
            return Status(success=False, retry=False, message=ret.message)
        elif return_code == 4:
            # 400, error condition is temporary, and the action may be requested again
            return Status(success=False, retry=True, message=ret.message)
        return Status(success=True, message=ret.message)


def init_mail_worker(name: str = 'mail_worker', test_config: Optional[Mapping[str, Any]] = None) -> MailQueueWorker:
    config = load_config(typ=QueueWorkerConfig, app_name=name, ns='queue', test_config=test_config)
    return MailQueueWorker(config=config)


def start_worker():
    worker = init_mail_worker()
    exit(asyncio.run(worker.run()))
