# -*- coding: utf-8 -*-

import logging
from typing import Optional, cast

from eduid_common.config.workers import QueueWorkerConfig
from eduid_userdb.q import QueueItem, TestPayload
from eduid_userdb.q.message import EduidInviteEmail

from eduid_queue.misc import slow_print
from eduid_queue.workers.base import QueueWorker

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class MailQueueWorker(QueueWorker):
    def __init__(self, app_name: str, test_config: Optional[dict] = None):
        worker_config = QueueWorkerConfig.init_config(ns='queue', app_name=app_name, test_config=test_config)
        # Register which queue items this worker should try to grab
        payloads = [TestPayload, EduidInviteEmail]
        super().__init__(config=worker_config, handle_payloads=payloads)

    async def handle_new_item(self, queue_item: QueueItem) -> QueueItem:
        if queue_item.payload_type == TestPayload.get_type():
            await slow_print(queue_item)
        elif queue_item.payload_type == EduidInviteEmail.get_type():
            await self.send_eduid_invite_mail(
                cast(
                    EduidInviteEmail,
                    queue_item.payload,
                )
            )
        return queue_item

    async def handle_expired_item(self, queue_item: QueueItem) -> QueueItem:
        raise NotImplementedError()

    async def send_eduid_invite_mail(self, data: EduidInviteEmail):
        sender = self.config.mail_default_from
        #
        message = f'something something from {data.inviter_name}'
        await self.sendmail(sender=sender, recipients=[data.email], message=message, reference=data.reference)

    async def sendmail(self, sender: str, recipients: list, message: str, reference: str) -> dict:
        """
        Send mail

        :param sender: the From of the email
        :param recipients: the recipients of the email
        :param message: email.mime.multipart.MIMEMultipart message as a string
        :param reference: Audit reference to help cross reference audit log and events

        :return Dict of errors
        """

        # Just log the mail if in development mode
        devel_mode = self.config.devel_mode
        if devel_mode is True:
            logger.debug('sendmail task:')
            logger.debug(
                f"\nType: email\nReference: {reference}\nSender: {sender}\nRecipients: {recipients}\n"
                f"Message:\n{message}"
            )
            return {'devel_mode': True}

        # TODO: Needs instantiated smtplib.SMTP
        # ret = smtp.sendmail(sender, recipients, message)

        # return ret
