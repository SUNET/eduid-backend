# -*- coding: utf-8 -*-

import asyncio
import logging
from random import randint
from typing import Optional, cast

from eduid_userdb.q import QueueItem, TestPayload
from eduid_userdb.q.message import EduidInviteEmail

from eduid_queue.db import ChangeEvent

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


async def slow_print(queue_item: QueueItem):
    delay = randint(2, 5)
    await asyncio.sleep(delay)
    if isinstance(queue_item.payload, TestPayload):
        message = queue_item.payload.message
        print(f'{message} slept {delay}: {queue_item}')
        return True
    return False


async def sendmail(sender: str, recipients: list, message: str, reference: str) -> dict:
    """
    Send mail

    :param sender: the From of the email
    :param recipients: the recipients of the email
    :param message: email.mime.multipart.MIMEMultipart message as a string
    :param reference: Audit reference to help cross reference audit log and events

    :return Dict of errors
    """

    # Just log the mail if in development mode
    # TODO: Needs config
    devel_mode = True
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


async def send_eduid_invite_mail(data: EduidInviteEmail):
    # TODO: Needs config
    sender = 'noreply@eduid.se'
    message = f'something something from {data.inviter_name}'
    await sendmail(sender=sender, recipients=[data.email], message=message, reference=data.reference)


async def process_item(item: QueueItem) -> QueueItem:
    if item.payload_type == TestPayload.get_type():
        await slow_print(item)
    elif item.payload_type == EduidInviteEmail.get_type():
        await send_eduid_invite_mail(
            cast(
                EduidInviteEmail,
                item.payload,
            )
        )
    return item
