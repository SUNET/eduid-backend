#
# Copyright (c) 2016 NORDUnet A/S
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
#     3. Neither the name of the NORDUnet nor the names of its
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
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

import eduid.workers.msg
from eduid.common.config.base import MailConfigMixin
from eduid.common.rpc.exceptions import MailTaskFailed

logger = logging.getLogger(__name__)


class MailRelay(object):
    """
    This is the interface to the RPC task to send e-mail.
    """

    def __init__(self, config: MailConfigMixin):
        self.app_name = config.app_name
        self.mail_from = config.mail_default_from
        eduid.workers.msg.init_app(config.celery)
        # this import has to happen _after_ init_app
        from eduid.workers.msg.tasks import pong, sendmail

        self._sendmail = sendmail
        self._pong = pong

    def sendmail(
        self,
        subject: str,
        recipients: List[str],
        text: Optional[str] = None,
        html: Optional[str] = None,
        reference: Optional[str] = None,
        timeout: int = 25,
    ) -> None:
        """
        :param subject: Message subject
        :param recipients: List of recipients
        :param text: Message in text format
        :param html: Message in html format
        :param reference: Audit reference to help cross reference audit log and events
        :param timeout: Max wait time for task to finish
        """
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.mail_from
        msg['To'] = ', '.join(recipients)
        if text:
            msg.attach(MIMEText(text, 'plain', 'utf-8'))
        if html:
            msg.attach(MIMEText(html, 'html', 'utf-8'))

        logger.debug(f'About to send email:\n\n {msg.as_string()}')
        rtask = self._sendmail.apply_async(args=[self.mail_from, recipients, msg.as_string(), reference])

        try:
            res = rtask.get(timeout=timeout)
            logger.info(f'email with reference {reference} sent. Task result: {res}')
        except Exception as e:
            rtask.forget()
            raise MailTaskFailed(f'sendmail task failed: {repr(e)}')

        logger.info(f'Sent email {rtask} to {recipients} with subject {subject}')
        return None

    def ping(self, timeout: int = 1) -> str:
        """
        Check if this application is able to reach an AM worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.apply_async(kwargs={'app_name': self.app_name})
        try:
            return rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise MailTaskFailed(f'ping task failed: {repr(e)}')
