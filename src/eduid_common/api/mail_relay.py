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

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

from flask import current_app

import eduid_msg

from eduid_common.api.app import EduIDBaseApp
from eduid_common.api.exceptions import MailTaskFailed


class MailRelay(object):
    def __init__(self, settings):
        self.settings = settings
        eduid_msg.init_app(settings)
        # this import has to happen _after_ init_app
        from eduid_msg.tasks import pong, sendmail

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
    ):
        """
        :param subject: Message subject
        :param recipients: List of recipients
        :param text: Message in text format
        :param html: Message in html format
        :param reference: Audit reference to help cross reference audit log and events
        :param timeout: Max wait time for task to finish
        """
        sender = current_app.config["MAIL_DEFAULT_FROM"]
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)
        if text:
            msg.attach(MIMEText(text, 'plain', 'utf-8'))
        if html:
            msg.attach(MIMEText(html, 'html', 'utf-8'))

        current_app.logger.debug(u'About to send email:\n\n {}'.format(msg.as_string()))
        rtask = self._sendmail.apply_async(args=[sender, recipients, msg.as_string(), reference])

        try:
            res = rtask.get(timeout=timeout)
            current_app.logger.info('SMS with reference {} sent. Task result: {}'.format(reference, res))
        except Exception as e:
            rtask.forget()
            raise MailTaskFailed(f'sendmail task failed: {repr(e)}')

        current_app.logger.info(u'Sent email {} to {} with subject {}'.format(rtask, recipients, subject))

    def ping(self):
        rtask = self._pong.delay()
        result = rtask.get(timeout=1)
        return result


def init_relay(app: EduIDBaseApp) -> None:
    """
    :param app: Flask app
    """
    app.mail_relay = MailRelay(app.config['CELERY_CONFIG'])
    return None
