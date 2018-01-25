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

from copy import deepcopy

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app
from eduid_msg.celery import celery, get_mail_relay
from eduid_msg.tasks import sendmail
from eduid_common.api.exceptions import MailTaskFailed


class MailRelay(object):

    def __init__(self, settings):
        celery.conf.update(settings)
        self._relay = get_mail_relay(celery)
        self.settings = settings
        self._sendmail = sendmail

    def sendmail(self, subject, recipients, text=None, html=None):
        """
        :param subject: Message subject
        :type subject: six.string_types
        :param recipients: List of recipients
        :type recipients: list
        :param text: Message in text format
        :type text: six.string_types
        :param html: Message in html format
        :type html: six.string_types
        """
        sender = current_app.config.get("MAIL_DEFAULT_SENDER")
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)
        if text:
            msg.attach(MIMEText(text, 'plain'))
        if html:
            msg.attach(MIMEText(html, 'html'))

        current_app.logger.debug('About to send email:\n\n {}'.format(msg.as_string()))

        try:
            rtask = self._sendmail.apply_async(sender, recipients, msg)
        except Exception as e:
            err = 'Error sending mail: {!r}'.format(e)
            current_app.logger.error(err)
            raise MailTaskFailed(err)

        current_app.logger.info('Sent email {} to {} with subject {}'.format(rtask, recipients, subject))


def init_relay(app):
    """
    :param app: Flask app
    :type app: flask.Flask
    :return: Flask app
    :rtype: flask.Flask
    """
    config = deepcopy(app.config['CELERY_CONFIG'])
    config['BROKER_URL'] = app.config.get('MSG_BROKER_URL', '')
    app.mail_relay = MailRelay(config)
    return app
