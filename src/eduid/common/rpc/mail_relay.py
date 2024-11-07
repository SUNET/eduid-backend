import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import eduid.workers.msg
from eduid.common.config.base import MailConfigMixin
from eduid.common.rpc.exceptions import MailTaskFailed

logger = logging.getLogger(__name__)


class MailRelay:
    """
    This is the interface to the RPC task to send e-mail.
    """

    def __init__(self, config: MailConfigMixin) -> None:
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
        recipients: list[str],
        text: str | None = None,
        html: str | None = None,
        reference: str | None = None,
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
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.mail_from
        msg["To"] = ", ".join(recipients)
        if text:
            msg.attach(MIMEText(text, "plain", "utf-8"))
        if html:
            msg.attach(MIMEText(html, "html", "utf-8"))

        logger.debug(f"About to send email:\n\n {msg.as_string()}")
        rtask = self._sendmail.apply_async(args=[self.mail_from, recipients, msg.as_string(), reference])

        try:
            res = rtask.get(timeout=timeout)
            logger.info(f"email with reference {reference} sent. Task result: {res}")
        except Exception as e:
            rtask.forget()
            raise MailTaskFailed(f"sendmail task failed: {repr(e)}")

        logger.info(f"Sent email {rtask} to {recipients} with subject {subject}")
        return None

    def ping(self, timeout: int = 1) -> str:
        """
        Check if this application is able to reach an AM worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.apply_async(kwargs={"app_name": self.app_name})
        try:
            return rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise MailTaskFailed(f"ping task failed: {repr(e)}")
