from __future__ import absolute_import

from celery import Task
from celery.utils.log import get_task_logger

from pkg_resources import iter_entry_points

import bson

from eduid_msg.celery import celery
from eduid_msg.exceptions import MessageException

logger = get_task_logger(__name__)

class SMSRelay(Task):
    abstract = True
    _sms = None 

    @property
    def sms(self):
        if self._sms is None:
            self._sms = SMSClient(self.app.conf.get("SMS_ACC"),self.app.conf.get("SMS_PASSWORD"))
            self._sender = self.app.conf.get("SMS_SENDER")
        return self._sms


@celery.task(ignore_results=True,base=SMSRelay)
def send(msg,to):
    self = send
    self.sms.send(msg,self._sender,to,prio=2)
