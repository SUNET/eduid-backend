# -*- coding: utf-8 -*-

from enum import unique

from eduid.webapp.common.api.messages import TranslatableMsg

__author__ = 'lundberg'


@unique
class LadokMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    no_verified_nin = 'ladok.no-verified-nin'
    no_ladok_data = 'ladok.no-data-for-user'
    user_linked = 'ladok.user-linked-successfully'
    user_unlinked = 'ladok.user-unlinked-successfully'
