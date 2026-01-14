__author__ = "lundberg"


class TaskFailed(Exception):
    pass


class AmTaskFailed(TaskFailed):
    pass


class MsgTaskFailed(TaskFailed):
    pass


class NoAddressFound(MsgTaskFailed):
    pass


class NoRelationsFound(MsgTaskFailed):
    pass


class NoNavetData(MsgTaskFailed):
    pass


class LookupMobileTaskFailed(TaskFailed):
    pass
