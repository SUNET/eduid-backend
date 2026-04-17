from typing import TYPE_CHECKING

__all__ = ["Task"]

if TYPE_CHECKING:
    from celery import Task
else:
    from celery import Task as _CeleryTask

    class Task(_CeleryTask):
        def __class_getitem__(cls, item: object) -> type["Task"]:
            return cls
