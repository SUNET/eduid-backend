# -*- coding: utf-8 -*-

from flask.json import JSONEncoder
import time
from datetime import datetime

__author__ = 'lundberg'


class EduidJSONEncoder(JSONEncoder):

    def default(self, obj):
        try:
            if isinstance(obj, datetime):
                if obj.utcoffset() is not None:
                    obj = obj - obj.utcoffset()
                return int(time.mktime(obj.timetuple()))
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        return JSONEncoder.default(self, obj)
