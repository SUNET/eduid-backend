# -*- coding: utf-8 -*-

import time

__author__ = 'lundberg'


def nin_to_age(nin):
    """
    :param nin: National Identity Number
    :type nin: six.string_types
    :return: Age
    :rtype: int
    """
    current_year = int(time.strftime("%Y"))
    current_month = int(time.strftime("%m"))
    current_day = int(time.strftime("%d"))

    birth_year = int(nin[:4])
    birth_month = int(nin[4:6])
    birth_day = int(nin[6:8])

    age = current_year - birth_year

    if current_month < birth_month or (current_month == birth_month and current_day < birth_day):
        age -= 1

    return age
