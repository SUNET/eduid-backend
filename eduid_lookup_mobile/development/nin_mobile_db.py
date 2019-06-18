__author__ = 'mathiashedstrom'

_db = {'200202027140': ['+46700011222'],
       '197512126371': ['+46700011333', '+46700011777'],
       '195010101631': ['+46700011444'],
       '190001019876': ['+46700011555', '+46700011666']
       }


def get_mobile(nin):
    return _db.get(nin, [])


def get_nin(mobile):
    for nin, numbers in _db.items():
        if mobile in numbers:
            return nin
    return None
