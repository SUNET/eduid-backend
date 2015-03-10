__author__ = 'mathiashedstrom'

_nins = ['200202025678', '197512125432', '195010106543', '190001019876']
_mobiles = [['+46700011222'], ['+46700011333', '+46700011777'], ['+46700011444'], ['+46700011555', '+46700011666']]

def get_mobile(nin):
    if nin not in _nins:
        return []

    return _mobiles[_nins.index(nin)]


def get_nin(mobile):

    index = 0
    for mobile_list in _mobiles:
        if mobile in mobile_list:
            return _nins[index]
        index += 1

    return None