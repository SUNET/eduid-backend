__author__ = "mathiashedstrom"

# PTS number series without subscribers
# https://www.pts.se/sv/bransch/telefoni/nummer-och-adressering/telefonnummer-for-anvandning-i-bocker-och-filmer-etc/
#  0701740605 - 0701740699

_db = {
    "200202027140": ["+46701740610"],
    "197512126371": ["+46701740608", "+46701740609"],
    "195010101631": ["+46701740607"],
    "190001019876": ["+46701740605", "+46701740606"],
}


def get_mobile(nin: str) -> list[str]:
    return _db.get(nin, [])


def get_nin(mobile: str) -> str | None:
    for nin, numbers in _db.items():
        if mobile in numbers:
            return nin
    return None
