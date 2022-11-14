import logging
import time

from eduid.userdb import User


def consume(user: User, logger: logging):
    print("user", user)
    time.sleep(5)
    f = open("/tmp/cleaner.txt", "a")
    f.write(user.eppn)
    f.close()
