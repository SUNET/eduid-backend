import signal

from typing import List
from eduid.userdb.user import User
from pydantic import BaseModel


class Shutdown(BaseModel):
    now = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self):
        self.now = True


class UserHandling(BaseModel):
    users: List[User]

    def __iter__(self):
        return iter(self.users)

    def __getitem__(self, item):
        return self.users[item]

    def fetch_users(self, cleaning_type: str):
        pass


class ServiceSKV(Shutdown, UserHandling):
    def run(self):
        for user in self.users:
            if Shutdown.now:
                break
        pass


if __name__ == "__main__":
    ServiceSKV().run()
