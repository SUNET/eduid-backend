import time
from typing import Optional, Dict

from eduid.common.models.amapi_user import UserUpdateNameRequest
from eduid.common.rpc.msg_relay import NavetData
from eduid.common.utils import set_user_names_from_official_address
from eduid.userdb import User
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType
from eduid.workers.user_cleaner.app import WorkerBase


class SKV(WorkerBase):
    def __init__(self, cleaner_type: CleanerType, test_config: Optional[Dict] = None):
        super().__init__(cleaner_type=cleaner_type.SKV, test_config=test_config)

    def update_name(self, user: User, navet_data: NavetData):
        self.logger.debug(f"number of changes: {self.made_changes} out of max_changes: {self.max_changes}, queue_actual_size: {self.queue_actual_size}")

        if navet_data.person.name.given_name is None or navet_data.person.name.surname is None:
            self.logger.info(f"No given_name or surname found in navet for eppn: {user.eppn}")
            return
        if user.given_name == navet_data.person.name.given_name and user.surname == navet_data.person.name.surname:
            self.logger.info(f"No update for names for eppn: {user.eppn}")
            return

        updated_user = set_user_names_from_official_address(
            user=user, user_postal_address=navet_data.get_full_postal_address()
        )

        self._add_to_made_changes()

        self.logger.debug(f"number of changes: {self.made_changes} out of {self.max_changes}, {self.queue_actual_size}")

        amapi_client_body =UserUpdateNameRequest(
                    reason="SKV_NAME_UPDATE",
                    source=CleanerType.SKV.value,
                    given_name=updated_user.given_name,
                    display_name=updated_user.display_name,
                    surname=updated_user.surname,
        )

        if self.config.dry_run:
            self.logger.debug(f"dry_run: eppn: {user.eppn}, amapi_client_body: {amapi_client_body}")
        else:
            self.amapi_client.update_user_name(
                user=user.eppn,
                body=amapi_client_body,
            )

    def run(self):
        while not self.shutdown_now:
            if self._is_quota_reached():
                self.logger.warning(f"worker skatteverket has reached its change_quota, sleep for 20 seconds")
                self._make_unhealthy()
                time.sleep(20.0)
            else:
                self._make_healthy()
                if self.queue.empty():
                    self.enqueuing(
                        cleaning_type=CleanerType.SKV,
                        identity_type=IdentityType.NIN,
                        limit=self.config.user_count,
                    )
                user = self.queue.get()

                navet_data = self.msg_relay.get_all_navet_data(nin=user.identities.nin.number)

                self.update_name(user=user, navet_data=navet_data)

                time.sleep(self.config.job_delay)

                self.queue.task_done()


def init_skv_worker(test_config: Optional[Dict] = None) -> SKV:
    worker = SKV(cleaner_type=CleanerType.SKV, test_config=test_config)
    return worker


def start_worker():
    worker = init_skv_worker()
    worker.run()


if __name__ == "__main__":
    start_worker()
