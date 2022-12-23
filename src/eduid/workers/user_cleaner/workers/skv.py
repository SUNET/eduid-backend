import time
from typing import Any, Optional, Dict

from eduid.common.models.amapi_user import UserUpdateNameRequest, Reason, Source
from eduid.common.rpc.msg_relay import NavetData
from eduid.common.utils import set_user_names_from_official_address
from eduid.userdb import User
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType
from eduid.workers.user_cleaner.app import WorkerBase


class SKV(WorkerBase):
    """Worker class for Skatteverket"""

    def __init__(self, test_config: Optional[Dict] = None):
        super().__init__(cleaner_type=CleanerType.SKV, identity_type=IdentityType.NIN, test_config=test_config)

    def update_name(self, queue_user: dict[str, Any], navet_data: NavetData) -> None:
        """
        Update-function for updating "given name" and "surname" from skatteverket, and creates new "display name" if needed.
        """

        db_user = self.db.get_user_by_eppn(eppn=queue_user["eppn"])
        if db_user is None:
            return

        self.logger.debug(
            f"number of changes: {self.made_changes} out of max_changes: {self.max_changes}, queue_actual_size: {self.queue_actual_size}"
        )

        if navet_data.person.name.given_name is None or navet_data.person.name.surname is None:
            self.logger.info(f"No given_name or surname found in navet for eppn: {db_user.eppn}")
            return

        if (
            db_user.given_name == navet_data.person.name.given_name
            and db_user.surname == navet_data.person.name.surname
        ):
            self.logger.info(f"No update for names for eppn: {db_user.eppn}")
            return

        updated_user = set_user_names_from_official_address(
            user=db_user, user_postal_address=navet_data.get_full_postal_address()
        )

        self._add_to_made_changes()

        self.logger.debug(f"number of changes: {self.made_changes} out of {self.max_changes}, {self.queue_actual_size}")

        amapi_client_body = UserUpdateNameRequest(
            reason=Reason.NAME_CHANGED.value,
            source=Source.SKV_NAVET_V2.value,
            given_name=updated_user.given_name,
            display_name=updated_user.display_name,
            surname=updated_user.surname,
        )

        if self.config.dry_run:
            self.logger.debug(f"dry_run: eppn: {db_user.eppn}, amapi_client_body: {amapi_client_body}")
        else:
            self.amapi_client.update_user_name(
                user=db_user.eppn,
                body=amapi_client_body,
            )

    def run(self):
        """skatteverket worker entry point"""
        while not self.shutdown_now:
            if self._is_quota_reached():
                self.logger.warning(f"worker skatteverket has reached its change_quota, sleep for 20 seconds")
                self._make_unhealthy()
                self._sleep(milliseconds=20000)

            self._make_healthy()
            if self.queue.empty():
                self.enqueuing()
            queue_user = self.queue.get()

            navet_data = self.msg_relay.get_all_navet_data(nin=queue_user["nin"])

            self.update_name(queue_user=queue_user, navet_data=navet_data)

            self.queue.task_done()

            self._sleep(milliseconds=self.execution_delay)


def init_skv_worker(test_config: Optional[dict[str, Any]] = None) -> SKV:
    """Initialize skv (skatteverket) worker"""
    worker = SKV(test_config=test_config)
    return worker


def start_worker():
    """Start skv (skatteverket) worker"""
    worker = init_skv_worker()
    worker.run()


if __name__ == "__main__":
    start_worker()
