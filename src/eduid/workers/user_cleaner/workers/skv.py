from typing import Any, Mapping, Optional
from time import time

from eduid.common.models.amapi_user import UserUpdateNameRequest, Reason, Source
from eduid.common.rpc.msg_relay import NavetData
from eduid.common.utils import set_user_names_from_official_address
from eduid.userdb.identity import IdentityType
from eduid.userdb.meta import CleanerType
from eduid.workers.user_cleaner.app import WorkerBase
from eduid.userdb.user_cleaner.cache import CacheUser
from eduid.userdb.user_cleaner.cachedb import CacheDB
from eduid.userdb.user_cleaner.metadb import MetaDB
from eduid.userdb.user_cleaner.meta import Meta


class SKV(WorkerBase):
    """Worker class for Skatteverket"""

    def __init__(self, test_config: Optional[Mapping[str, Any]] = None):
        super().__init__(cleaner_type=CleanerType.SKV, identity_type=IdentityType.NIN, test_config=test_config)
        self.db_cache = CacheDB(db_uri=self.config.mongo_uri, collection="skv_cache")
        self.db_meta = MetaDB(db_uri=self.config.mongo_uri)

    def update_name(self, queue_user: CacheUser, navet_data: NavetData) -> None:
        """
        Update-function for updating "given name" and "surname" from skatteverket, and creates new "display name" if needed.
        """

        db_user = self.db.get_user_by_eppn(eppn=queue_user.eppn)
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
        if not self.db_meta.exist(cleaner_type=self.cleaner_type):
            # if self.db_meta.get(self.cleaner_type) is None:
            meta = Meta(
                periodicity=self.config.periodicity,
                cleaner_type=self.cleaner_type,
            )
            self.db_meta.save(doc=meta)

        meta = self.db_meta.get(self.cleaner_type)
        if meta.periodicity != self.config.periodicity:
            meta.periodicity = self.config.periodicity
            self.db_meta.save(doc=meta)

            self.db_cache.delete_all()

        while not self.shutdown_now:
            if self._is_quota_reached():
                self.logger.warning(f"worker skatteverket has reached its change_quota, sleep for 20 seconds")
                self._make_unhealthy()
                self._sleep(seconds=20000)

            self._make_healthy()

            if self.db_cache.is_empty():
                users = self.db.get_uncleaned_verified_users(
                    cleaned_type=self.cleaner_type,
                    identity_type=self.identity_type,
                    limit=10000000,
                )
                self.db_cache.populate(am_users=users, periodicity=self.config.periodicity)

            if self.worker_queue.empty():
                self._enqueuing_to_worker_queue()
            queue_user = CacheUser.from_dict(self.worker_queue.get())

            if self._wait(user=queue_user):
                db_user = self.db.get_user_by_eppn(eppn=queue_user.eppn)
                if db_user.identities.nin is not None and db_user.identities.nin.is_verified:
                    navet_data = self.msg_relay.get_all_navet_data(nin=db_user.identities.nin.number)

                    # update name if needed against navet.
                    self.update_name(queue_user=queue_user, navet_data=navet_data)

                self.task_done(eppn=queue_user.eppn)
            else:
                self.worker_queue.put(queue_user.to_dict())


def init_skv_worker(test_config: Optional[Mapping[str, Any]] = None) -> SKV:
    """Initialize skv (skatteverket) worker"""
    worker = SKV(test_config=test_config)
    return worker


def start_worker():
    """Start skv (skatteverket) worker"""
    worker = init_skv_worker()
    worker.run()


if __name__ == "__main__":
    start_worker()
