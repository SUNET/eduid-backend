from eduid.common.config.base import DataOwnerName
from eduid.common.config.parsers import load_config
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.testing import ScimApiTestCase


class TestContext(ScimApiTestCase):
    def test_init(self):
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        ctx = Context(config=config)
        self.assertEqual(ctx.base_url, "http://localhost:8000")

    def test_load_many_data_owners(self):
        # Add 99 more data owners to the config
        for i in range(99):
            self.test_config["data_owners"][f"owner{i}"] = {"db_name": f"owner_{i}"}
        self.test_config["max_loaded_data_owner_dbs"] = 3
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        assert len(self.test_config["data_owners"]) == 100

        ctx = Context(config=config)
        assert len(ctx._dbs) == 0  # no databases loaded at startup

        # simulate a request to load the databases
        for i in range(99):
            ctx.get_userdb(DataOwnerName(f"owner{i}"))
            ctx.get_groupdb(DataOwnerName(f"owner{i}"))
            ctx.get_invitedb(DataOwnerName(f"owner{i}"))
            ctx.get_eventdb(DataOwnerName(f"owner{i}"))
            assert len(ctx._dbs) <= ctx.config.max_loaded_data_owner_dbs
