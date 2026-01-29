from eduid.common.config.parsers import load_config
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.testing import ScimApiTestCase


class TestContext(ScimApiTestCase):
    def test_init(self) -> None:
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        ctx = Context(config=config)
        self.assertEqual(ctx.base_url, "http://localhost:8000")

    def test_load_many_data_owners(self) -> None:
        # Add 99 more data owners to the config
        for i in range(99):
            self.test_config["data_owners"][f"owner{i}"] = {"db_name": f"owner_{i}"}
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        assert len(self.test_config["data_owners"]) == 100

        ctx = Context(config=config)
        assert len(ctx._dbs) == 0  # no databases loaded at startup

        # load default data owner databases
        ctx.get_userdb(self.data_owner)
        ctx.get_groupdb(self.data_owner)
        ctx.get_invitedb(self.data_owner)
        ctx.get_eventdb(self.data_owner)
        assert len(ctx._dbs) == 1

        # simulate a request to load the databases
        for i in range(99):
            ctx.get_userdb(f"owner{i}")
            ctx.get_groupdb(f"owner{i}")
            ctx.get_invitedb(f"owner{i}")
            ctx.get_eventdb(f"owner{i}")
        assert len(ctx._dbs) == 100
