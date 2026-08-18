from typing import cast
from unittest.mock import MagicMock

import pytest

from eduid.common.config.parsers import load_config
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context, DataOwnerDatabases
from eduid.scimapi.testing import ScimApiTestCase


class TestContext(ScimApiTestCase):
    def test_init(self) -> None:
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        ctx = Context(config=config)
        assert ctx.base_url == "http://localhost:8000"

    def test_load_many_data_owners(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_load_data_owner_dbs(ctx: Context, data_owner: str) -> None:
            ctx._dbs[data_owner] = DataOwnerDatabases(
                data_owner=data_owner,
                userdb=cast(object, MagicMock()),
                groupdb=cast(object, MagicMock()),
                invitedb=cast(object, MagicMock()),
                eventdb=cast(object, MagicMock()),
            )

        # Add 99 more data owners to the config
        for i in range(99):
            self.test_config["data_owners"][f"owner{i}"] = {"db_name": f"owner_{i}"}
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        assert len(self.test_config["data_owners"]) == 100

        monkeypatch.setattr(Context, "_load_data_owner_dbs", fake_load_data_owner_dbs)

        ctx = Context(config=config)
        assert len(ctx._dbs) == 0  # no databases loaded at startup

        # load default data owner databases
        ctx.get_userdb(self.data_owner)
        ctx.get_groupdb(self.data_owner)
        ctx.get_invitedb(self.data_owner)
        ctx.get_eventdb(self.data_owner)
        assert len(ctx._dbs) == 1

        # simulate requests that load many data owners — eviction should kick in
        for i in range(99):
            ctx.get_userdb(f"owner{i}")
            ctx.get_groupdb(f"owner{i}")
            ctx.get_invitedb(f"owner{i}")
            ctx.get_eventdb(f"owner{i}")
        assert len(ctx._dbs) == config.max_loaded_data_owner_dbs
        assert "owner98" in ctx._dbs
        assert self.data_owner not in ctx._dbs

        # verify we can reload an evicted data owner
        ctx.get_userdb(self.data_owner)
        assert len(ctx._dbs) == config.max_loaded_data_owner_dbs
        assert self.data_owner in ctx._dbs
