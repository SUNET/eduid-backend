import logging
from uuid import UUID, uuid4

from eduid.common.config.base import DataOwnerName
from eduid.common.config.parsers import load_config
from eduid.graphdb.groupdb import Group as GraphGroup
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.testing import ScimApiTestCase
from eduid.userdb.scimapi import GroupExtensions, ScimApiGroup

logger = logging.getLogger(__name__)


class TestGroupDB(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.test_config = self._get_config()
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        self.context = Context(config=config)
        self.groupdb = self.context.get_groupdb("eduid.se")

        for i in range(9):
            self.add_group(uuid4(), f"Test Group-{i}")

    def tearDown(self) -> None:
        super().tearDown()
        assert self.groupdb is not None
        self.groupdb._drop_whole_collection()

    def add_group(self, scim_id: UUID, display_name: str, extensions: GroupExtensions | None = None) -> ScimApiGroup:
        if extensions is None:
            extensions = GroupExtensions()
        group = ScimApiGroup(scim_id=scim_id, display_name=display_name, extensions=extensions)
        assert self.groupdb  # mypy doesn't know setUp will be called
        group.graph = GraphGroup(identifier=str(group.scim_id), display_name=display_name)
        self.groupdb.save(group)
        logger.info(f"TEST saved group {group}")
        return group

    def test_full_search(self) -> None:
        assert self.groupdb is not None
        groups = self.groupdb.get_groups()
        self.assertEqual(len(groups), 9)

    def test_documents_and_count_first_page(self) -> None:
        assert self.groupdb is not None
        groups, count = self.groupdb._get_documents_and_count_by_filter(spec={}, limit=3)
        for x in groups:
            logger.info(f"Group {x}")
        self.assertEqual(len(groups), 3)
        self.assertEqual(count, 9)

    def test_documents_and_count_last_page(self) -> None:
        assert self.groupdb is not None
        groups, count = self.groupdb._get_documents_and_count_by_filter(spec={}, skip=6, limit=3)
        self.assertEqual(len(groups), 3)
        self.assertEqual(count, 9)

    def test_documents_and_count_partial_last_page(self) -> None:
        assert self.groupdb is not None
        groups, count = self.groupdb._get_documents_and_count_by_filter(spec={}, skip=8, limit=3)
        self.assertEqual(len(groups), 1)
        self.assertEqual(count, 9)
