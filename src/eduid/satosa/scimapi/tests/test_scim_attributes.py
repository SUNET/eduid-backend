import pytest
from pytest_mock import MockerFixture

from eduid.satosa.scimapi.scim_attributes import Config, ScimAttributes

__author__ = "lundberg"


def make_scim_attributes(config: Config) -> ScimAttributes:
    """
    Build a bare ScimAttributes instance for testing get_groupdb_for_data_owner, without going
    through satosa's ResponseMicroService.__init__ or connecting to any real database - both of
    which are irrelevant to the behaviour under test here.
    """
    instance = ScimAttributes.__new__(ScimAttributes)
    instance.config = config
    instance._groupdbs = {}
    return instance


class TestGetGroupdbForDataOwner:
    """
    Regression tests for the explicit group_lookups_enabled kill switch. It must be checked in
    addition to (not instead of) the pre-existing implicit `neo4j_uri is None` kill switch.
    """

    @pytest.mark.parametrize("neo4j_uri", [None, "bolt://localhost:7687"])
    def test_disabled_returns_none_regardless_of_neo4j_uri(self, mocker: MockerFixture, neo4j_uri: str | None) -> None:
        mock_groupdb_cls = mocker.patch("eduid.satosa.scimapi.scim_attributes.ScimApiGroupDB")
        scim_attributes = make_scim_attributes(
            Config(mongo_uri="mongodb://localhost:27017", neo4j_uri=neo4j_uri, group_lookups_enabled=False)
        )

        assert scim_attributes.get_groupdb_for_data_owner("eduid.se") is None
        mock_groupdb_cls.assert_not_called()

    def test_enabled_default_with_neo4j_uri_unset_returns_none(self, mocker: MockerFixture) -> None:
        mock_groupdb_cls = mocker.patch("eduid.satosa.scimapi.scim_attributes.ScimApiGroupDB")
        # group_lookups_enabled defaults to True
        scim_attributes = make_scim_attributes(Config(mongo_uri="mongodb://localhost:27017", neo4j_uri=None))

        assert scim_attributes.get_groupdb_for_data_owner("eduid.se") is None
        mock_groupdb_cls.assert_not_called()

    def test_enabled_default_with_neo4j_uri_set_returns_groupdb(self, mocker: MockerFixture) -> None:
        mock_groupdb_instance = mocker.MagicMock()
        mock_groupdb_cls = mocker.patch(
            "eduid.satosa.scimapi.scim_attributes.ScimApiGroupDB", return_value=mock_groupdb_instance
        )
        # group_lookups_enabled defaults to True, matching behaviour before this change
        scim_attributes = make_scim_attributes(
            Config(mongo_uri="mongodb://localhost:27017", neo4j_uri="bolt://localhost:7687")
        )

        result = scim_attributes.get_groupdb_for_data_owner("eduid.se")

        assert result is mock_groupdb_instance
        mock_groupdb_cls.assert_called_once()
        _, kwargs = mock_groupdb_cls.call_args
        assert kwargs["mongo_collection"] == "eduid_se__groups"
        assert kwargs["setup_indexes"] is False

    def test_explicitly_enabled_with_neo4j_uri_set_returns_groupdb(self, mocker: MockerFixture) -> None:
        mock_groupdb_instance = mocker.MagicMock()
        mocker.patch("eduid.satosa.scimapi.scim_attributes.ScimApiGroupDB", return_value=mock_groupdb_instance)
        scim_attributes = make_scim_attributes(
            Config(
                mongo_uri="mongodb://localhost:27017",
                neo4j_uri="bolt://localhost:7687",
                group_lookups_enabled=True,
            )
        )

        assert scim_attributes.get_groupdb_for_data_owner("eduid.se") is mock_groupdb_instance

    @pytest.mark.parametrize("neo4j_fallback", [True, False])
    def test_neo4j_fallback_passed_through_to_groupdb(self, mocker: MockerFixture, neo4j_fallback: bool) -> None:
        # neo4j_fallback is a third, orthogonal flag: it must be threaded through to
        # ScimApiGroupDB regardless of group_lookups_enabled, which is a separate, full on/off
        # switch for group lookups.
        mock_groupdb_cls = mocker.patch("eduid.satosa.scimapi.scim_attributes.ScimApiGroupDB")
        scim_attributes = make_scim_attributes(
            Config(
                mongo_uri="mongodb://localhost:27017",
                neo4j_uri="bolt://localhost:7687",
                neo4j_fallback=neo4j_fallback,
            )
        )

        scim_attributes.get_groupdb_for_data_owner("eduid.se")

        mock_groupdb_cls.assert_called_once()
        _, kwargs = mock_groupdb_cls.call_args
        assert kwargs["neo4j_fallback"] is neo4j_fallback
