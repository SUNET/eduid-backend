import unittest
from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from eduid.common.config.base import CeleryConfig, MsgConfigMixin
from eduid.common.config.workers import MsgConfig
from eduid.common.rpc.exceptions import NoAddressFound, NoNavetData
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, FullPostalAddress, MsgRelay, NavetData, RelationType
from eduid.workers.msg import MsgCelerySingleton
from eduid.workers.msg.tasks import MessageSender

__author__ = "lundberg"


class MsgRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        msg_config = MsgConfig(app_name="test", devel_mode=True)
        msg_relay_config = MsgConfigMixin(app_name="test", celery=CeleryConfig())
        MsgCelerySingleton.update_worker_config(config=msg_config)
        self.msg_relay = MsgRelay(config=msg_relay_config)
        self.message_sender = MessageSender()

    @staticmethod
    def _fix_relations_to(relative_nin: str, relations: Mapping[str, Any]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for d in relations["Relations"]["Relation"]:
            if d.get("RelationId", {}).get("NationalIdentityNumber") == relative_nin:
                if "RelationType" in d:
                    result.append(d["RelationType"])
        return result

    @patch("eduid.workers.msg.tasks.get_all_navet_data.apply_async")
    def test_get_all_navet_data(self, mock_get_all_navet_data: MagicMock):
        mock_conf = {"get.return_value": self.message_sender.get_devel_all_navet_data()}
        ret = Mock(**mock_conf)
        mock_get_all_navet_data.return_value = ret
        res = self.msg_relay.get_all_navet_data(nin="190102031234")
        assert res == NavetData(**self.message_sender.get_devel_all_navet_data())

    @patch("eduid.workers.msg.tasks.get_all_navet_data.apply_async")
    def test_get_all_navet_data_deceased(self, mock_get_all_navet_data: MagicMock):
        mock_conf = {"get.return_value": self.message_sender.get_devel_all_navet_data(identity_number="189001019802")}
        ret = Mock(**mock_conf)
        mock_get_all_navet_data.return_value = ret
        res = self.msg_relay.get_all_navet_data(nin="189001019802", allow_deregistered=True)
        assert res.person.deregistration_information.cause_code == DeregisteredCauseCode.DECEASED
        assert res == NavetData(**self.message_sender.get_devel_all_navet_data(identity_number="189001019802"))

    @patch("eduid.workers.msg.tasks.get_all_navet_data.apply_async")
    def test_get_all_navet_data_none_response(self, mock_get_all_navet_data: MagicMock):
        mock_conf = {"get.return_value": None}
        ret = Mock(**mock_conf)
        mock_get_all_navet_data.return_value = ret
        with pytest.raises(NoNavetData):
            self.msg_relay.get_all_navet_data(nin="190102031234")

    @patch("eduid.workers.msg.tasks.get_postal_address.apply_async")
    def test_get_postal_address(self, mock_get_postal_address: MagicMock):
        mock_conf = {"get.return_value": self.message_sender.get_devel_postal_address()}
        ret = Mock(**mock_conf)
        mock_get_postal_address.return_value = ret
        res = self.msg_relay.get_postal_address(nin="190102031234")
        assert res == FullPostalAddress(**self.message_sender.get_devel_postal_address())

    @patch("eduid.workers.msg.tasks.get_postal_address.apply_async")
    def test_get_postal_address_none_response(self, mock_get_postal_address: MagicMock):
        mock_conf = {"get.return_value": None}
        ret = Mock(**mock_conf)
        mock_get_postal_address.return_value = ret
        with pytest.raises(NoAddressFound):
            self.msg_relay.get_postal_address(nin="190102031234")

    @patch("eduid.workers.msg.tasks.get_relations_to.apply_async")
    def test_get_relations_to(self, mock_get_relations: MagicMock):
        relations_to = self._fix_relations_to(
            relative_nin="194004048989", relations=self.message_sender.get_devel_relations()
        )
        mock_conf = {"get.return_value": relations_to}
        ret = Mock(**mock_conf)
        mock_get_relations.return_value = ret
        res = self.msg_relay.get_relations_to(nin="190102031234", relative_nin="194004048989")

        assert res == [RelationType(item) for item in relations_to]

    @patch("eduid.workers.msg.tasks.get_relations_to.apply_async")
    def test_get_relations_to_empty_response(self, mock_get_relations: MagicMock):
        mock_conf: dict[str, Any] = {"get.return_value": []}
        ret = Mock(**mock_conf)
        mock_get_relations.return_value = ret
        res = self.msg_relay.get_relations_to(nin="190102031234", relative_nin="194004048989")
        assert res == []
