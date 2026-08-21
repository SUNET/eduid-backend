from collections.abc import Mapping
from typing import Any

import pytest

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.checks import check_mongo
from eduid.webapp.common.api.testing import EduidAPITestCase


class NoUserdbApp(EduIDBaseApp):
    """An app without access to the central user db, the way jsconfig is set up."""

    def __init__(self, config: EduIDBaseAppConfig, **kwargs: Any) -> None:
        kwargs["init_central_userdb"] = False
        super().__init__(config, **kwargs)


class WithUserdbApp(EduIDBaseApp):
    """An app with access to the central user db, which is the default."""


class NoCentralUserdbTests(EduidAPITestCase[NoUserdbApp]):
    app: NoUserdbApp

    @classmethod
    def load_app(cls, config: Mapping[str, Any]) -> NoUserdbApp:
        app_config = load_config(typ=EduIDBaseAppConfig, app_name="test_app", ns="webapp", test_config=config)
        return NoUserdbApp(app_config)

    def test_has_central_userdb_is_false(self) -> None:
        assert self.app.has_central_userdb is False

    def test_central_userdb_raises(self) -> None:
        """central_userdb is not a probe - it raises rather than returning None."""
        with pytest.raises(RuntimeError, match="Central userdb not initialised"):
            _ = self.app.central_userdb

    def test_check_mongo_is_healthy(self) -> None:
        """An app without a central user db has nothing to check, so it reports healthy."""
        with self.app.app_context():
            assert check_mongo() is True


class WithCentralUserdbTests(EduidAPITestCase[WithUserdbApp]):
    app: WithUserdbApp

    @classmethod
    def load_app(cls, config: Mapping[str, Any]) -> WithUserdbApp:
        app_config = load_config(typ=EduIDBaseAppConfig, app_name="test_app", ns="webapp", test_config=config)
        return WithUserdbApp(app_config)

    def test_has_central_userdb_is_true(self) -> None:
        assert self.app.has_central_userdb is True

    def test_check_mongo_is_healthy(self) -> None:
        """With a central user db, the health check actually queries it."""
        with self.app.app_context():
            assert check_mongo() is True
