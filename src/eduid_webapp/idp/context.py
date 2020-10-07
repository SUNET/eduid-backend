"""
A context for the IdP.
"""

from dataclasses import dataclass
from logging import Logger
from typing import Optional

from saml2.server import Server as Saml2Server

from eduid_common.authn.idp_authn import IdPAuthn
from eduid_common.session.redis_session import RedisEncryptedSession
from eduid_common.session.sso_cache import SSOSessionCache
from eduid_userdb.actions import ActionDB

from eduid_webapp.idp.settings.common import IdPConfig


@dataclass(frozen=True)
class IdPContext(object):
    config: IdPConfig
    sso_sessions: SSOSessionCache
    idp: Saml2Server
    logger: Logger
    authn: IdPAuthn
    actions_db: Optional[ActionDB] = None
    session: Optional[RedisEncryptedSession] = None
