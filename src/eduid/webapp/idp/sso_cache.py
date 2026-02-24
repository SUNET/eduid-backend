# This SAML IdP implementation is derived from the pysaml2 example 'idp2'.
# That code is covered by the following copyright (from pysaml2 LICENSE.txt 2013-05-06) :
#
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY ROLAND HEDBERG ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ROLAND HEDBERG OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# -------------------------------------------------------------------------------
#
# All the changes made during the eduID development are subject to the following
# copyright:
#
# Copyright (c) 2013 SUNET. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY SUNET "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL SUNET OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of SUNET.

import logging

from eduid.userdb.db import BaseDB
from eduid.userdb.exceptions import EduIDDBError
from eduid.webapp.idp.sso_session import SSOSession, SSOSessionId

logger = logging.getLogger(__name__)


class SSOSessionCacheError(EduIDDBError):
    pass


class SSOSessionCache(BaseDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_idp", collection: str = "sso_sessions") -> None:
        super().__init__(db_uri, db_name, collection=collection, safe_writes=True)

        # Remove messages older than created_ts + ttl
        indexes = {
            "auto-discard": {"key": [("expires_at", 1)], "expireAfterSeconds": 0},
            "unique-session-id": {"key": [("session_id", 1)], "unique": True},
        }
        self.setup_indexes(indexes)

    def remove_session(self, session: SSOSession) -> bool:
        """
        Remove entries when SLO is executed.
        :return: False on failure
        """
        result = self._coll.delete_one({"_id": session.obj_id})
        logger.debug(f"Removed session {session}: num={result.deleted_count}")
        return bool(result.deleted_count)

    def save(self, session: SSOSession) -> None:
        """
        Add a new SSO session to the cache, or update an existing one.

        The mapping of uid -> user (and data) is used when a user visits another SP before
        the SSO session expires, and the mapping of user -> uid is used if the user requests
        logout (SLO).
        """
        result = self._coll.replace_one({"_id": session.obj_id}, session.to_dict(), upsert=True)
        logger.debug(
            f"Saved SSO session {session} in the db: "
            f"matched={result.matched_count}, modified={result.modified_count}, upserted_id={result.upserted_id}"
        )

    def get_session(self, sid: SSOSessionId) -> SSOSession | None:
        """
        Lookup an SSO session using the session id (same `sid' previously used with add_session).

        :param sid: Unique session identifier as string
        :param userdb: Database to use to initialise session.idp_user
        :return: The session, if found
        """
        res = self._coll.find_one({"session_id": sid})
        if not res:
            logger.debug(f"No SSO session found with session_id={sid!r}")
            return None
        session = SSOSession.from_dict(res)
        return session

    def get_sessions_for_user(self, eppn: str) -> list[SSOSession]:
        """
        Lookup all SSO session ids for a given user. Used in SLO with SOAP binding.

        :param eppn: The eppn to look for

        :return: A list with zero or more SSO sessions
        """
        entrys = self._coll.find({"eppn": eppn})
        res = [SSOSession.from_dict(this) for this in entrys]
        return res
