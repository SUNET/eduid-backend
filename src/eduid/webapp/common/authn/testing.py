import json
import logging

from eduid.common.decorators import deprecated
from eduid.vccs.client import VCCSClient

logger = logging.getLogger()


class FakeVCCSClient(VCCSClient):
    def __init__(self, fake_response=None):
        super().__init__()
        self.fake_response = fake_response

    def _execute_request_response(self, _service, _values):
        if self.fake_response is not None:
            return json.dumps(self.fake_response)

        fake_response = {}
        if _service == "add_creds":
            fake_response = {
                "add_creds_response": {"version": 1, "success": True},
            }
        elif _service == "authenticate":
            fake_response = {
                "auth_response": {"version": 1, "authenticated": True},
            }
        elif _service == "revoke_creds":
            fake_response = {
                "revoke_creds_response": {"version": 1, "success": True},
            }
        return json.dumps(fake_response)


class TestVCCSClient:
    """
    Mock VCCS client for testing. It stores factors locally,
    and it only checks for the credential_id to authenticate/revoke.

    It is used as a singleton, so we can manipulate it in the tests
    before the real functions (check_password, add_credentials) use it.
    """

    @deprecated("Remove once eduid-webapp is using MockVCCSClient (just below this)")
    def __init__(self):
        self.factors = {}

    def authenticate(self, user_id, factors):
        found = False
        if user_id not in self.factors:
            logger.debug(f"User {user_id!r} not found in TestVCCSClient credential store:\n{self.factors}")
            return False
        for factor in factors:
            logger.debug(f"Trying to authenticate user {user_id} with factor {factor} (id {factor.credential_id})")
            fdict = factor.to_dict("auth")
            for stored_factor in self.factors[user_id]:
                if factor.credential_id != stored_factor.credential_id:
                    logger.debug(f"No match for id of stored factor {stored_factor} (id {stored_factor.credential_id})")
                    continue
                logger.debug(f"Found matching credential_id: {stored_factor}")
                try:
                    sdict = stored_factor.to_dict("auth")
                except (AttributeError, ValueError):
                    # OATH token
                    found = True
                    break
                else:
                    # H1 hash comparision for password factors
                    if fdict["H1"] == sdict["H1"]:
                        found = True
                        break
                    logger.debug("Hash {} did not match the expected hash {}".format(fdict["H1"], sdict["H1"]))
        logger.debug(f"TestVCCSClient authenticate result for user_id {user_id}: {found}")
        return found

    def add_credentials(self, user_id, factors):
        user_factors = self.factors.get(str(user_id), [])
        user_factors.extend(factors)
        self.factors[str(user_id)] = user_factors
        return True

    def revoke_credentials(self, user_id, revoked):
        stored = self.factors.get(user_id, None)
        if stored:  # Nothing stored in test client yet
            for rfactor in revoked:
                rdict = rfactor.to_dict("revoke_creds")
                for factor in stored:
                    fdict = factor.to_dict("revoke_creds")
                    if rdict["credential_id"] == fdict["credential_id"]:
                        stored.remove(factor)
                        break


# new name to import from dependent packages, so we can remove the deprecated TestVCCSClient
MockVCCSClient = TestVCCSClient
