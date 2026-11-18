from eduid.userdb.identity import IdentityProofingMethod
from eduid.webapp.idp.settings.common import IdPConfig


def test_digg_loa2_allows_sverigeid_proofed_nin() -> None:
    allowed = IdPConfig.model_fields["digg_loa2_allowed_identity_proofing_methods"].default
    assert IdentityProofingMethod.SVERIGEID in allowed
    # the methods that were allowed before are still allowed
    assert IdentityProofingMethod.SWEDEN_CONNECT in allowed
    assert IdentityProofingMethod.BANKID in allowed
    assert IdentityProofingMethod.LETTER in allowed
