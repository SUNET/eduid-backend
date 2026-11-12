from eduid.webapp.bankid.settings.common import BankIDConfig


def test_bankid_loa_map_matches_credential_guard() -> None:
    # the shared BankID proofing functions resolve and compare the LoA name "uncertified-loa3"
    default = BankIDConfig.model_fields["loa_authn_context_map"].default
    assert default == {"uncertified-loa3": "http://id.swedenconnect.se/loa/1.0/uncertified-loa3"}
