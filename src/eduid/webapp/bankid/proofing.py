from typing import Any

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.models.saml_models import BaseSessionInfo
from eduid.webapp.common.proofing.base import ProofingFunctions
from eduid.webapp.common.proofing.swedenconnect.proofing import BankIDProofingFunctions
from eduid.webapp.common.proofing.swedenconnect.session_info import BankIDSessionInfo


def get_proofing_functions(
    session_info: BaseSessionInfo,
    app_name: str,
    config: ProofingConfigMixin,
    backdoor: bool,
) -> ProofingFunctions[Any]:
    if isinstance(session_info, BankIDSessionInfo):
        return BankIDProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    else:
        raise NotImplementedError(f"Proofing functions for {type(session_info)} not implemented")
