from typing import Any

from eduid.common.config.base import ProofingConfigMixin
from eduid.common.models.saml_models import BaseSessionInfo
from eduid.webapp.common.proofing.base import ProofingFunctions
from eduid.webapp.common.proofing.swedenconnect.proofing import EidasProofingFunctions, FrejaProofingFunctions
from eduid.webapp.common.proofing.swedenconnect.session_info import ForeignEidSessionInfo, NinSessionInfo


def get_proofing_functions(
    session_info: BaseSessionInfo,
    app_name: str,
    config: ProofingConfigMixin,
    backdoor: bool,
) -> ProofingFunctions[Any]:
    if isinstance(session_info, NinSessionInfo):
        return FrejaProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    elif isinstance(session_info, ForeignEidSessionInfo):
        return EidasProofingFunctions(session_info=session_info, app_name=app_name, config=config, backdoor=backdoor)
    else:
        raise NotImplementedError(f"MFA matching for {type(session_info)} not implemented")
