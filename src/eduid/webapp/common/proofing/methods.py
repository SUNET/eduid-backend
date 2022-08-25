from dataclasses import dataclass
from typing import List, Optional

from pydantic import BaseModel

from eduid.common.config.base import ProofingConfigMixin
from eduid.userdb.credentials.external import TrustFramework


@dataclass(frozen=True)
class ProofingMethod:
    framework: TrustFramework
    required_loa: List[str]
    idp: str
    method: str


class ProofingMethodFreja(ProofingMethod):
    pass


class ProofingMethodEidas(ProofingMethod):
    pass


def get_proofing_method(method: str, config: ProofingConfigMixin) -> Optional[ProofingMethod]:
    if method == 'freja':
        return ProofingMethodFreja(
            framework=TrustFramework.SWECONN, required_loa=config.required_loa, idp=config.freja_idp, method=method
        )
    if method == 'eidas':
        return ProofingMethodEidas(
            framework=TrustFramework.EIDAS,
            required_loa=config.foreign_required_loa,
            idp=config.foreign_identity_idp,
            method=method,
        )
    return None
