from typing import List

from eduid.userdb import User, UserDB
from eduid.workers.amapi.context_request import ContextRequest
from eduid.workers.amapi.models.sampler import SamplerRequest, SamplerResponse


def get_sample(ctx: ContextRequest, sampler_request: SamplerRequest) -> List[str]:
    """Return a sample from DB"""
    return ctx.app.db.get_eppn_samples(
        sample_size=SamplerRequest.sample_size, exclude_process_id=SamplerRequest.exclude_process_id
    )
