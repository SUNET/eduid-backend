from typing import Any, Dict, List, Optional

from fastapi import Response
from eduid.workers.amapi.api_router import APIRouter
from eduid.workers.amapi.context_request import ContextRequest, ContextRequestRoute
from eduid.workers.amapi.exceptions import BadRequest, ErrorDetail, NotFound
from eduid.workers.amapi.models.sampler import SamplerRequest, SamplerResponse
from eduid.workers.amapi.routers.utils.sampler import get_sample

sampler_router = APIRouter(
    route_class=ContextRequestRoute,
    prefix='/sampler',
    responses={
        400: {'description': 'Bad request', 'model': ErrorDetail},
        404: {'description': 'Not found', 'model': ErrorDetail},
        500: {'description': 'Internal server error', 'model': ErrorDetail},
    },
)


# processID
@sampler_router.post('', response_model=SamplerResponse)
async def on_get(ctx: ContextRequest, sample_request: SamplerRequest):
    ctx.app.logger.info(f'Get user samples')
    return get_sample(ctx, sampler_request=sample_request)