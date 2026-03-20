from eduid.common.fastapi.routers.status import create_status_router
from eduid.scimapi.context_request import ScimApiRoute
from eduid.scimapi.routers.utils.status import check_mongo, check_neo4j

__author__ = "lundberg"

status_router = create_status_router(checks=[check_mongo, check_neo4j], route_class=ScimApiRoute)
