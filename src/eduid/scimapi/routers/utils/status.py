from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.fastapi.utils import check_restart, log_failure_info, reset_failure_info

__author__ = "lundberg"


def check_mongo(req: ContextRequest) -> bool:
    if not req.app.context.config.data_owners:
        log_failure_info(req, "_check_mongo", msg="Mongodb health check failed: no data_owners configured")
        return False
    default_data_owner = next(iter(req.app.context.config.data_owners.keys()))
    user_db = req.app.context.get_userdb(default_data_owner)
    group_db = req.app.context.get_groupdb(default_data_owner)
    try:
        user_db.is_healthy()
        group_db.is_healthy()
        reset_failure_info(req, "_check_mongo")
        return True
    except Exception as exc:
        log_failure_info(req, "_check_mongo", msg="Mongodb health check failed", exc=exc)
        check_restart("_check_mongo", restart=0, terminate=120)
        return False


def check_neo4j(req: ContextRequest) -> bool:
    if not req.app.context.config.data_owners:
        log_failure_info(req, "_check_neo4j", msg="Neo4j health check failed: no data_owners configured")
        return False
    default_data_owner = next(iter(req.app.context.config.data_owners.keys()))
    group_db = req.app.context.get_groupdb(default_data_owner)
    try:
        q = """
            MATCH (n)
            RETURN count(*) as exists LIMIT 1
            """
        with group_db.graphdb.db.driver.session() as session:
            session.run(q).single()
        reset_failure_info(req, "_check_neo4j")
        return True
    except Exception as exc:
        log_failure_info(req, "_check_neo4j", msg="Neo4j health check failed", exc=exc)
        check_restart("_check_neo4j", restart=0, terminate=120)
        return False
