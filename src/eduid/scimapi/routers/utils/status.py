from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.fastapi.utils import check_restart, log_failure_info, reset_failure_info

__author__ = "lundberg"


def check_mongo(req: ContextRequest, default_data_owner: str) -> bool | None:
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


def check_neo4j(req: ContextRequest, default_data_owner: str) -> bool | None:
    group_db = req.app.context.get_groupdb(default_data_owner)
    try:
        # TODO: Implement is_healthy, check if there is a better way for neo4j
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
