from typing import cast

from flask import session as flask_session

from eduid.webapp.common.session.eduid_session import EduidSession


# Ugly hack to get make type checks/hints to work
# Instead of importing session from flask it needs to be imported
# from here
def get_typed_flask_session() -> EduidSession:
    return cast(EduidSession, flask_session)


session = get_typed_flask_session()
