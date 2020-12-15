from asyncio import Lock

from fastapi import FastAPI

from vccs.server.config import init_config
from vccs.server.endpoints.misc import misc_router
from vccs.server.hasher import hasher_from_string
from vccs.server.log import InterceptHandler, init_logging


class VCCS_API(FastAPI):
    def __init__(self):
        super().__init__()

        self.state.config = init_config()

        self.logger = init_logging()

        yhsm_lock = Lock()  # brief testing indicates locking is not needed with asyncio, but...
        self.state.hasher = hasher_from_string(name='/dev/ttyACM0', lock=yhsm_lock, debug=self.state.config.yhsm_debug)
        self.state.hasher._yhsm.unlock(self.state.config.yhsm_unlock_password)

        self.logger.info(f'Starting, YHSM {self.state.hasher}')
        self.logger.info(f'YHSM status: {self.state.hasher._yhsm.info()}')

app = VCCS_API()
app.include_router(misc_router)  #, prefix='/v1')


@app.on_event("startup")
async def startup_event():
    """
    Uvicorn mucks with the logging config on startup, particularly the access log. Rein it in.
    """
    import logging
    for _name in ['uvicorn', 'uvicorn.access', 'uvicorn.error']:
        _logger = logging.getLogger(_name)
        _logger.level = logging.DEBUG
        _old_handlers = _logger.handlers
        _logger.handlers = [InterceptHandler()]
        _logger.propagate = False
        app.logger.info(f'Updated logger {_name} handlers {_old_handlers} -> {_logger.handlers} '
                        f'(prop: {_logger.propagate})')


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000, log_config=None)
