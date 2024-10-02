from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI

from eduid.common.config.parsers import load_config
from eduid.workers.job_runner.config import JobRunnerConfig
from eduid.workers.job_runner.context import Context
from eduid.workers.job_runner.scheduler import JobScheduler
from eduid.workers.job_runner.status import status_router


class JobRunner(FastAPI):
    scheduler: JobScheduler = JobScheduler(timezone="UTC")

    def __init__(self, name: str = "job_runner", test_config: dict | None = None, lifespan: Callable | None = None):
        self.config = load_config(typ=JobRunnerConfig, app_name=name, ns="worker", test_config=test_config)
        super().__init__(root_path=self.config.application_root, lifespan=lifespan)

        self.context = Context(config=self.config)
        self.context.logger.info(f"Starting {name} worker: {self.context.worker_name}")


@asynccontextmanager
async def lifespan(app: JobRunner) -> AsyncIterator[None]:
    app.context.logger.info("Starting scheduler...")
    app.scheduler.start()
    yield
    app.context.logger.info("Stopping scheduler...")
    app.scheduler.shutdown()


def init_app(name: str = "job_runner", test_config: dict | None = None) -> JobRunner:
    app = JobRunner(name, test_config, lifespan=lifespan)
    app.context.logger.info(app.config)

    app.include_router(status_router)

    # schedule jobs defined in config
    app.scheduler.schedule_jobs(app.context)

    app.context.logger.info("app running...")
    return app
