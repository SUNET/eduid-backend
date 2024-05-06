from apscheduler.schedulers.asyncio import AsyncIOScheduler

from eduid.workers.job_runner.context import Context
from eduid.workers.job_runner.jobs.skv import check_skv_users, gather_skv_users


class JobScheduler(AsyncIOScheduler):

    def schedule_jobs(self, context: Context):
        """
        Schedule all jobs configured for host or environment
        """

        environment = context.config.environment

        jobs_config = context.config.jobs

        jobs: dict = {}

        if environment in jobs_config:
            context.logger.info(f"Setting up jobs for environment {environment}")
            context.logger.info(f"Setting up jobs {jobs_config[environment]}")
            jobs.update(jobs_config[environment])

        if context.worker_name in jobs_config:
            context.logger.info(f"Setting up jobs for worker {context.worker_name}")
            context.logger.info(f"Setting up jobs {jobs_config[context.worker_name]}")
            jobs.update(jobs_config[context.worker_name])

        context.logger.info(f"Setting up jobs {jobs} for {context.worker_name} running {environment}")

        for job in jobs:
            params = jobs[job]
            context.logger.info(f"Setting up job {job} with parameters {params}")

            match job:
                case "gather_skv_users":
                    self.add_job(gather_skv_users, "cron", **params, args=(context,))
                case "check_skv_users":
                    self.add_job(check_skv_users, "cron", **params, args=(context,))
                case _:
                    BaseException("unknown job in config")
