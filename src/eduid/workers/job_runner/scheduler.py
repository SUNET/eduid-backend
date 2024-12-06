from apscheduler.schedulers.asyncio import AsyncIOScheduler

from eduid.common.config.exceptions import BadConfiguration
from eduid.workers.job_runner.config import EnvironmentOrWorkerName, JobCronConfig, JobName
from eduid.workers.job_runner.context import Context
from eduid.workers.job_runner.jobs.skv import check_skv_users, gather_skv_users


class JobScheduler(AsyncIOScheduler):
    def schedule_jobs(self, context: Context) -> None:
        """
        Schedule all jobs configured for host or environment
        """

        environment = EnvironmentOrWorkerName(context.config.environment)
        worker_name = EnvironmentOrWorkerName(context.worker_name)

        if context.config.jobs is None:
            context.logger.info("No jobs configured in config")
            return

        jobs_config = context.config.jobs
        context.logger.debug(f"jobs_config: {jobs_config}")

        jobs: dict[JobName, JobCronConfig] = {}

        # Gather jobs for current environment and worker in a dictionary
        if environment in jobs_config:
            context.logger.debug(f"Setting up jobs for environment {environment}")
            context.logger.debug(f"Setting up jobs {jobs_config[environment]}")
            jobs.update(jobs_config[environment])

        if worker_name in jobs_config:
            context.logger.debug(f"Setting up jobs for worker {worker_name}")
            context.logger.debug(f"Setting up jobs {jobs_config[worker_name]}")
            jobs.update(jobs_config[worker_name])

        if len(jobs) == 0:
            context.logger.info(f"No jobs configured for {worker_name} running {environment}")
            return

        context.logger.info(f"Setting up jobs {jobs} for {worker_name} running {environment}")

        # Add all configured jobs to the scheduler
        for job, cron_settings in jobs.items():
            params = cron_settings.model_dump()
            context.logger.info(f"Setting up job {job} with parameters {params}")

            match job:
                case "gather_skv_users":
                    self.add_job(gather_skv_users, "cron", **params, args=(context,))
                case "check_skv_users":
                    self.add_job(check_skv_users, "cron", **params, args=(context,))
                case _:
                    raise BadConfiguration("unknown job in config")
