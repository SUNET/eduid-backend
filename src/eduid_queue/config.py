# -*- coding: utf-8 -*-

from dataclasses import dataclass

from eduid_common.config.base import BaseConfig

__author__ = 'lundberg'


@dataclass
class QueueWorkerConfig(BaseConfig):
    """
    Configuration for eduid-queue workers
    """

    mongo_collection: str = ''
    periodic_interval: int = 10
    periodic_min_retry_wait_in_seconds: int = 10
    max_retries: int = 10
    audit: bool = True
    # Mail worker
    mail_host: str = 'localhost'
    mail_port: int = 25
    mail_starttls: bool = False
    mail_keyfile: str = ''
    mail_certfile: str = ''
    mail_username: str = ''
    mail_password: str = ''
