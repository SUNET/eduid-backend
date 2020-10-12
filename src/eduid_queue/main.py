import asyncio
import logging

from eduid_queue.workers.mail import MailQueueWorker

logger = logging.getLogger(__name__)


if __name__ == '__main__':
    config = {
        'app_name': 'mail_worker',
        'worker_name': 'mail_worker_1',
        'mongo_uri': 'mongodb://localhost:43444',
        'mongo_collection': 'test',
    }
    worker = MailQueueWorker(app_name='mail_worker', test_config=config)
    exit(asyncio.run(worker.run()))
