# This is the canonical place of the Celery() instance once initialized
# by either a worker or an app. Don't touch :).
from typing import Optional

from celery import Celery

celery: Optional[Celery] = None
