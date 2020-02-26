# -*- coding: utf-8 -*-
from datetime import datetime
from typing import Mapping, Optional

__author__ = 'lundberg'


def neo4j_ts_to_dt(data: Mapping) -> Mapping[str, Optional[datetime]]:
    created_ts = data.get('created_ts')
    if created_ts:
        created_ts = datetime.fromtimestamp(created_ts / 1000)  # Milliseconds since 1970
    modified_ts = data.get('modified_ts')
    if modified_ts:
        modified_ts = datetime.fromtimestamp(modified_ts / 1000)  # Milliseconds since 1970
    return {
        'created_ts': created_ts,
        'modified_ts': modified_ts
    }
