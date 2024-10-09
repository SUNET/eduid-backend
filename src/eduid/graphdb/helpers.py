from collections.abc import Mapping
from datetime import UTC, datetime

__author__ = "lundberg"


def neo4j_ts_to_dt(data: Mapping) -> Mapping[str, datetime | None]:
    created_ts = data.get("created_ts")
    if isinstance(created_ts, int):
        created_ts = datetime.fromtimestamp(created_ts / 1000)  # Milliseconds since 1970
        created_ts.replace(tzinfo=UTC)
    modified_ts = data.get("modified_ts")
    if isinstance(modified_ts, int):
        modified_ts = datetime.fromtimestamp(modified_ts / 1000)  # Milliseconds since 1970
        modified_ts.replace(tzinfo=UTC)
    return {"created_ts": created_ts, "modified_ts": modified_ts}
