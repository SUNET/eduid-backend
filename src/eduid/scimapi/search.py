import logging
from dataclasses import dataclass

from eduid.scimapi.exceptions import BadRequest

logger = logging.getLogger(__name__)


@dataclass
class SearchFilter:
    attr: str
    op: str
    val: str | int


MAX_FILTER_LENGTH = 1024
FILTER_PARTS_COUNT = 3
VALID_OPERATORS = frozenset({"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le", "pr"})


def parse_search_filter(search_filter: str) -> SearchFilter:
    # TODO: Maybe use a proper parser instead, maybe https://pypi.org/project/scim2-filter-parser/
    # Though this simple parsing is enough for our current needs.
    if len(search_filter) > MAX_FILTER_LENGTH:
        raise BadRequest(scim_type="invalidFilter", detail="Filter too long")

    parts = search_filter.split(" ", 2)
    if len(parts) != FILTER_PARTS_COUNT or not parts[0] or not parts[2]:
        logger.debug(f"Unrecognised filter: {search_filter}")
        raise BadRequest(scim_type="invalidFilter", detail="Unrecognised filter")

    val: str | int
    attr, op, val = parts

    if op.lower() not in VALID_OPERATORS:
        logger.debug(f"Unsupported operator in filter: {op}")
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported operator")

    if len(val) and val[0] == '"' and val[-1] == '"':
        val = val[1:-1]
        if not val.isprintable():
            logger.debug(f"Unrecognised string value in filter: {val!r}")
            raise BadRequest(scim_type="invalidFilter", detail="Unrecognised string value in filter")
    elif val.isdecimal():
        val = int(val)
    else:
        logger.debug(f"Unrecognised type of value (not string or integer) in filter: {val}")
        raise BadRequest(
            scim_type="invalidFilter", detail="Unrecognised type of value (not string or integer) in filter"
        )

    return SearchFilter(attr=attr.lower(), op=op.lower(), val=val)
