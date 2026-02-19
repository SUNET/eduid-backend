import logging
import re
from dataclasses import dataclass

from eduid.scimapi.exceptions import BadRequest

logger = logging.getLogger(__name__)


@dataclass
class SearchFilter:
    attr: str
    op: str
    val: str | int


MAX_FILTER_LENGTH = 1024


def parse_search_filter(search_filter: str) -> SearchFilter:
    # Bandaid for GitHub CodeQL: Polynomial regular expression used on uncontrolled data
    # TODO: Maybe use a proper parser instead of regex, maybe https://pypi.org/project/scim2-filter-parser/
    if len(search_filter) > MAX_FILTER_LENGTH:
        raise BadRequest(scim_type="invalidFilter", detail="Filter too long")
    match = re.match("(.+?) (..) (.+)", search_filter)
    if not match:
        logger.debug(f"Unrecognised filter: {search_filter}")
        raise BadRequest(scim_type="invalidFilter", detail="Unrecognised filter")

    val: str | int
    attr, op, val = match.groups()

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
