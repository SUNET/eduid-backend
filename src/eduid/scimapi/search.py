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


def parse_search_filter(filter: str) -> SearchFilter:
    # Bandaid for GitHub CodeQL: Polynomial regular expression used on uncontrolled data
    # TODO: Maybe use a proper parser instead of regex, maybe https://pypi.org/project/scim2-filter-parser/
    if len(filter) > 1024:
        raise BadRequest(scim_type="invalidFilter", detail="Filter too long")
    match = re.match("(.+?) (..) (.+)", filter)
    if not match:
        logger.debug(f"Unrecognised filter: {filter}")
        raise BadRequest(scim_type="invalidFilter", detail="Unrecognised filter")

    val: str | int
    attr, op, val = match.groups()

    if len(val) and val[0] == '"' and val[-1] == '"':
        val = val[1:-1]
        if not val.isprintable():
            logger.debug(f"Unrecognised string value in filter: {repr(val)}")
            raise BadRequest(scim_type="invalidFilter", detail="Unrecognised string value in filter")
    elif val.isdecimal():
        val = int(val)
    else:
        logger.debug(f"Unrecognised type of value (not string or integer) in filter: {val}")
        raise BadRequest(
            scim_type="invalidFilter", detail="Unrecognised type of value (not string or integer) in filter"
        )

    return SearchFilter(attr=attr.lower(), op=op.lower(), val=val)
