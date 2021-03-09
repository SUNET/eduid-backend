import logging
import re
from dataclasses import dataclass
from typing import Union

from eduid.scimapi.exceptions import BadRequest

logger = logging.getLogger(__name__)


@dataclass
class SearchFilter(object):
    attr: str
    op: str
    val: Union[str, int]


def parse_search_filter(filter: str) -> SearchFilter:
    match = re.match('(.+?) (..) (.+)', filter)
    if not match:
        logger.debug(f'Unrecognised filter: {filter}')
        raise BadRequest(scim_type='invalidFilter', detail='Unrecognised filter')

    val: Union[str, int]
    attr, op, val = match.groups()

    if len(val) and val[0] == '"' and val[-1] == '"':
        val = val[1:-1]
        if not val.isprintable():
            logger.debug(f'Unrecognised string value in filter: {repr(val)}')
            raise BadRequest(scim_type='invalidFilter', detail='Unrecognised string value in filter')
    elif val.isdecimal():
        val = int(val)
    else:
        logger.debug(f'Unrecognised type of value (not string or integer) in filter: {val}')
        raise BadRequest(
            scim_type='invalidFilter', detail='Unrecognised type of value (not string or integer) in filter'
        )

    return SearchFilter(attr=attr.lower(), op=op.lower(), val=val)
