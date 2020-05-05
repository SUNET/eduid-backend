import re
from dataclasses import dataclass
from typing import Union

from eduid_scimapi.exceptions import BadRequest


@dataclass
class SearchFilter(object):
    attr: str
    op: str
    val: Union[str, int]


def parse_search_filter(filter: str) -> SearchFilter:
    match = re.match('(.+?) (..) (.+)', filter)
    if not match:
        raise BadRequest(scim_type='invalidFilter', detail='Unrecognised filter')

    attr, op, val = match.groups()

    if len(val) and val[0] == '"' and val[-1] == '"':
        val = val[1:-1]
        check = re.match('^[a-zA-Z0-9_ .,:;+-]*$', val)
        if not check:
            raise BadRequest(scim_type='invalidFilter', detail='Unrecognised string value in filter')
    elif val.isdecimal():
        val = int(val)
    else:
        raise BadRequest(
            scim_type='invalidFilter', detail='Unrecognised type of value (not string or integer) in filter'
        )

    return SearchFilter(attr=attr.lower(), op=op.lower(), val=val)
