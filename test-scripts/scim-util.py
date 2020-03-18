#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from pprint import pformat
from typing import Any, Callable, Dict, Mapping, NewType, Optional, cast

import requests
import yaml

logger = logging.getLogger(__name__)

Args = NewType('Args', argparse.Namespace)
NUTID_V1 = 'https://scim.eduid.se/schema/nutid/v1'


def parse_args() -> Args:
    parser = argparse.ArgumentParser(description='SCIM testing utility')
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=False,
                        help='Enable debug operation'
                        )

    parser.add_argument('file', metavar='FILE', type=argparse.FileType('r'), help='YAML file with command data in it')

    return cast(Args, parser.parse_args())


def scim_request(func: Callable, url: str, json=None) -> Optional[Dict[str, Any]]:
    headers = {'content-type': 'application/scim+json'}
    logger.debug(f'API URL: {url}')
    r = func(url, json=json, headers=headers)
    logger.debug(f'Response from server: {r}\n{r.text}')

    if r.status_code != 200:
        return None

    response = r.json()
    logger.debug(f'Response:\n{pformat(response, width=120)}')
    return response


def search_user(api: str, external_id: str) -> Optional[Dict[str, Any]]:
    logger.info(f'Searching for user with externalId {external_id}')
    query = {
        'schemas': [
            'urn:ietf:params:scim:api:messages:2.0:SearchRequest'
        ],
        'filter': f'externalId eq "{external_id}"',
        'startIndex': 1,
        'count': 1
    }

    logger.debug(f'Sending user search query:\n{pformat(json.dumps(query, sort_keys=True, indent=4))}')
    res = scim_request(requests.post, f'{api}/Users/.search', json=query)
    logger.info(f'User search result:\n{json.dumps(res, sort_keys=True, indent=4)}\n')
    return res


def get_user_resource(api: str, scim_id: str) -> Optional[Dict[str, Any]]:
    logger.debug(f'Fetching SCIM user resource {scim_id}')

    return scim_request(requests.get, f'{api}/Users/{scim_id}')


def put_user(api: str, scim_id: str, profiles: Mapping[str, Any]) -> None:
    scim = get_user_resource(api, scim_id)
    if not scim:
        return

    if NUTID_V1 not in scim['schemas']:
        scim['schemas'] += [NUTID_V1]
    if NUTID_V1 not in scim:
        scim[NUTID_V1] = {}
    if 'profiles' not in scim[NUTID_V1]:
        scim[NUTID_V1]['profiles'] = {}

    scim[NUTID_V1]['profiles'] = profiles

    logger.info(f'Updating profiles for SCIM user resource {scim_id}:\n{json.dumps(scim, sort_keys=True, indent=4)}\n')
    res = scim_request(requests.put, f'{api}/Users/{scim_id}', json=scim)
    logger.info(f'Update result:\n{json.dumps(res, sort_keys=True, indent=4)}')
    return None



def process_users(api: str, ops: Mapping[str, Any]) -> None:
    """
    Process users.

    Example ops:

        {'put': {'f5a3b0d0-3caf-43b0-ab61-17dd97ed0556':
                     [{'eduid': {'display_name': 'Kalle Anka'}}]
                 },
         'search': ['numol-fojar@eduid.se']
         }
    """
    for op in ops.keys():
        if op == 'search':
            for external_id in ops[op]:
                search_user(api, external_id)
        elif op == 'put':
            for scim_id in ops[op]:
                put_user(api, scim_id, ops[op][scim_id]['profiles'])


def main(args: Args) -> bool:
    data = yaml.safe_load(args.file)

    logger.debug(f'Loaded command data: {pformat(data)}')

    for api in data.keys():
        if 'users' in data[api]:
            process_users(api, data[api]['users'])

    return True


def _config_logger(args: Args, progname: str):
    # This is the root log level
    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr,
                        format='%(asctime)s: %(name)s: %(levelname)s %(message)s')
    logger.name = progname
    # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to WARNING
    if not sys.stderr.isatty() and not args.debug:
        for this_h in logging.getLogger('').handlers:
            this_h.setLevel(logging.WARNING)


if __name__ == '__main__':
    args = parse_args()
    _config_logger(args, 'scim-util')
    if main(args):
        sys.exit(0)

    sys.exit(1)
