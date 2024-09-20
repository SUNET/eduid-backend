#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pprint import pformat
from typing import Any, NewType, cast

import requests
import yaml

logger = logging.getLogger(__name__)

Args = NewType("Args", argparse.Namespace)
NUTID_USER_V1 = "https://scim.eduid.se/schema/nutid/user/v1"
NUTID_GROUP_V1 = "https://scim.eduid.se/schema/nutid/group/v1"
EVENT_CORE_V1 = "https://scim.eduid.se/schema/nutid/event/core-v1"
NUTID_EVENT_V1 = "https://scim.eduid.se/schema/nutid/event/v1"


@dataclass
class Api:
    url: str
    verify: bool
    token: str | None = None


def parse_args() -> Args:
    parser = argparse.ArgumentParser(description="SCIM testing utility")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Enable debug operation")
    parser.add_argument(
        "--insecure", "-k", dest="insecure", action="store_true", default=False, help="Do not verify tls cert"
    )
    parser.add_argument("file", metavar="FILE", type=argparse.FileType("r"), help="YAML file with command data in it")

    return cast(Args, parser.parse_args())


def scim_request(
    func: Callable,
    url: str,
    data: dict | None = None,
    headers: dict | None = None,
    token: str | None = None,
    verify: bool = True,
) -> dict[str, Any] | None:
    if not headers:
        headers = {"content-type": "application/scim+json"}
    if token is not None:
        logger.debug(f"Using Authorization {token}")
        headers["Authorization"] = f"Bearer {token}"
    logger.debug(f"API URL: {url}")
    r = _make_request(func, url, data, headers, verify)

    if not r:
        return None

    response = r.json()
    logger.debug(f"Response:\n{pformat(response, width=120)}")
    return response


def _make_request(
    func: Callable,
    url: str,
    data: dict | None = None,
    headers: dict | None = None,
    verify: bool = True,
) -> requests.Response | None:
    r = func(url, json=data, headers=headers, verify=verify)
    logger.debug(f"Response from server: {r}\n{r.text}")

    if r.status_code not in [200, 201, 204]:
        try:
            logger.error(
                f"Failure parsed_response ({r.status_code}) received from server:\n"
                f"{json.dumps(r.json(), sort_keys=True, indent=4)}"
            )
        except Exception:
            logger.error(f"Error {r} received from server: {r.text}")
        return None
    return r


def search_user(api: Api, filter: str) -> dict[str, Any] | None:
    logger.info(f"Searching for user with filter {filter}")
    query = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
        "filter": filter,
        "startIndex": 1,
        "count": 1,
    }

    logger.info(f"Sending user search query:\n{json.dumps(query, sort_keys=True, indent=4)}")
    res = scim_request(requests.post, f"{api.url}/Users/.search", data=query, token=api.token, verify=api.verify)
    logger.info(f"User search result:\n{json.dumps(res, sort_keys=True, indent=4)}\n")
    return res


def search_group(api: Api, filter: str) -> dict[str, Any] | None:
    logger.info(f"Searching for group with filter {filter}")
    query = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
        "filter": filter,
        "startIndex": 1,
        "count": 10,
    }

    logger.info(f"Sending group search query:\n{json.dumps(query, sort_keys=True, indent=4)}")
    res = scim_request(requests.post, f"{api.url}/Groups/.search", data=query, token=api.token, verify=api.verify)
    logger.info(f"Group search result:\n{json.dumps(res, sort_keys=True, indent=4)}\n")
    return res


def create_user(api: Api, external_id: str) -> dict[str, Any] | None:
    logger.info(f"Creating user with externalId {external_id}")
    query = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "externalId": external_id}
    logger.debug(f"Sending user create query:\n{pformat(json.dumps(query, sort_keys=True, indent=4))}")
    res = scim_request(requests.post, f"{api.url}/Users/", data=query, token=api.token, verify=api.verify)
    logger.info(f"User create result:\n{json.dumps(res, sort_keys=True, indent=4)}\n")
    return res


def create_group(api: Api, display_name: str, token: str | None = None) -> dict[str, Any] | None:
    logger.info(f"Creating group with displayName {display_name}")
    query = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": display_name, "members": []}
    logger.debug(f"Sending group create query:\n{pformat(json.dumps(query, sort_keys=True, indent=4))}")
    res = scim_request(requests.post, f"{api.url}/Groups/", data=query, token=api.token, verify=api.verify)
    logger.info(f"Group create result:\n{json.dumps(res, sort_keys=True, indent=4)}\n")
    return res


def get_user_resource(api: Api, scim_id: str) -> dict[str, Any] | None:
    logger.debug(f"Fetching SCIM user resource {scim_id}")

    if "@" in scim_id:
        # lookup a user with this external_id
        res = search_user(api, f'externalId eq "{scim_id}"')
        if not res or res.get("totalResults") != 1:
            logger.error(f"No user found with externalId {scim_id}")
            return None
        scim_id = res["Resources"][0]["id"]

    return scim_request(requests.get, f"{api.url}/Users/{scim_id}", token=api.token, verify=api.verify)


def get_group_resource(api: Api, scim_id: str) -> dict[str, Any] | None:
    logger.debug(f"Fetching SCIM group resource {scim_id}")

    return scim_request(requests.get, f"{api.url}/Groups/{scim_id}", token=api.token, verify=api.verify)


def put_user(api: Api, scim_id: str, nutid_data: Mapping[str, Any]) -> None:
    scim = get_user_resource(api, scim_id)
    if not scim:
        return

    # Update scim_id from the fetched resource, in case it was an externalId
    scim_id = scim["id"]

    meta = scim.pop("meta")

    if NUTID_USER_V1 not in scim["schemas"]:
        scim["schemas"] += [NUTID_USER_V1]
    if NUTID_USER_V1 not in scim:
        scim[NUTID_USER_V1] = {}
    if "profiles" not in scim[NUTID_USER_V1]:
        scim[NUTID_USER_V1]["profiles"] = {}

    for k, v in nutid_data.items():
        scim[NUTID_USER_V1][k] = v

    headers = {"content-type": "application/scim+json", "if-match": meta["version"]}

    logger.info(f"Updating profiles for SCIM user resource {scim_id}:\n{json.dumps(scim, sort_keys=True, indent=4)}\n")
    res = scim_request(
        requests.put, f"{api.url}/Users/{scim_id}", data=scim, headers=headers, token=api.token, verify=api.verify
    )
    logger.info(f"Update result:\n{json.dumps(res, sort_keys=True, indent=4)}")
    return None


def put_group(api: Api, scim_id: str, data: dict[str, Any], token: str | None = None) -> None:
    scim = get_group_resource(api, scim_id)
    if not scim:
        return

    meta = scim.pop("meta")
    display_name = data.get("display_name")
    members = data.get("members")
    if display_name:
        scim["displayName"] = display_name
    if members:
        new_members = [
            {"$ref": f'{api}/Users/{member["id"]}', "value": member["id"], "display": member["display_name"]}
            for member in members
        ]
        scim["members"] = new_members
    if "data" in data:
        if NUTID_GROUP_V1 not in scim["schemas"]:
            scim["schemas"] += [NUTID_GROUP_V1]
        scim[NUTID_GROUP_V1] = {"data": data["data"]}

    headers = {"content-type": "application/scim+json", "if-match": meta["version"]}

    logger.info(f"Updating SCIM group resource {scim_id}:\n{json.dumps(scim, sort_keys=True, indent=4)}\n")
    res = scim_request(
        requests.put, f"{api.url}/Groups/{scim_id}", data=scim, headers=headers, token=api.token, verify=api.verify
    )
    logger.info(f"Update result:\n{json.dumps(res, sort_keys=True, indent=4)}")


def post_event(
    api: Api,
    resource_scim_id: str,
    resource_type: str,
    level: str = "info",
    data: dict[str, Any] | None = None,
) -> None:
    if resource_type == "User":
        resource = get_user_resource(api=api, scim_id=resource_scim_id)
    elif resource_type == "Group":
        resource = get_group_resource(api=api, scim_id=resource_scim_id)
    else:
        logger.warning(f"No event created for resource type {resource_type} - not implemented.")
        return None

    if resource is None:
        logger.error(f"Event resource {resource_type} {resource_scim_id} not found.")
        return None

    event = {
        "resource": {
            "resourceType": resource_type,
            "id": resource_scim_id,
            "lastModified": resource["meta"]["lastModified"],
            "version": resource["meta"]["version"],
        },
        "level": level,
    }

    if data is not None:
        event.update({"data": data})

    headers = {"content-type": "application/scim+json"}
    scim = {"schemas": [EVENT_CORE_V1, NUTID_EVENT_V1], NUTID_EVENT_V1: event}

    logger.info(f"Creating SCIM event:\n{json.dumps(scim, sort_keys=True, indent=4)}\n")
    res = scim_request(
        requests.post, f"{api.url}/Events/", data=scim, headers=headers, token=api.token, verify=api.verify
    )
    logger.info(f"Update result:\n{json.dumps(res, sort_keys=True, indent=4)}")


def process_login(api: Api, params: Mapping[str, Any]) -> str | None:
    url = f"{api.url}/login"
    data_owner = params["data_owner"]
    logger.debug(f"Login URL: {url}")
    data = {"data_owner": data_owner}
    logger.debug(f"Login payload:\n{json.dumps(data)}")
    r = _make_request(requests.post, url, data=data, verify=api.verify)
    if not r:
        return None

    logger.debug(f"Response from server: {r}\n{r.text}")
    return r.headers["Authorization"]


def process_users(api: Api, ops: Mapping[str, Any]) -> None:
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
        if op == "search":
            for what in ops[op]:
                if what == "externalId":
                    for external_id in ops[op][what]:
                        res = search_user(api, f'externalId eq "{external_id}"')
                        if res is not None and res["totalResults"] == 0:
                            logger.info(f"Found no user with externalId: {external_id}. Creating it.")
                            create_user(api, external_id)

                elif what == "lastModified":
                    for _op in ops[op][what]:
                        if _op in ["gt", "ge"]:
                            for _ts in ops[op][what][_op]:
                                search_user(api, f'meta.lastModified {_op} "{_ts}"')
                        else:
                            logger.error(f'Unknown "user" lastModified operation {_op}')
                else:
                    logger.error(f'Unknown "user" search attribute {what}')
        elif op == "put":
            for scim_id in ops[op]:
                put_user(api, scim_id, ops[op][scim_id])
        else:
            logger.error(f'Unknown "user" operation {op}')


def process_groups(api: Api, ops: Mapping[str, Any]) -> None:
    for op in ops.keys():
        if op == "search":
            for what in ops[op]:
                if what == "displayName":
                    for display_name in ops[op][what]:
                        res = search_group(api, f'displayName eq "{display_name}"')
                        if res is not None and res["totalResults"] == 0:
                            logger.info(f"Found no group with displayName: {display_name}. Creating it.")
                            create_group(api, display_name)
                elif what == "lastModified":
                    for _op in ops[op][what]:
                        if _op in ["gt", "ge"]:
                            for _ts in ops[op][what][_op]:
                                search_group(api, f'meta.lastModified {_op} "{_ts}"')
                        else:
                            logger.error(f'Unknown "group" lastModified operation {_op}')
                elif what.startswith("extensions.data"):
                    for value in ops[op][what]:
                        search_group(api, f'{what} eq "{value}"')
                else:
                    logger.error(f'Unknown "group" search attribute {what}')
        elif op == "put":
            for scim_id in ops[op]:
                put_group(api, scim_id, data=ops[op][scim_id])


def process_events(api: Api, ops: Mapping[str, Any]) -> None:
    for op in ops.keys():
        if op == "post":
            for item in ops[op]:
                params = ops[op][item]
                post_event(api, **params)


def main(args: Args) -> bool:
    data = yaml.safe_load(args.file)

    logger.debug(f"Loaded command data: {pformat(data)}")

    for url in data.keys():
        api = Api(url=url, verify=not args.insecure)
        if "login" in data[url]:
            api.token = data[url]["login"]["token"]
            if not api.token:
                logger.error("Login failed")
                return False

        if "users" in data[url]:
            process_users(api, data[url]["users"])
        if "groups" in data[url]:
            process_groups(api, data[url]["groups"])
        if "events" in data[url]:
            process_events(api, data[url]["events"])

    return True


def _config_logger(args: Args, progname: str):
    # This is the root log level
    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr, format="%(asctime)s: %(name)s: %(levelname)s %(message)s")
    logger.name = progname
    # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to WARNING
    if not sys.stderr.isatty() and not args.debug:
        for this_h in logging.getLogger("").handlers:
            this_h.setLevel(logging.WARNING)


if __name__ == "__main__":
    args = parse_args()
    _config_logger(args, "scim-util")
    if main(args):
        sys.exit(0)

    sys.exit(1)
