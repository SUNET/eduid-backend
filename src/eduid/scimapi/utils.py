import base64
import functools
import logging
import time
from collections.abc import Callable
from typing import AnyStr, TypeVar
from uuid import uuid4

from jwcrypto import jwk
from neo4j.exceptions import Neo4jError

from eduid.common.config.exceptions import BadConfiguration
from eduid.graphdb.exceptions import EduIDGroupDBError
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.exceptions import MaxRetriesReached
from eduid.userdb.exceptions import EduIDDBError

logger = logging.getLogger(__name__)


def b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").strip("=")


def b64_decode(data: AnyStr) -> bytes:
    if isinstance(data, str):
        _data = data.encode("utf-8")
    elif isinstance(data, bytes):
        _data = data
    else:
        raise ValueError("b64_decode needs either str or bytes")
    _data += b"=" * (len(_data) % 4)
    return base64.urlsafe_b64decode(_data)


Filtered = TypeVar("Filtered")


def filter_none(x: Filtered) -> Filtered:
    """
    Recursively removes key, value pairs or items that is None.
    """
    if isinstance(x, dict):
        return {k: filter_none(v) for k, v in x.items() if v is not None}  # type: ignore[return-value]
    elif isinstance(x, list):
        return [filter_none(i) for i in x if x is not None]  # type: ignore[return-value]

    return x


def get_unique_hash():
    return str(uuid4())


def load_jwks(config: ScimApiConfig) -> jwk.JWKSet:
    if not config.keystore_path.exists():
        raise BadConfiguration(f"JWKS path {config.keystore_path} does not exist.")
    with config.keystore_path.open("r") as f:
        jwks = jwk.JWKSet.from_json(f.read())
        logger.info(f"jwks loaded from {config.keystore_path}")
    return jwks


def retryable_db_write(func: Callable):
    @functools.wraps(func)
    def wrapper_run_func(*args, **kwargs):
        max_retries = 10
        retry = 0
        while True:
            try:
                return func(*args, **kwargs)
            except (EduIDDBError, EduIDGroupDBError, Neo4jError) as e:
                retry += 1
                if retry >= max_retries:
                    raise MaxRetriesReached(f"Max retries reached for {func.__name__}")
                time.sleep(0.1)
                logger.warning(f"Retrying {func.__name__}, retry {retry} of {max_retries}: {e}")

    return wrapper_run_func
