"""
A microservice to serve static file(s) - based on a simular microservice in InAcademia
"""

import logging
import mimetypes
from typing import Any

from satosa.context import Context
from satosa.micro_services.base import RequestMicroService
from satosa.response import Response
from satosa.satosa_config import SATOSAConfig

logger = logging.getLogger("satosa")


class ServeStatic(RequestMicroService):
    """
    A class to serve static files from a given directory

    Example configuration:
    ```yaml
    module: eduid.satosa.scimapi.serve_static.ServeStatic
    name: ServeStatic
    config:
        locations:
            static: /path/on/disk/to/static
    ```
    """

    logprefix = "SERVE_STATIC_SERVICE:"

    def __init__(self, config: SATOSAConfig, *args: Any, **kwargs: Any) -> None:
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)
        self.locations = config.get("locations", {})

    def register_endpoints(self) -> list:
        url_map = []
        for endpoint_raw, path in self.locations.items():
            endpoint = endpoint_raw.strip("/")
            logger.info(f"{self.logprefix} registering {endpoint} - {path}")
            url_map.append([f"^{endpoint}/", self._handle])
        return url_map

    def _handle(self, context: Context) -> Response:
        path = context._path
        if path is None:  # satisfy ty
            return Response(b"Not found", content="text/html", status="404 Not Found")
        endpoint = path.split("/")[0]
        target = path[len(endpoint) + 1 :]
        status = "200 OK"

        file = f"{self.locations[endpoint]}/{target}"
        try:
            with open(file, "rb") as f:
                response = f.read()
                mimetype = mimetypes.guess_type(file)[0]
                logger.debug(f"mimetype {mimetype}")
        except OSError:
            response = b"File not found"
            mimetype = "text/html"
            status = "404 Not Found"

        logger.info(f"{self.logprefix} _handle: {endpoint} - {target} - {file} - {status}")
        return Response(response, content=mimetype, status=status)
