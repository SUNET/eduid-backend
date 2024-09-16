"""
A microservice to serve static file(s) - based on a simular microservice in InAcademia
"""

import logging
import mimetypes

from satosa.micro_services.base import RequestMicroService
from satosa.response import Response

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

    def __init__(self, config, *args, **kwargs):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)
        self.locations = config.get("locations", {})

    def register_endpoints(self):
        url_map = []
        for endpoint, path in self.locations.items():
            endpoint = endpoint.strip("/")
            logger.info(f"{self.logprefix} registering {endpoint} - {path}")
            url_map.append([f"^{endpoint}/", self._handle])
        return url_map

    def _handle(self, context):
        path = context._path
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
            response = "File not found"
            mimetype = "text/html"
            status = "404 Not Found"

        logger.info(f"{self.logprefix} _handle: {endpoint} - {target} - {file} - {status}")
        return Response(response, content=mimetype, status=status)
