# -*- coding: utf-8 -*-

__author__ = "lundberg"


# Copied from https://stackoverflow.com/questions/18967441/add-a-prefix-to-all-flask-routes/36033627#36033627
class PrefixMiddleware(object):
    def __init__(self, app, prefix="", server_name=""):
        self.app = app
        if prefix is None:
            prefix = ""
        if server_name is None:
            server_name = ""
        self.prefix = prefix
        self.server_name = server_name

    def __call__(self, environ, start_response):
        # Handle localhost requests for health checks
        if environ.get("REMOTE_ADDR") == "127.0.0.1":
            environ["HTTP_HOST"] = self.server_name
            environ["SCRIPT_NAME"] = self.prefix
            return self.app(environ, start_response)
        elif environ.get("PATH_INFO", "").startswith(self.prefix):
            environ["PATH_INFO"] = environ["PATH_INFO"][len(self.prefix) :]
            environ["SCRIPT_NAME"] = self.prefix
            return self.app(environ, start_response)
        else:
            start_response("404", [("Content-Type", "text/plain")])
            return ["Not found.".encode()]
