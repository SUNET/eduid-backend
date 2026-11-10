from flask import Blueprint

__author__ = "lundberg"

# The routes (authenticate, callback, status, ...) are added in a later step
oidceid_views = Blueprint("oidceid", __name__, url_prefix="")
