from eduid_scimapi.context import Context
from eduid_scimapi.utils import urlappend


class BaseResource(object):

    def __init__(self, context: Context):
        self.context = context

    def url_for(self, *args) -> str:
        url = self.context.base_url
        for arg in args:
            url = urlappend(url, f'{arg}')
        return url
