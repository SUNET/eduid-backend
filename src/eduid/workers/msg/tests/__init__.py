from __future__ import absolute_import

from mock import MagicMock


def mock_get_attribute_manager(celery):
    """
    Mocked get function for an attribute manager we don't need here
    :return: Mocked am
    :rtype: Object
    """
    am = MagicMock()
    return am


# Mocked celery for am that we don't need here
mock_celery = MagicMock()
