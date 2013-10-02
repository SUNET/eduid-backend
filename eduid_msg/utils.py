"""
This module provides utility functions.
"""

import os


def load_template(template_dir, filename, lang):
    """
    This function loads a template file by provided language.
    """
    if not isinstance(template_dir, basestring):
        return False
    if not os.path.isdir(template_dir):
        return False
    try:
        # First try to load template with suffix lang otherwise use
        # fallback template
        _file = os.path.join(template_dir, '.'.join([filename, lang]))
        if not os.path.exists(_file):
            _file = os.path.join(template_dir, filename)
        text = open(_file).read()
        return text
    except OSError:
        return False
