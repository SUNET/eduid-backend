# -*- encoding: utf-8 -*-
"""
This module provides utility functions.
"""

import os


def load_template(template_dir, filename, message_dict, lang):
    """
    This function loads a template file by provided language.
    """
    from jinja2 import Environment, FileSystemLoader

    if not isinstance(template_dir, basestring):
        return False
    if not os.path.isdir(template_dir):
        return False
    try:
        f = '.'.join([filename, lang])
        if os.path.exists(os.path.join(template_dir, f)):
            filename = f
        template = Environment(loader=FileSystemLoader(template_dir)).get_template(filename)
        return template.render(message_dict)
    except OSError:
        return False
