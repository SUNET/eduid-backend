#!/usr/bin/env python3
#
import os
from pathlib import PurePath
from typing import List

from setuptools import find_packages, setup

here = PurePath(__file__)
README = open(here.with_name('README')).read()

version = '0.0.1'

def load_requirements(path: PurePath) -> List[str]:
    """ Load dependencies from a requirements.txt style file, ignoring comments etc. """
    res = []
    with open(path) as fd:
        for line in fd.readlines():
            while line.endswith('\n'):
                line = line[:-1]
            if not line or line.startswith('-') or line.startswith('#'):
                continue
            res += [line]
    return res

install_requires = load_requirements(here.with_name('requirements.txt'))
testing_extras = load_requirements(here.with_name('test_requirements.txt'))

print(install_requires)
setup(name='vccs_auth',
      version=version,
      description="Very Complicated Credential System - authentication backend",
      long_description=README,
      classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        ],
      keywords='security password hashing bcrypt PBKDF2',
      author='Fredrik Thulin',
      author_email='fredrik@thulin.net',
      license='BSD',
      packages=find_packages('src'),
      package_dir = {'': 'src'},
      zip_safe=False,
      install_requires=install_requires,
      extras_require={
          'testing': testing_extras,
      },
      )
