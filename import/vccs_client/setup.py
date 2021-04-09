#!/usr/bin/env python
#
from setuptools import setup, find_packages
import sys, os
#from distutils import versionpredicate

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README')).read()

version = '0.4.5'

install_requires = [
    'py-bcrypt >= 0.4',
    'simplejson >= 3.3.0',
    'pymongo >= 2.8.0, < 3.0',
    'six',
]

testing_extras = [
    'nose==1.2.1',
    'nosexcover==1.0.8',
    'coverage==3.6',
]

setup(name='vccs_client',
      version=version,
      description="Very Complicated Credential System - authentication client",
      long_description=README,
      classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        ],
      keywords='security password hashing bcrypt PBKDF2',
      author='Fredrik Thulin',
      author_email='fredrik@thulin.net',
      license='BSD',
      packages=['vccs_client',],
      package_dir = {'': 'src'},
      #include_package_data=True,
      #package_data = { },
      zip_safe=False,
      install_requires=install_requires,
      extras_require={
        'testing': testing_extras,
        },
      )
