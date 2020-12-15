#!/usr/bin/env python
#
import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README')).read()

version = '0.0.1'

install_requires = [
    #'ndnkdf>=0.1',
    'py-bcrypt>=0.3',
    'pymongo>=3.6',
    'fastapi',
    'uvicorn',
    'pyhsm',
    'python-multipart',  # to parse form data
]

testing_extras = [
    'nose==1.2.1',
    'coverage==3.6',
    'py-bcrypt==0.4',
]

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
      package_dir = {'': 'src'},
      zip_safe=False,
      install_requires=install_requires,
      extras_require={
          'testing': testing_extras,
      },
      )
