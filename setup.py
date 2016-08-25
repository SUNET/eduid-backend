# -*- encoding: utf-8 -*-
import os

from setuptools import setup, find_packages

__author__ = 'mathiashedstrom'

here = os.path.abspath(os.path.dirname(__file__))
README_fn = os.path.join(here, 'README.rst')
README = 'eduID Lookup Mobile'
if os.path.exists(README_fn):
    README = open(README_fn).read()

version = '0.0.6b3'

install_requires = [
    'eduid-userdb >= 0.0.2',
    'eduid_common>=0.1.3b5',
    'celery >= 3.1.9, <4',
    'suds-jurko >= 0.6',
    'phonenumbers >= 7.0.2'
]

setup(
    name='eduid_lookup_mobile',
    version=version,
    description="eduID nin mobile lookup",
    long_description=README,
    classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    ],
    keywords='nin mobile lookup',
    author='Mathias Hedström',
    author_email='mathias.hedstrom@umu.se',
    #url='http://blogs.mnt.se',
    license='BSD',
    packages=find_packages(),
    include_package_data=True,
    package_data = {
        },
    zip_safe=False,
    install_requires=install_requires,
    #extras_require={
    #    'testing': testing_extras,
    #},
    #test_suite='eduid_msg',
)
