# -*- encoding: utf-8 -*-
import os

from setuptools import setup, find_packages

__author__ = 'mathiashedstrom'

here = os.path.abspath(os.path.dirname(__file__))
README_fn = os.path.join(here, 'README.rst')
README = 'eduID Lookup Mobile'
if os.path.exists(README_fn):
    README = open(README_fn).read()

version = '0.0.7b1'

install_requires = [
    'eduid-userdb >= 0.4.0b12',
    'eduid_common>=0.3.5b6',
    'celery >= 3.1.17, <3.2',
    'suds-jurko >= 0.6',
    'phonenumbers >= 8.9.3'
]

test_requires = [
    'WebTest==2.0.30',
    'mock==2.0.0',
]

testing_extras = test_requires + [
    'nose == 1.3.7',
    'coverage == 4.5.1',
    'nosexcover == 1.0.11',
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
    license='BSD',
    packages=find_packages(),
    include_package_data=True,
    package_data = {
        },
    zip_safe=False,
    install_requires=install_requires,
    tests_require=test_requires,
    test_suite='eduid_lookup_mobile',
    extras_require={
        'testing': testing_extras,
    },
)
