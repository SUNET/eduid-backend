#!/usr/bin/env python

from setuptools import setup, find_packages
import sys

version = '0.1.0'

requires = [
    'eduid-common==0.2.0b0',
    'Flask==0.10.1',
#    'Flask-RESTful==0.3.5',
]


test_requires = [
    'WebTest==2.0.18',
    'mock==1.0.1',
]

testing_extras = test_requires + [
    'nose==1.2.1',
    'coverage==3.6',
    'nosexcover==1.0.8',
]

setup(
    name='eduid_api.authn',
    version='0.1.0',
    license='bsd',
    url='https://www.github.com/eduID/',
    author='NORDUnet A/S',
    author_email='',
    description='authentication service for eduID',
    classifiers=[
        'Framework :: Flask',
    ],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    namespace_packages=['eduid_api'],
    zip_safe=False,
    include_package_data=True,
    install_requires=requires,
    tests_require=test_requires,
    extras_require={
        'testing': testing_extras,
    },
)
