#!/usr/bin/env python

from setuptools import setup, find_packages
import sys

version = '0.2.1b11'

# Use requirements files
requires = []

test_requires = [
    'WebTest==2.0.30',
    'mock==2.0.0',
]

testing_extras = test_requires + [
    'nose == 1.3.7',
    'nosexcover == 1.0.11',
    'coverage == 4.5.1',
]

setup(
    name='eduid-webapp',
    version=version,
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
    namespace_packages=['eduid_webapp'],
    zip_safe=False,
    package_data={'': ['templates/*.html']},
    include_package_data=True,
    install_requires=requires,
    tests_require=test_requires,
    extras_require={
        'testing': testing_extras,
    },
)
