# -*- encoding: utf-8 -*-
import os

from setuptools import setup, find_packages

__author__ = 'mathiashedstrom'

here = os.path.abspath(os.path.dirname(__file__))
README_fn = os.path.join(here, 'README.rst')
README = 'eduID Lookup Mobile'
if os.path.exists(README_fn):
    README = open(README_fn).read()

version = '0.2.2'

here = os.path.abspath(os.path.dirname(__file__))
install_requires = [x for x in open(os.path.join(here, 'requirements.txt')).read().split('\n') if len(x) > 0]
test_requires = [
    x
    for x in open(os.path.join(here, 'test_requirements.txt')).read().split('\n')
    if len(x) > 0 and not x.startswith('-')
]

setup(
    name='eduid_lookup_mobile',
    version=version,
    description='eduID nin mobile lookup',
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
    package_data={},
    zip_safe=False,
    install_requires=install_requires,
    tests_require=test_requires,
    test_suite='eduid_lookup_mobile',
    extras_require={'testing': test_requires,},
)
