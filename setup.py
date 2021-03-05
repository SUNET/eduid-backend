# -*- encoding: utf-8 -*-
import os
from pathlib import PurePath
from typing import List

from setuptools import setup, find_packages

__author__ = 'mathiashedstrom'


version = '0.2.2'


def load_requirements(path: PurePath) -> List[str]:
    """ Load dependencies from a requirements.txt style file, ignoring comments etc. """
    res = []
    with open(path) as fd:
        for line in fd.readlines():
            while line.endswith('\n') or line.endswith('\\'):
                line = line[:-1]
            line = line.strip()
            if not line or line.startswith('-') or line.startswith('#'):
                continue
            res += [line]
    return res


here = PurePath(__file__)
README = open(here.with_name('README.md')).read()

install_requires = load_requirements(here.with_name('requirements.txt'))
test_requires = load_requirements(here.with_name('test_requirements.txt'))


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
