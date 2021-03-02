import os
from pathlib import PurePath
from typing import List

from setuptools import setup, find_packages, find_namespace_packages

__author__ = 'ft'



version = '0.5.2'

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
    name='eduid-scimapi',
    version=version,
    description="External SCIM API for eduID",
    classifiers=['Framework :: Falcon',],
    keywords='eduid',
    author='Fredrik Thulin',
    author_email='fredrik@thulin.net',
    url='https://www.eduid.se/',
    license='BSD',
    packages=find_packages('src') + find_namespace_packages(where='src', include='eduid_satosa_plugins.*'),
    package_dir={'': 'src'},
    zip_safe=False,
    install_requires=install_requires,
    test_requires=test_requires,
    extras_require={'testing': []},
)
