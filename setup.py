import os
from pathlib import PurePath
from typing import List

from setuptools import setup, find_packages

__author__ = 'ft'

version = '0.11.1'


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
README = open(here.with_name('README.rst')).read()

install_requires = load_requirements(here.with_name('requirements.txt'))
test_requires = load_requirements(here.with_name('test_requirements.txt'))


setup(
    name='eduid-userdb',
    version=version,
    description="eduID User Database interface module",
    long_description=README,
    classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    ],
    keywords='eduid',
    author='Fredrik Thulin',
    author_email='fredrik@thulin.net',
    url='https://www.eduid.se/',
    license='BSD',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    zip_safe=False,
    install_requires=install_requires,
    test_requires=test_requires,
    extras_require={'testing': [],},
)
