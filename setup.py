import os
from pathlib import PurePath
from typing import List

from setuptools import setup, find_packages

__author__ = 'leifj'

version = '0.7.9'


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
    name='eduid_am',
    version=version,
    description="eduID Attribute Manager",
    long_description=README,
    classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    ],
    keywords='identity federation saml',
    author='Leif Johansson',
    author_email='leifj@sunet.se',
    url='http://eduid.se/',
    license='BSD',
    packages=find_packages(),
    include_package_data=True,
    package_data={},
    zip_safe=False,
    install_requires=install_requires,
    test_requires=test_requires,
    extras_require={'testing': [],},
    test_suite='eduid_am',
    python_requires='>=3.7',
)
