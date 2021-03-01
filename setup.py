from pathlib import PurePath
from typing import List

from setuptools import setup, find_packages


def load_requirements(path: PurePath) -> List[str]:
    """ Load dependencies from a requirements.txt style file, ignoring comments etc. """
    res = []
    with open(path) as fd:
        for line in fd.readlines():
            while line.endswith('\n'):
                line = line[:-1]
            if not line or line.startswith('-') or line.startswith('#'):
                continue
            res += [line]
    return res


version = '0.32.1'


here = PurePath(__file__)
README = open(here.with_name('README')).read()

install_requires = load_requirements(here.with_name('requirements.txt'))
test_requires = load_requirements(here.with_name('test_requirements.txt'))


setup(
    name='eduid-common',
    version=version,
    description="Common code for eduID applications",
    long_description=README,
    classifiers=["Programming Language :: Python",],
    keywords='',
    author='SUNET',
    author_email='',
    url='https://github.com/SUNET/',
    license='bsd',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    tests_require=test_requires,
    extras_require={
        'testing': [],
        'webapp': load_requirements(here.with_name('webapp_requirements.txt')),
        'worker': load_requirements(here.with_name('worker_requirements.txt')),
        'api': load_requirements(here.with_name('api_requirements.txt')),
        'nodeps': [],
    },
    entry_points="""
      """,
)
