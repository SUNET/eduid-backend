from pathlib import PurePath
from typing import List

from setuptools import find_packages, setup

version = '0.0.3'


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
    name='eduid-queue',
    version=version,
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/sunet/eduid-queue',
    license='BSD-2-Clause',
    keywords='eduid',
    author='Johan Lundberg',
    author_email='lundberg@sunet.se',
    description='MongoDB based task queue',
    install_requires=install_requires,
    test_requires=test_requires,
    extras_require={'testing': [],
                    'client': load_requirements(here.with_name('client_requirements.txt')),
                    },
    include_package_data=True,
    entry_points={'console_scripts': ['run-mail-worker=eduid_queue.workers.mail:start_worker',],},
)
