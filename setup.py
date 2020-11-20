import os

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))
install_requires = [x for x in open(os.path.join(here, 'requirements.txt')).read().split('\n') if len(x) > 0]
testing_extras = [
    x
    for x in open(os.path.join(here, 'test_requirements.txt')).read().split('\n')
    if len(x) > 0 and not x.startswith('-')
]
client_extras = [x for x in open(os.path.join(here, 'requirements.txt')).read().split('\n') if len(x) > 0]

version = '0.0.2'

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
    extras_require={'testing': testing_extras, 'client': client_extras},
    include_package_data=True,
    entry_points={'console_scripts': ['run-mail-worker=eduid_queue.workers.mail:start_worker',],},
)
