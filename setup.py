#!/usr/bin/env python
import os
from setuptools import setup, find_packages

version = '0.2.16'

here = os.path.abspath(os.path.dirname(__file__))

install_requires = [x for x in open(os.path.join(here, 'requirements.txt')).read().split('\n') if len(x) > 0]
testing_extras = [x for x in open(os.path.join(here, 'test_requirements.txt')).read().split('\n')
                  if len(x) > 0 and not x.startswith('-')]

setup(
    name='eduid-webapp',
    version=version,
    license='bsd',
    url='https://www.github.com/SUNET/',
    author='SUNET',
    author_email='',
    description='web apps for eduID',
    classifiers=[
        'Framework :: Flask',
    ],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    namespace_packages=['eduid_webapp'],
    zip_safe=False,
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'testing': testing_extras,
    },
)
