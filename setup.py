import os

from setuptools import setup, find_packages

__author__ = 'ft'

here = os.path.abspath(os.path.dirname(__file__))

install_requires = [x for x in open(os.path.join(here, 'requirements.txt')).read().split('\n') if len(x) > 0]
testing_extras = [x for x in open(os.path.join(here, 'test_requirements.txt')).read().split('\n')
                  if len(x) > 0 and not x.startswith('-')]

version = '0.2.3'

setup(
    name='eduid-scimapi',
    version=version,
    description="External SCIM API for eduID",
    classifiers=[
        'Framework :: Falcon',
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
    extras_require={
        'testing': testing_extras,
    },
)
