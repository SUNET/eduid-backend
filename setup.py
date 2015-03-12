import os

from setuptools import setup, find_packages

__author__ = 'ft'

here = os.path.abspath(os.path.dirname(__file__))
README_fn = os.path.join(here, 'README.rst')
README = 'eduID User Database interface module'
if os.path.exists(README_fn):
    README = open(README_fn).read()

version = '0.0.1-dev'

install_requires = [
    'pymongo >= 2.6.3',
]

testing_extras = [
    'nose == 1.2.1',
    'nosexcover == 1.0.8',
    'coverage == 3.6',
]

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
    url='https://www.eduid.se',
    license='BSD',
    packages=find_packages(),
    include_package_data=True,
    package_data = {
        },
    zip_safe=False,
    install_requires=install_requires,
    extras_require={
        'testing': testing_extras,
    },
)
