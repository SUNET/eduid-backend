import os

from setuptools import setup, find_packages

__author__ = 'leifj'

here = os.path.abspath(os.path.dirname(__file__))
README_fn = os.path.join(here, 'README.rst')
README = 'eduID Attribute Manager'
if os.path.exists(README_fn):
    README = open(README_fn).read()

version = '0.5.2-dev'

install_requires = [
    'python-dateutil>=2.1',
    'pymongo>=2.6.3',   # XXX remove after eduid_userdb transition
    'celery>=3.1.9',
    'simplejson>=3.6.5',
    'eduid_userdb',
]

testing_extras = [
    'nose==1.2.1',
    'nosexcover==1.0.8',
    'coverage==3.6',
]

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
    url='http://blogs.mnt.se',
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
    test_suite='eduid_am',
)
