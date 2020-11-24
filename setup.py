import os

from setuptools import setup, find_packages

__author__ = 'ft'

here = os.path.abspath(os.path.dirname(__file__))
README_fn = os.path.join(here, 'README.rst')
README = 'eduID User Database interface module'
if os.path.exists(README_fn):
    README = open(README_fn).read()

version = '0.8.5'

install_requires = [
    'pymongo >= 3.6',
    'six',
]

testing_extras = ['pytest>=5.2.0' 'pytest-cov>=2.7.1']

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
    #   packages=['eduid_userdb',
    #             'eduid_userdb.signup',
    #             'eduid_userdb.dashboard',
    #             'eduid_userdb.actions',
    #             'eduid_userdb.actions.tou',
    #             'eduid_userdb.actions.chpass',
    #             'eduid_userdb.proofing',
    #             ],
    # include_package_data=True,
    # package_data = { },
    zip_safe=False,
    install_requires=install_requires,
    extras_require={'testing': testing_extras,},
)
