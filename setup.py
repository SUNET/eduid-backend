#!/usr/bin/env python

from setuptools import setup, find_packages
import sys

version = '0.2.2b1'

# Use requirements files
requires = [
    'eduid-userdb>=0.4.0b12',
    'eduid-common[webapp]>=0.3.5b6',
    'eduid-action>=0.2.1b1',
    'eduid-am>=0.6.3b5',
    'eduid-msg>=0.10.3b7',
    'eduid_lookup_mobile>=0.0.6b3',
    'Flask>=0.12,<0.13',
    'redis>=2.10.5',
    'pynacl>=1.0.1',
    'urllib3>=1.21.1',
    'python-etcd>=0.4.3',
    'Pillow>=3.0.0',
    'marshmallow>=2.10,<2.11',
    'Babel>=2.6.0',
    'flask-babel>=0.11.2',
    'oic>=0.8.3',
    'zxcvbn>=4.4.27,<5.0',
    'pysaml2==4.6.1',
    'xhtml2pdf>=0.2.2',
    'hammock>=0.2.4',
    'qrcode>=5.1',
    'python-jose>=3.0.1',
    'python-u2flib-server>=5.0.0',
    'cryptography>=2.0.3',
    'pyOpenSSL>=17.3.0',
    'proquint==0.2.1',
    'bleach>=2.1.4',
    'html5lib>=1.0.1',
]

test_requires = [
    'WebTest==2.0.30',
    'mock==2.0.0',
]

testing_extras = test_requires + [
    'nose == 1.3.7',
    'nosexcover == 1.0.11',
    'coverage == 4.5.1',
]

setup(
    name='eduid-webapp',
    version=version,
    license='bsd',
    url='https://www.github.com/eduID/',
    author='NORDUnet A/S',
    author_email='',
    description='authentication service for eduID',
    classifiers=[
        'Framework :: Flask',
    ],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    namespace_packages=['eduid_webapp'],
    zip_safe=False,
    include_package_data=True,
    install_requires=requires,
    tests_require=test_requires,
    extras_require={
        'testing': testing_extras,
    },
)
