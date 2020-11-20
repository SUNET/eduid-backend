from setuptools import setup, find_packages


version = '0.18.1'


requires = [
    'six >= 1.11.0',
    'setuptools >= 2.2',
    'eduid-userdb >= 0.8.0,==0.8.*',
]

# Flavours
webapp_requires = [
    'Flask>=1.1,<1.2',
    'pysaml2 == 6.*',  # version sync with IdP to avoid pip catastrophes
    'redis >= 2.10.5',
    'pwgen == 0.4',
    'vccs_client >= 0.4.5',
    'PyNaCl >= 1.0.1',
    'python-etcd >= 0.4.5',
    'PyYAML >= 3.11',
    'bleach>=3.1.3',
    'marshmallow>=3.0,==3.*',
    'Flask-Mail == 0.9.1',
    'eduid_msg >= 0.10.9',
    'eduid-am >= 0.7.3',
    'statsd==3.2.1',
    'zxcvbn>=4.4.27,<5.0',
    'python-u2flib-server>=5.0.0',
    'fido2==0.6.0',
    'cookies-samesite-compat==0.0.*',
]
webapp_extras = webapp_requires + []

idp_requires = [
    'pysaml2 >= 4.9.0',
    'redis >= 2.10.5',
    'vccs_client >= 0.4.2',
    'PyNaCl >= 1.0.1',
    'PyYAML >= 3.11',
    'statsd==3.2.1',
    'bleach>=3.1.3',
    'Flask>=0.12.2,==0.12.*',
    'pwgen == 0.4',
    'python-etcd >= 0.4.5',
]
idp_extras = idp_requires + []

worker_requires = [
    'python-etcd >= 0.4.5',
    'PyNaCl >= 1.0.1',
    'PyYAML >= 3.11',
]
worker_extras = worker_requires + []
api_extras = worker_extras

# No dependecies flavor, let the importing application handle dependencies
nodeps_requires = requires

test_requires = [
    'mock == 1.0.1',
]
testing_extras = test_requires + webapp_extras + ['pytest>=5.2.0' 'pytest-cov>=2.7.1']

long_description = open('README.txt').read()

setup(
    name='eduid-common',
    version=version,
    description="Common code for eduID applications",
    long_description=long_description,
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
    install_requires=requires,
    tests_require=test_requires,
    extras_require={
        'testing': testing_extras,
        'webapp': webapp_extras,
        'idp': idp_extras,
        'worker': worker_extras,
        'api': api_extras,
        'nodeps': [],
    },
    entry_points="""
      """,
)
