from setuptools import setup, find_packages


version = '0.4.1b2'

requires = [
    'six >= 1.11.0',
    'setuptools >= 2.2',
    'eduid-userdb >= 0.4.6b0',
]

# Flavours
webapp_requires = [
    'Flask>=0.12.2,<0.13',
    'pysaml2 >= 4.6.1',  # version sync with dashboard to avoid pip catastrophes
    'redis >= 2.10.5',
    'pwgen == 0.4',
    'vccs_client >= 0.4.5',
    'PyNaCl >= 1.0.1',
    'python-etcd >= 0.4.5',
    'PyYAML >= 3.11',
    'bleach>=2.0.0',
    'marshmallow>=2.15.1,==2.*',
    'Flask-Mail == 0.9.1',
    'eduid_msg >= 0.10.3b1',
    'eduid-am >= 0.6.2b2',
    'statsd==3.2.1',
    'zxcvbn>=4.4.27,<5.0',
]
webapp_extras = webapp_requires + []

idp_requires = [
    'pysaml2 >= 4.6.1',
    'redis >= 2.10.5',
    'vccs_client >= 0.4.2',
    'PyNaCl >= 1.0.1',
    'statsd==3.2.1',
    'bleach>=2.0.0',
    'Flask>=0.12.2,==0.12.*',
    'pwgen == 0.4',
]
idp_extras = idp_requires + []

worker_requires = [
    'python-etcd >= 0.4.5',
    'PyNaCl >= 1.0.1',
    ]
worker_extras = worker_requires + []

# No dependecies flavor, let the importing application handle dependencies
nodeps_requires = requires

test_requires = [
    'mock == 1.0.1',
]
testing_extras = test_requires + webapp_extras + [
    'nose',
    'coverage',
    'nosexcover',
]

long_description = open('README.txt').read()

setup(name='eduid-common',
      version=version,
      description="Common code for eduID applications",
      long_description=long_description,
      classifiers=[
          "Programming Language :: Python",
      ],
      keywords='',
      author='SUNET',
      author_email='',
      url='https://github.com/SUNET/',
      license='bsd',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      namespace_packages=['eduid_common'],
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=test_requires,
      extras_require={
          'testing': testing_extras,
          'webapp': webapp_extras,
          'idp': idp_extras,
          'worker': worker_extras,
          'nodeps': []
      },
      entry_points="""
      """,
      )
