from setuptools import setup, find_packages


version = '0.3.2b5'

requires = [
    'setuptools >= 2.2',
    'eduid-userdb >= 0.3.0',
]

# Flavours
webapp_requires = [
    'Flask>=0.12,<0.13',
    'pysaml2 >= 4.0.3rc1',  # version sync with dashboard to avoid pip catastrophes
    'redis >= 2.10.5',
    'pwgen == 0.4',
    'vccs_client >= 0.4.1',
    'PyNaCl >= 1.0.1',
    'python-etcd >= 0.4.5',
    'PyYAML >= 3.11',
    'bleach>=2.0.0',
    'marshmallow>=2.10,<2.11',
    'Flask-Mail == 0.9.1',
    'eduid_msg >= 0.10.2',
    'eduid-am >= 0.6.2b2',
    'statsd==3.2.1',
]
webapp_extras = webapp_requires + []

idp_requires = [
    'pysaml2 >= 1.2.0beta2',
    'redis >= 2.10.5',
    'vccs_client >= 0.4.2',
    'PyNaCl >= 1.0.1',
    'statsd==3.2.1',
]
idp_extras = idp_requires + []

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
          'nodeps': []
      },
      entry_points="""
      """,
      )
