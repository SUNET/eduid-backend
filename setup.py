from setuptools import setup, find_packages
import os


version = '0.1.0'

requires = [
    'setuptools==18.5',
    'pwgen==0.4',
    'eduid-userdb>=0.0.4b6',
    'vccs_client>=0.4.1',
]

test_requires = [
    'WebTest==2.0.18',
    'mock==1.0.1',
]

testing_extras = test_requires + [
    'nose==1.2.1',
    'coverage==3.6',
    'nosexcover==1.0.8',
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
      author='NORDUnet A/S',
      author_email='',
      url='https://github.com/SUNET/',
      license='gpl',
      packages=find_packages('src'),
      package_dir = {'': 'src'},
      namespace_packages=['eduid_common'],
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=test_requires,
      extras_require={
          'testing': testing_extras,
      },
      entry_points="""
      """,
      )
