#!/usr/bin/env python

__author__ = 'leifj'

#!/usr/bin/env python
from distutils.core import setup
from setuptools import find_packages
import sys, os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()

version = '0.1dev'

install_requires = [
    'pymongo',
    'celery',
]


setup(name='eduid-am',
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
      packages=find_packages('src'),
      package_dir={'': 'src'},
      include_package_data=True,
      package_data={
          'eduid.attribute_manager': []
      },
      zip_safe=False,
      install_requires=install_requires)
