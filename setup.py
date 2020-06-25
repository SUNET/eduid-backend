import os

from setuptools import setup, find_packages

version = '0.4.0'

here = os.path.abspath(os.path.dirname(__file__))

install_requires = [x for x in open(os.path.join(here, 'requirements.txt')).read().split('\n') if len(x) > 0]
testing_extras = [x for x in open(os.path.join(here, 'test_requirements.txt')).read().split('\n')
                  if len(x) > 0 and not x.startswith('-')]

# Add bson as a requirement if this package should be installed in an environment without pymongo
bson_requires = ['bson>=0.5.9']

setup(
    name='eduid-graphdb',
    version=version,
    packages=find_packages('src'),
    package_dir={'': 'src'},
    zip_safe=False,
    include_package_data=True,
    install_requires=install_requires,
    tests_require=testing_extras,
    extras_require={
        'bson': bson_requires,
    },
    url='https://github.com/SUNET/eduid-graphdb',
    license='BSD-2-Clause',
    author='Johan Lundberg',
    author_email='lundberg@sunet.se',
    description='Graph operations with Neo4j'
)
