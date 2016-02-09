from setuptools import setup, find_packages


version = '0.1.3b4'

requires = [
    'setuptools>=2.2',
    'eduid-userdb>=0.0.5',
]

# Flavours
webapp_requires = [
    'pysaml2 >= 1.2.0beta2',  # version sync with dashboard to avoid pip catastrophies
    'redis >= 2.10.5',
    'pwgen==0.4',
    'vccs_client>=0.4.1',
]
webapp_extras = webapp_requires + []

test_requires = [
    'mock==1.0.1',
]
testing_extras = test_requires + webapp_extras + []

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
      package_dir={'': 'src'},
      namespace_packages=['eduid_common'],
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=test_requires,
      extras_require={
          'testing': testing_extras,
          'webapp': webapp_extras,
      },
      entry_points="""
      """,
      )
