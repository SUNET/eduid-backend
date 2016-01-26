from setuptools import setup, find_packages


version = '0.1.3b1'

requires = [
]

# Flavours
webapp_requires = [
    'pysaml2 >= 1.2.0beta2',  # version sync with dashboard to avoid pip catastrophies
    'redis >= 2.10.5',
]
webapp_extras = webapp_requires + []

test_requires = []
testing_extras = test_requires + []

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
