import codecs
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, 'README.rst'), encoding='utf-8') as f:
    README = f.read()

with codecs.open(os.path.join(here, 'CHANGES.txt'), encoding='utf-8') as f:
    CHANGES = f.read()

requires = ['requests!=2.8.0', 'mohawk']

setup(name='requests-hawk',
      version='1.0.0',
      description='requests-hawk',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
          "Intended Audience :: Developers",
          "Programming Language :: Python",
          "License :: OSI Approved :: Apache Software License",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.4"
      ],
      entry_points={
          'httpie.plugins.auth.v1': [
              'httpie_hawk = requests_hawk:HawkPlugin'
          ]
      },
      license='Apache License (2.0)',
      author='Mozilla Services',
      author_email='services-dev@mozilla.org',
      url='https://github.com/mozilla-services/requests-hawk',
      keywords='authentication token hawk requests',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="requests_hawk")
