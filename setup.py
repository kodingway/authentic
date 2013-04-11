#! /usr/bin/env python
#
'''
   Setup script for Authentic 2
'''
import authentic2

from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

setup(name="authentic2",
      version=authentic2.VERSION,
      license="AGPLv3+",
      description="Authentic 2, a versatile identity management server",
      url="http://dev.entrouvert.org/projects/authentic/",
      author="Entr'ouvert",
      author_email="authentic-devel@lists.labs.libre-entreprise.org",
      maintainer="Benjamin Dauvergne",
      maintainer_email="bdauvergne@entrouvert.com",
      packages=find_packages(),
      include_package_data=True,
      install_requires=['django < 1.6',
        'south<0.8.0',
        'requests',
        'django-registration',
        'django-debug-toolbar<1.0.0'],
      zip_safe=False,
      classifiers=[
          "Development Status :: 5 - Production/Stable",
          "Environment :: Web Environment",
          "Framework :: Django",
          'Intended Audience :: End Users/Desktop',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'Intended Audience :: Information Technology',
          'Intended Audience :: Legal Industry',
          'Intended Audience :: Science/Research',
          'Intended Audience :: Telecommunications Industry',
          "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
          "Operating System :: OS Independent",
          "Programming Language :: Python",
          "Topic :: System :: Systems Administration :: Authentication/Directory",
      ],
      dependency_links = [
          'https://bitbucket.org/bdauvergne/django-registration-1.5/get/tip.tar.gz#egg=django-registration-0.8.0',
      ],
)
