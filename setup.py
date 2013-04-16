#! /usr/bin/env python
#
'''
   Setup script for Authentic 2
'''
import authentic2

from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages
from setuptools.command.install_lib import install_lib as _install_lib
from distutils.command.build import build as _build
from distutils.command.sdist import sdist  as _sdist
from distutils.cmd import Command

class compile_translations(Command):
    description = 'compile message catalogs to MO files via django compilemessages'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import os
        import sys
        from django.core.management.commands.compilemessages import \
            compile_messages
        curdir = os.getcwd()
        os.chdir(os.path.realpath('authentic2'))
        compile_messages(stderr=sys.stderr)
        os.chdir(curdir)

class build(_build):
    sub_commands = [('compile_translations', None)] + _build.sub_commands

class sdist(_sdist):
    sub_commands = [('compile_translations', None)] + _sdist.sub_commands

class install_lib(_install_lib):
    def run(self):
        self.run_command('compile_translations')
        _install_lib.run(self)

setup(name="authentic2",
      version=authentic2.VERSION,
      license="AGPLv3+",
      description="Authentic 2, a versatile identity management server",
      url="http://dev.entrouvert.org/projects/authentic/",
      author="Entr'ouvert",
      author_email="authentic-devel@lists.labs.libre-entreprise.org",
      maintainer="Benjamin Dauvergne",
      maintainer_email="bdauvergne@entrouvert.com",
      scripts = ('authentic2-ctl',),
      packages=find_packages(),
      include_package_data=True,
      install_requires=['django < 1.6',
        'south<0.8.0',
        'requests',
        'django-registration==0.8.1',
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
          'https://bitbucket.org/bdauvergne/django-registration-1.5/get/tip.tar.gz#egg=django-registration-0.8.1',
      ],
      cmdclass={'build': build, 'install_lib': install_lib,
          'compile_translations': compile_translations,
          'sdist': sdist},
)
