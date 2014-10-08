#! /usr/bin/env python
#
'''
   Setup script for Authentic 2
'''

import glob
import re
import sys
import os

from setuptools import setup, find_packages
from setuptools.command.install_lib import install_lib as _install_lib
from distutils.command.build import build as _build
from distutils.command.sdist import sdist
from distutils.cmd import Command


class compile_translations(Command):
    description = 'compile message catalogs to MO files via django compilemessages'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            from django.core.management.commands.compilemessages import \
                    compile_messages
            for path, dirs, files in os.walk('authentic2'):
                if 'locale' not in dirs:
                    continue
                curdir = os.getcwd()
                os.chdir(os.path.realpath(path))
                compile_messages(sys.stderr)
                os.chdir(curdir)
        except ImportError:
            print
            sys.stderr.write('!!! Please install Django >= 1.4 to build translations')
            print
            print


class build(_build):
    sub_commands = [('compile_translations', None)] + _build.sub_commands

class eo_sdist(sdist):

    def run(self):
        print "creating VERSION file"
        if os.path.exists('VERSION'):
            os.remove('VERSION')
        version = get_version()
        version_file = open('VERSION', 'w')
        version_file.write(version)
        version_file.close()
        sdist.run(self)
        print "removing VERSION file"
        if os.path.exists('VERSION'):
            os.remove('VERSION')

class install_lib(_install_lib):
    def run(self):
        self.run_command('compile_translations')
        _install_lib.run(self)


def get_version():

    version = None
    if os.path.exists('VERSION'):
        version_file = open('VERSION', 'r')
        version = version_file.read()
        version_file.close()
        return version
    for d in glob.glob('*'):
        if not os.path.isdir(d):
            continue
        module_file = os.path.join(d, '__init__.py')
        if not os.path.exists(module_file):
            continue
        for v in re.findall("""__version__ *= *['"](.*)['"]""",
                open(module_file).read()):
            assert version is None
            version = v
        if version:
            break
    assert version is not None
    if os.path.exists('.git'):
        import subprocess
        p = subprocess.Popen(['git','describe','--dirty','--match=v*'],
                stdout=subprocess.PIPE)
        result = p.communicate()[0]
        assert p.returncode == 0, 'git returned non-zero'
        new_version = result.split()[0][1:]
        assert new_version.split('-')[0] == version, '__version__ must match the last git annotated tag'
        version = new_version.replace('-', '.')
    return version


setup(name="authentic2",
      version=get_version(),
      license="AGPLv3+",
      description="Authentic 2, a versatile identity management server",
      url="http://dev.entrouvert.org/projects/authentic/",
      author="Entr'ouvert",
      author_email="authentic@listes.entrouvert.com",
      maintainer="Benjamin Dauvergne",
      maintainer_email="bdauvergne@entrouvert.com",
      scripts = ('authentic2-ctl',),
      packages=find_packages(),
      include_package_data=True,
      install_requires=['django < 1.6',
        'south>=0.8.4,<0.9',
        'requests',
        'django-model-utils',
        'django-registration>=1',
        'django-admin-tools>=0.5.1',
        'dnspython',
        'django-select2',
        'django-tables2',
        'gadjo',
        'XStatic',
        'XStatic_Font_Awesome',
        'XStatic_jQuery',
        'XStatic_jquery_ui',
        'django-import-export',
      ],
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
      cmdclass={'build': build, 'install_lib': install_lib,
          'compile_translations': compile_translations,
          'sdist': eo_sdist},
      entry_points={
          'authentic2.plugin': [
              'authentic2-auth-ssl = authentic2.auth2_auth.auth2_ssl:Plugin',
              'authentic2-idp-saml2 = authentic2.idp.saml:Plugin',
          ],
      },
)
