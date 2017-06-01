#! /usr/bin/env python
#
'''
   Setup script for Authentic 2
'''

import subprocess
import sys
import os
import glob

from setuptools import setup, find_packages
from setuptools.command.install_lib import install_lib as _install_lib
from setuptools.command.sdist import sdist as _sdist
from distutils.command.build import build as _build
from distutils.cmd import Command


class compile_translations(Command):
    description = 'compile message catalogs to MO files via django compilemessages'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        curdir = os.getcwd()
        try:
            os.environ.pop('DJANGO_SETTINGS_MODULE', None)
            from django.core.management import call_command
            for dir in glob.glob('src/*'):
                for path, dirs, files in os.walk(dir):
                    if 'locale' not in dirs:
                        continue
                    os.chdir(os.path.realpath(path))
                    call_command('compilemessages')
                    os.chdir(curdir)
        except ImportError:
            print
            sys.stderr.write('!!! Please install Django >= 1.4 to build translations')
            print
            print
            os.chdir(curdir)


class build(_build):
    sub_commands = [('compile_translations', None)] + _build.sub_commands


class sdist(_sdist):
    sub_commands = [('compile_translations', None)] + _sdist.sub_commands

    def run(self):
        print "creating VERSION file"
        if os.path.exists('VERSION'):
            os.remove('VERSION')
        version = get_version()
        version_file = open('VERSION', 'w')
        version_file.write(version)
        version_file.close()
        _sdist.run(self)
        print "removing VERSION file"
        if os.path.exists('VERSION'):
            os.remove('VERSION')


class install_lib(_install_lib):
    def run(self):
        self.run_command('compile_translations')
        _install_lib.run(self)


def get_version():
    '''Use the VERSION, if absent generates a version with git describe, if not
       tag exists, take 0.0.0- and add the length of the commit log.
    '''
    if os.path.exists('VERSION'):
        with open('VERSION', 'r') as v:
            return v.read()
    if os.path.exists('.git'):
        p = subprocess.Popen(['git', 'describe', '--dirty', '--match=v*'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        result = p.communicate()[0]
        if p.returncode == 0:
            result = result.split()[0][1:]
        else:
            result = '0.0.0-%s' % len(subprocess.check_output(
                ['git', 'rev-list', 'HEAD']).splitlines())
        return result.replace('-', '.').replace('.g', '+g')
    return '0.0.0'


setup(name="authentic2",
      version=get_version(),
      license="AGPLv3+",
      description="Authentic 2, a versatile identity management server",
      url="http://dev.entrouvert.org/projects/authentic/",
      author="Entr'ouvert",
      author_email="authentic@listes.entrouvert.com",
      maintainer="Benjamin Dauvergne",
      maintainer_email="bdauvergne@entrouvert.com",
      scripts=('authentic2-ctl',),
      packages=find_packages('src'),
      package_dir={
          '': 'src',
      },
      include_package_data=True,
      install_requires=[
          'django>=1.8,<1.9',
          'requests>=2.3',
          'django-model-utils>=2.4',
          'django-admin-tools>=0.6,<0.7',
          'dnspython>=1.10',
          'Django-Select2>5',
          'django-tables2>=1.0,<1.1',
          'gadjo',
          'django-import-export>=0.2.7',
          'djangorestframework>=3.3,<3.4',
          'six>=1',
          'Markdown>=2.1',
          'python-ldap',
          'django-filter>1',
          'pycrypto',
          'django-mellon',
          'ldaptools',
          'django-jsonfield',
          'jwcrypto>=0.3.1,<1',
          'cryptography',
          'XStatic-jQuery',
          'XStatic-jquery-ui<1.12',
          'xstatic-select2',
      ],
      extras_require = {
          'idp-openid': ['python-openid'],
      },
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
      cmdclass={
          'build': build,
          'install_lib': install_lib,
          'compile_translations': compile_translations,
          'sdist': sdist,
      },
      entry_points={
          'authentic2.plugin': [
              'authentic2-auth-ssl = authentic2.auth2_auth.auth2_ssl:Plugin',
              'authentic2-auth-saml = authentic2_auth_saml:Plugin',
              'authentic2-auth-oidc = authentic2_auth_oidc:Plugin',
              'authentic2-idp-saml2 = authentic2.idp.saml:Plugin',
              'authentic2-idp-openid = authentic2_idp_openid:Plugin',
              'authentic2-idp-cas = authentic2_idp_cas:Plugin',
              'authentic2-idp-oidc = authentic2_idp_oidc:Plugin',
              'authentic2-provisionning-ldap = authentic2_provisionning_ldap:Plugin',
          ],
      })
