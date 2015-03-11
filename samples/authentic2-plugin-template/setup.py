#!/usr/bin/python
import subprocess
from setuptools import setup, find_packages
import os

def get_version():
    '''Use the VERSION, if absent generates a version with git describe, if not
       tag exists, take 0.0.0- and add the length of the commit log.
    '''
    if os.path.exists('VERSION'):
        with open('VERSION', 'r') as v:
            return v.read()
    if os.path.exists('.git'):
        p = subprocess.Popen(['git','describe','--dirty','--match=v*'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = p.communicate()[0]
        if p.returncode == 0:
            return result.split()[0][1:].replace('-', '.')
        else:
            return '0.0.0-%s' % len(
                    subprocess.check_output(
                            ['git', 'rev-list', 'HEAD']).splitlines())
    return '0.0.0'

README = file(os.path.join(
    os.path.dirname(__file__),
    'README')).read()

setup(name='authentic2-plugin-template',
        version=get_version(),
        license='AGPLv3',
        description='Authentic2 Plugin Template',
        long_description=README,
        author="Entr'ouvert",
        author_email="info@entrouvert.com",
        packages=find_packages('src'),
        package_dir={
            '': 'src',
        },
        package_data={
            'authentic2_plugin_template': [
                  'templates/authentic2_plugin_template/*.html',
                  'static/authentic2_plugin_template/js/*.js',
                  'static/authentic2_plugin_template/css/*.css',
                  'static/authentic2_plugin_template/img/*.png',
            ],
        },
        install_requires=[
        ],
        entry_points={
            'authentic2.plugin': [
                'authentic2-plugin-template= authentic2_plugin_template:Plugin',
            ],
        },
)
