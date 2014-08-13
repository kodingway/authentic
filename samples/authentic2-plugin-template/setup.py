#!/usr/bin/python
from setuptools import setup, find_packages
import os

def get_version():
    import glob
    import re
    import os

    version = None
    for d in glob.glob('src/*'):
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
